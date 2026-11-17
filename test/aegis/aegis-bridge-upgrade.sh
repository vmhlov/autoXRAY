#!/bin/bash
# ============================================================================
# aegis-bridge-upgrade.sh — апгрейд установленного bridgeTLSxhttp.sh (RU-мост)
# Запускать НА RU-СЕРВЕРЕ, где уже стоит мост. Ничего не перегенерирует.
#
# Исправления по методичке от 07.11.2026 и документации Xray:
#   1. routing.domainStrategy IPIfNonMatch -> IPOnDemand.
#   2. IP-чекеры (ifconfig.me/ipify/2ip/testipv6.net и пр.) убраны из direct.
#   3. fallbackTag балансировщика direct -> block (fail-closed, вход не светится).
#   4. burstObservatory: sampling 1->3, interval 40s->30s, timeout 3s->5s.
#   5. DNS: "localhost" вторым сервером (DoH из РФ периодически не проходит).
#   6. Подписка: fingerprint -> chrome, bittorrent direct -> block,
#      IP-чекеры убраны из direct-правил клиента.
#   7. Новый профиль "AEGIS BRIDGE AUTO": leastPing по входам моста (не более 3,
#      чтобы не плодить TLS-рукопожатия к одному SNI), fallback -> прямой EU,
#      полный туннель (RU-сплит делает сам мост), пароль на локальных прокси.
#
# Использование: bash aegis-bridge-upgrade.sh
# Откат: cp config.json.bak-aegis config.json; cp <подписка>.json.bak-aegis <подписка>.json; systemctl restart xray
# ============================================================================
set -u
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GRN}$*${NC}"; }; warn(){ echo -e "${YEL}$*${NC}"; }; die(){ echo -e "${RED}$*${NC}"; exit 1; }
[[ $EUID -eq 0 ]] || die "❌ Нужны root права"
for b in jq curl openssl xray systemctl; do command -v "$b" >/dev/null 2>&1 || die "❌ Нет команды: $b"; done
jq -n '{} | walk(.)' >/dev/null 2>&1 || die "❌ Нужен jq >= 1.6"
CFG=/usr/local/etc/xray/config.json
[ -s "$CFG" ] || die "❌ Не найден $CFG — сначала установите bridgeTLSxhttp.sh"
SUB=""
for f in /var/www/*/*.json; do
    [ -s "$f" ] || continue
    if jq -e 'type=="array" and length>0 and (.[0].outbounds|type=="array")' "$f" >/dev/null 2>&1; then SUB="$f"; break; fi
done
[ -n "$SUB" ] || die "❌ Подписка моста не найдена в /var/www/*/*.json"
DOMAIN=$(basename "$(dirname "$SUB")"); HTML="${SUB%.json}.html"
cp "$CFG" "$CFG.bak-aegis" || die "❌ бэкап конфига"
cp "$SUB" "$SUB.bak-aegis" || die "❌ бэкап подписки"
[ -s "$HTML" ] && cp "$HTML" "$HTML.bak-aegis"
XG=$(id -gn xray 2>/dev/null || echo root)
apply_cfg(){ jq empty "$1" >/dev/null 2>&1 || return 1; xray run -test -config "$1" >/dev/null 2>&1 || return 1; chown root:"$XG" "$1" 2>/dev/null; chmod 640 "$1"; mv "$1" "$CFG"; }

warn "[1/4] Правка серверного конфига моста..."
jq '
  .routing.domainStrategy = "IPOnDemand"
  | .routing.balancers |= map(.fallbackTag = "block")
  | .routing.rules |= map(
      if (.outboundTag == "direct") and (((.domain // []) | length) > 0) then
        .domain |= map(select(. as $d |
          (["domain:ifconfig.me","domain:checkip.amazonaws.com","domain:ipify.org","domain:2ip.io","geosite:category-ip-geo-detect","domain:testipv6.net"]
           | index($d)) == null))
      else . end)
  | if .burstObservatory then
      .burstObservatory.pingConfig.sampling = 3
      | .burstObservatory.pingConfig.interval = "30s"
      | .burstObservatory.pingConfig.timeout = "5s"
    else . end
  | .dns.servers |= (if (map(type == "string" and . == "localhost") | any) then . else (.[0:1] + ["localhost"] + .[1:]) end)
' "$CFG" > "$CFG.aegis" || die "❌ jq не разобрал $CFG"
if apply_cfg "$CFG.aegis"; then systemctl restart xray; info "✅ серверный конфиг обновлён"; else rm -f "$CFG.aegis"; die "❌ xray -test не прошёл, конфиг не изменён"; fi

warn "[2/4] Подписка: чистка, chrome, hardening..."
OLDFP=$(jq -r '.[0].outbounds[0].streamSettings.tlsSettings.fingerprint // "firefox"' "$SUB")
jq 'map(select(((.remarks // "") | startswith("🛡️ AEGIS BRIDGE AUTO")) | not))' "$SUB" > "$SUB.aegis" || die "❌ jq: чистка"
jq 'walk(if type == "object" and has("fingerprint") then .fingerprint = "chrome" else . end)' "$SUB.aegis" > "$SUB.a2" && mv "$SUB.a2" "$SUB.aegis" || die "❌ jq: fp"
jq '
  map(
    .routing.rules |= map(
      if (.outboundTag == "direct") and (((.domain // []) | length) > 0) then
        .domain |= map(select(. as $d |
          (["domain:ifconfig.me","domain:checkip.amazonaws.com","domain:ipify.org","domain:2ip.io","geosite:category-ip-geo-detect","domain:testipv6.net"]
           | index($d)) == null))
      else . end)
    | .routing.rules |= map(if ((.protocol // []) | index("bittorrent")) != null then .outboundTag = "block" else . end)
  )
' "$SUB.aegis" > "$SUB.a2" && mv "$SUB.a2" "$SUB.aegis" || die "❌ jq: hardening"

warn "[3/4] Сборка AEGIS BRIDGE AUTO..."
BASE=$(jq '.[0]' "$SUB.aegis")
AU=$(openssl rand -hex 4); AP=$(openssl rand -hex 12)
PAIRS=$(jq -c '[.[] | {r:(.remarks // ""), o:.outbounds[0]}]' "$SUB.aegis")
BR=$(printf '%s' "$PAIRS" | jq '[.[] | select(.r | startswith("🇷🇺")) | .o][0:3] | to_entries | map(.value + {tag:("proxy-bridge-" + (.key|tostring))})')
EU=$(printf '%s' "$PAIRS" | jq '[.[] | select(.r | startswith("🇪🇺")) | .o][0:2] | to_entries | map(.value + {tag:("proxy-eu-" + (.key|tostring))})')
[ "$(printf '%s' "$BR" | jq 'length')" -ge 1 ] || die "❌ В подписке нет профилей моста (🇷🇺)"
FB=$(printf '%s' "$EU" | jq -r '.[0].tag // "block"')
AUTO=$(jq -n --argjson base "$BASE" --argjson br "$BR" --argjson eu "$EU" --arg fb "$FB" --arg au "$AU" --arg ap "$AP" '
  $base
  | .remarks = "🛡️ AEGIS BRIDGE AUTO (RU>EU, fallback EU dir)"
  | .outbounds = ($br + $eu + [{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}])
  | .inbounds |= map(
      if .protocol == "http" then .settings = ((.settings // {}) + {accounts:[{user:$au,pass:$ap}]})
      else .settings = ((.settings // {}) + {auth:"password",accounts:[{user:$au,pass:$ap}]}) end)
  | .routing = {
      domainMatcher:"hybrid", domainStrategy:"AsIs",
      rules:[
        {domain:["geosite:category-ads"],outboundTag:"block"},
        {protocol:["bittorrent"],outboundTag:"block"},
        {ip:["geoip:private"],outboundTag:"direct"},
        {network:"tcp,udp",balancerTag:"auto"}
      ],
      balancers:[{tag:"auto",selector:["proxy-bridge-"],strategy:{type:"leastPing"},fallbackTag:$fb}]
    }
  | .burstObservatory = {subjectSelector:["proxy-bridge-"],
      pingConfig:{destination:"https://www.google.com/generate_204",interval:"30s",sampling:3,timeout:"5s",httpMethod:"HEAD"}}
')
jq --argjson a "$AUTO" '. + [$a]' "$SUB.aegis" > "$SUB.a2" || die "❌ jq: AUTO"
jq empty "$SUB.a2" || die "❌ подписка невалидна, откат: cp $SUB.bak-aegis $SUB"
mv "$SUB.a2" "$SUB"; rm -f "$SUB.aegis"; chmod 644 "$SUB"
[ -s "$HTML" ] && [ "$OLDFP" != "chrome" ] && sed -i "s/fp=$OLDFP/fp=chrome/g" "$HTML"
info "✅ Подписка обновлена. Пароль локальных прокси AUTO: $AU / $AP"

warn "[4/4] Финальная проверка..."
systemctl is-active --quiet xray && info "Xray: RUNNING" || warn "Xray: STOPPED — journalctl -u xray -n 50"
systemctl is-active --quiet nginx && info "Nginx: RUNNING" || warn "Nginx: STOPPED"
SU=$(jq -r '.inbounds[] | select(.tag=="RUsocks5") | .settings.accounts[0].user // empty' "$CFG")
SP=$(jq -r '.inbounds[] | select(.tag=="RUsocks5") | .settings.accounts[0].pass // empty' "$CFG")
if [ -n "$SU" ] && [ -n "$SP" ]; then
    TRACE=$(curl -s --max-time 20 -x "socks5h://${SU}:${SP}@127.0.0.1:10443" https://www.cloudflare.com/cdn-cgi/trace)
    printf '%s' "$TRACE" | grep -q '^warp=on' && info "Каскад: зарубежный трафик выходит через WARP (IP EU-входа скрыт)" || warn "Каскад: WARP не виден на выходе (проверьте EU-сервер)"
    RC=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -x "socks5h://${SU}:${SP}@127.0.0.1:10443" https://ya.ru)
    case "$RC" in 200|301|302) info "RU-трафик идёт напрямую с моста (ya.ru: $RC)";; *) warn "RU-трафик: ya.ru ответил $RC";; esac
fi
echo
info "Готово. Подписка: https://$DOMAIN/$(basename "$SUB")"
info "В клиенте выберите «🛡️ AEGIS BRIDGE AUTO». Весь трафик идёт в мост, RU-сплит делает сервер."
warn "Откат: cp $CFG.bak-aegis $CFG && cp $SUB.bak-aegis $SUB && systemctl restart xray"
