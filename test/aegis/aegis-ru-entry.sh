#!/bin/bash
# ============================================================================
# aegis-ru-entry.sh — добавляет RU-мост как вход в AEGIS AUTO на EU-сервере
# Запускать НА EU-СЕРВЕРЕ, где уже выполнен aegis-upgrade.sh (есть AEGIS AUTO).
#
# Что делает:
#   1. Разбирает vless:// ссылку моста (XHTTP или RAW Vision из вывода
#      bridgeTLSxhttp.sh / caddyBridge.sh), fingerprint принудительно chrome.
#   2. Живая самопроверка: временный клиент на этом сервере ходит через мост
#      (EU -> RU -> EU -> WARP) и открывает generate_204. Не прошло — ничего
#      не меняется.
#   3. В профиль AEGIS AUTO добавляет outbound proxy-fast-ruN (покрывается
#      существующим балансировщиком и burstObservatory) и правила:
#      RU-домены и geoip:ru -> балансировщик ru-route (leastPing по мостам,
#      fallback -> быстрый EU-канал). domainStrategy -> IPOnDemand.
#   4. Добавляет отдельный профиль "🇷🇺 AEGIS RU ENTRY" (полный туннель через
#      мост, пароль на локальных прокси).
#
# Использование:
#   bash aegis-ru-entry.sh "vless://...ссылка_моста_xhttp..." ["vless://...ещё..."]
# Откат: cp <подписка>.json.bak-ruentry <подписка>.json
# ============================================================================
set -u
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GRN}$*${NC}"; }; warn(){ echo -e "${YEL}$*${NC}"; }; die(){ echo -e "${RED}$*${NC}"; exit 1; }
[[ $EUID -eq 0 ]] || die "❌ Нужны root права"
for b in jq curl openssl xray; do command -v "$b" >/dev/null 2>&1 || die "❌ Нет команды: $b"; done
[ $# -ge 1 ] || die "❌ Передайте хотя бы одну vless:// ссылку моста"
CFG=/usr/local/etc/xray/config.json
[ -s "$CFG" ] || die "❌ Не найден $CFG"
SUB=""
for f in /var/www/*/*.json; do
    [ -s "$f" ] || continue
    if jq -e 'type=="array" and length>0 and (.[0].outbounds|type=="array")' "$f" >/dev/null 2>&1; then SUB="$f"; break; fi
done
[ -n "$SUB" ] || die "❌ Подписка не найдена"
jq -e 'map(select((.remarks // "") | startswith("🛡️ AEGIS AUTO"))) | length > 0' "$SUB" >/dev/null 2>&1 || die "❌ Профиль AEGIS AUTO не найден — сначала выполните aegis-upgrade.sh"
DOMAIN=$(basename "$(dirname "$SUB")")
cp "$SUB" "$SUB.bak-ruentry" || die "❌ бэкап подписки"

urldecode(){ local s="${1//+/ }"; printf '%b' "${s//%/\\x}"; }

RU_OBJS="[]"
n=0
for url in "$@"; do
    n=$((n+1))
    [[ "$url" == vless://* ]] || { warn "⚠️ #$n не vless:// — пропуск"; continue; }
    body="${url#vless://}"; body="${body%%#*}"
    UUID="${body%@*}"
    hp="${body#*@}"; ADDR="${hp%%:*}"; rest="${hp#*:}"; PORT="${rest%%\?*}"; QS="${rest#*\?}"
    TYPE="xhttp"; PATHV="/"; MODE="stream-up"; EXTRA=""; SNI="$ADDR"; FLOW=""; ALPN="h2"; SEC="tls"
    IFS='&' read -ra pairs <<< "$QS"
    for p in "${pairs[@]}"; do
        k="${p%%=*}"; v="$(urldecode "${p#*=}")"
        case "$k" in
            type) TYPE="$v";; path) PATHV="$v";; mode) MODE="$v";; extra) EXTRA="$v";;
            sni) SNI="$v";; flow) FLOW="$v";; alpn) ALPN="$v";; security) SEC="$v";;
        esac
    done
    [ "$SEC" = "tls" ] || { warn "⚠️ #$n security=$SEC (ожидается tls) — пропуск"; continue; }
    [ -n "$UUID" ] && [ -n "$ADDR" ] && [ -n "$PORT" ] || { warn "⚠️ #$n неполная ссылка — пропуск"; continue; }
    if [ "$TYPE" = "tcp" ] || [ "$TYPE" = "raw" ]; then NET="raw"; else NET="xhttp"; fi
    OB=$(jq -n --arg t "proxy-fast-ru$n" --arg u "$UUID" --arg a "$ADDR" --argjson p "$PORT" \
        --arg net "$NET" --arg mode "$MODE" --arg path "$PATHV" --arg sni "$SNI" --arg flow "$FLOW" \
        --arg alpn "$ALPN" --arg extra "$EXTRA" '
        {tag:$t, protocol:"vless", mux:{enabled:false, concurrency:-1},
         settings:{vnext:[{address:$a, port:$p,
           users:[({id:$u, encryption:"none"} + (if $flow != "" then {flow:$flow} else {} end))]}]},
         streamSettings:({network:$net, security:"tls",
           tlsSettings:({serverName:$sni, fingerprint:"chrome"} + (if $net == "xhttp" then {alpn:($alpn|split(","))} else {} end))}
           + (if $net == "xhttp" then
                {xhttpSettings:({mode:$mode, path:$path} + (if $extra != "" then {extra:($extra|fromjson)} else {} end))}
              else {} end))}
    ') || { warn "⚠️ #$n не удалось собрать outbound (проверьте extra) — пропуск"; continue; }
    printf '%s' "$OB" | jq empty >/dev/null 2>&1 || { warn "⚠️ #$n невалидный JSON — пропуск"; continue; }
    AU=$(openssl rand -hex 4); AP=$(openssl rand -hex 12); SP=$((18830+n))
    TCLI=$(jq -n --argjson o "$OB" --arg au "$AU" --arg ap "$AP" --argjson sp "$SP" '
        {log:{loglevel:"warning"},
         dns:{servers:["https://8.8.4.4/dns-query","https://1.1.1.1/dns-query"],queryStrategy:"UseIPv4"},
         routing:{domainStrategy:"AsIs",rules:[{ip:["geoip:private"],outboundTag:"direct"}]},
         inbounds:[{tag:"s",protocol:"socks",listen:"127.0.0.1",port:$sp,
           settings:{udp:true,auth:"password",accounts:[{user:$au,pass:$ap}]}}],
         outbounds:[($o + {tag:"proxy"}),{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}]}
    ')
    TD=$(mktemp -d); printf '%s' "$TCLI" > "$TD/c.json"
    if ! xray run -test -config "$TD/c.json" >/dev/null 2>&1; then rm -rf "$TD"; warn "⚠️ #$n xray -test не прошёл — пропуск"; continue; fi
    xray run -config "$TD/c.json" > "$TD/c.log" 2>&1 & CPID=$!
    sleep 2
    RES=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 60 -x "socks5h://${AU}:${AP}@127.0.0.1:${SP}" https://www.google.com/generate_204)
    kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; rm -rf "$TD"
    if [ "${RES%% *}" = "204" ]; then
        RU_OBJS=$(printf '%s' "$RU_OBJS" | jq --argjson o "$OB" '. + [$o]')
        info "✅ Мост #$n ($ADDR) проверен сквозь каскад: ${RES#* } с"
    else
        warn "❌ Мост #$n не прошёл самопроверку (ответ: ${RES:-нет}) — пропуск"
    fi
done
[ "$(printf '%s' "$RU_OBJS" | jq 'length')" -ge 1 ] || die "❌ Ни один мост не прошёл проверку, подписка не изменена"

warn "Патч подписки: AEGIS AUTO + RU ENTRY..."
jq --argjson ru "$RU_OBJS" '
  map(
    if ((.remarks // "") | startswith("🛡️ AEGIS AUTO")) then
      .outbounds = ((.outbounds | map(select((.tag // "") | startswith("proxy-fast-ru") | not)))[0:-2] + $ru + (.outbounds | map(select((.tag // "") | startswith("proxy-fast-ru") | not)))[-2:])
      | .routing.domainStrategy = "IPOnDemand"
      | .routing.rules |= (map(select((.balancerTag // "") != "ru-route"))
          | .[0:-1] + [
              {domain:["geosite:category-ru","geosite:yandex","geosite:vk","domain:ru","domain:su","domain:xn--p1ai"],balancerTag:"ru-route"},
              {ip:["geoip:ru"],balancerTag:"ru-route"}
            ] + .[-1:])
      | .routing.balancers = ((.routing.balancers // []) | map(select(.tag != "ru-route")))
          + [{tag:"ru-route",selector:["proxy-fast-ru"],strategy:{type:"leastPing"},
              fallbackTag:(([.outbounds[].tag | select(startswith("proxy-fast-") and (startswith("proxy-fast-ru") | not))][0]) // "block")}]
    else . end)
  | map(select(((.remarks // "") | startswith("🇷🇺 AEGIS RU ENTRY")) | not))
' "$SUB" > "$SUB.re" || die "❌ jq: патч AUTO"
BASE=$(jq '.[0]' "$SUB.re")
AU=$(openssl rand -hex 4); AP=$(openssl rand -hex 12)
FIRST=$(printf '%s' "$RU_OBJS" | jq '.[0] + {tag:"proxy"}')
ENTRY=$(jq -n --argjson base "$BASE" --argjson o "$FIRST" --arg au "$AU" --arg ap "$AP" '
  $base
  | .remarks = "🇷🇺 AEGIS RU ENTRY (каскад через мост)"
  | .outbounds = [$o,{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}]
  | .inbounds |= map(
      if .protocol == "http" then .settings = ((.settings // {}) + {accounts:[{user:$au,pass:$ap}]})
      else .settings = ((.settings // {}) + {auth:"password",accounts:[{user:$au,pass:$ap}]}) end)
  | .routing = {domainMatcher:"hybrid",domainStrategy:"AsIs",rules:[
      {domain:["geosite:category-ads"],outboundTag:"block"},
      {protocol:["bittorrent"],outboundTag:"block"},
      {ip:["geoip:private"],outboundTag:"direct"}]}
  | del(.burstObservatory, .observatory)
')
jq --argjson e "$ENTRY" '. + [$e]' "$SUB.re" > "$SUB.re2" || die "❌ jq: RU ENTRY"
jq empty "$SUB.re2" || die "❌ подписка невалидна, откат: cp $SUB.bak-ruentry $SUB"
mv "$SUB.re2" "$SUB"; rm -f "$SUB.re"; chmod 644 "$SUB"
echo
info "Готово. Подписка: https://$DOMAIN/$(basename "$SUB")"
info "AEGIS AUTO: RU-трафик теперь всегда идёт через мост (RU-выход), зарубежный — через быстрые каналы/WARP."
info "Профиль «🇷🇺 AEGIS RU ENTRY»: весь трафик через мост. Пароль локальных прокси: $AU / $AP"
warn "Финальную проверку делайте с клиента ИЗ РФ: я проверил каскад со стороны EU-сервера."
warn "Откат: cp $SUB.bak-ruentry $SUB"
