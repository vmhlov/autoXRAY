#!/bin/bash
# ============================================================================
# aegis-xdrive-ydisk.sh — аварийный канал XDRIVE через Яндекс.Диск (template)
# Запускать НА EU-СЕРВЕРЕ, где уже выполнен aegis-upgrade.sh (есть AEGIS AUTO).
#
# Почему это новый канал: официальный template-бэкенд XDRIVE поддерживает
# двухшаговые операции hrefPath/hrefMethod — в исходнике Xray-core это прямо
# описано как сценарий Yandex Disk REST API. Клиент ходит ТОЛЬКО в
# cloud-api.yandex.ru и presigned-хосты Яндекс.Диска (российские, кандидаты
# на проход при белых списках), IP сервера не светится. В отличие от S3,
# запросы к API Диска не тарифицируются поштучно (лимиты частоты, не деньги).
#
# Использование:
#   bash aegis-xdrive-ydisk.sh FOLDER_NAME OAUTH_TOKEN [--pq]
#   FOLDER_NAME — имя папки в корне Диска (создаётся скриптом, латиница/цифры/-)
#   OAUTH_TOKEN — токен Яндекс OAuth с доступом к Диску (отдельный аккаунт!)
#
# Безопасность: токен в клиентском конфиге даёт доступ к Диску в рамках scope.
# Используйте ОТДЕЛЬНЫЙ Яндекс-аккаунт и отдельную папку.
# Откат: cp config.json.bak-ydisk config.json; cp <подписка>.json.bak-ydisk <подписка>.json; systemctl restart xray
# ============================================================================
set -u
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GRN}$*${NC}"; }; warn(){ echo -e "${YEL}$*${NC}"; }; die(){ echo -e "${RED}$*${NC}"; exit 1; }
[[ $EUID -eq 0 ]] || die "❌ Нужны root права"
for b in jq curl openssl xray systemctl; do command -v "$b" >/dev/null 2>&1 || die "❌ Нет команды: $b"; done
PQ=false; ARGS=()
for a in "$@"; do if [ "$a" = "--pq" ]; then PQ=true; else ARGS+=("$a"); fi; done
[ "${#ARGS[@]}" -eq 2 ] || die "❌ Использование: $0 FOLDER_NAME OAUTH_TOKEN [--pq]"
FOLDER="${ARGS[0]}"; TOKEN="${ARGS[1]}"
[[ "$FOLDER" =~ ^[A-Za-z0-9_-]+$ ]] || die "❌ FOLDER_NAME: только латиница, цифры, - и _"
CFG=/usr/local/etc/xray/config.json
[ -s "$CFG" ] || die "❌ Не найден $CFG"
SUB=""
for f in /var/www/*/*.json; do
    [ -s "$f" ] || continue
    if jq -e 'type=="array" and length>0 and (.[0].outbounds|type=="array")' "$f" >/dev/null 2>&1; then SUB="$f"; break; fi
done
[ -n "$SUB" ] || die "❌ Подписка не найдена"
jq -e 'map(select((.remarks // "") | startswith("🛡️ AEGIS AUTO"))) | length > 0' "$SUB" >/dev/null 2>&1 || die "❌ AEGIS AUTO не найден — сначала aegis-upgrade.sh"
V=$(xray version 2>/dev/null | awk 'NR==1 {print $2}')
[ -n "$V" ] && [ "$(printf '%s\n' "26.11.9" "$V" | sort -V | head -n1)" = "26.11.9" ] || die "❌ Нужен Xray >= 26.11.9 (сейчас: ${V:-нет})"
cp "$CFG" "$CFG.bak-ydisk"; cp "$SUB" "$SUB.bak-ydisk"
XG=$(id -gn xray 2>/dev/null || echo root)
API="https://cloud-api.yandex.ru/v1/disk"

warn "[1/5] Проверка токена и папки Яндекс.Диска..."
CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "Authorization: OAuth $TOKEN" "$API/")
[ "$CODE" = "200" ] || die "❌ Яндекс.Диск ответил HTTP $CODE на проверку токена (нужен scope доступа к Диску)"
FC=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 -X PUT -H "Authorization: OAuth $TOKEN" "$API/resources?path=/$FOLDER")
case "$FC" in 201|409) info "✅ Папка /$FOLDER готова";; *) die "❌ Не удалось создать папку (HTTP $FC)";; esac

warn "[2/5] Сборка template-бэкенда XDRIVE (Yandex Disk REST, двухшаговый href)..."
NR='"name"\s*:\s*"([^"]+)"'
TMPL=$(jq -n --arg api "$API" --arg nr "$NR" '{
  flatten: true,
  concurrency: 8,
  auth: { type: "static", header: { "Authorization": "OAuth {secret0}" } },
  put: {
    method: "GET",
    url: ($api + "/resources/upload?path=/{folder}/{name}&overwrite=true"),
    hrefPath: "href", hrefMethod: "PUT"
  },
  get: {
    method: "GET",
    url: ($api + "/resources/download?path=/{folder}/{name}"),
    hrefPath: "href", hrefMethod: "GET"
  },
  delete: {
    method: "DELETE",
    url: ($api + "/resources?path=/{folder}/{name}&permanently=true")
  },
  list: {
    method: "GET",
    url: ($api + "/resources?path=/{folder}&limit=1000"),
    namesRegex: $nr
  },
  retry: { status: [429, 500, 502, 503, 504] }
}')
printf '%s' "$TMPL" | jq empty >/dev/null 2>&1 || die "❌ template JSON невалиден"
ENC_OUT=$(xray vlessenc 2>/dev/null); [ -n "$ENC_OUT" ] || die "❌ vlessenc пуст"
if $PQ; then
    DEC=$(printf '%s\n' "$ENC_OUT" | grep '"decryption"' | grep -m1 'mlkem768x25519plus' | sed 's/.*: "\(.*\)"/\1/')
    ENC=$(printf '%s\n' "$ENC_OUT" | grep '"encryption"' | grep -m1 'mlkem768x25519plus' | sed 's/.*: "\(.*\)"/\1/')
fi
if [ -z "${DEC:-}" ] || [ -z "${ENC:-}" ]; then
    DEC=$(printf '%s\n' "$ENC_OUT" | grep -m1 '"decryption"' | sed 's/.*: "\(.*\)"/\1/')
    ENC=$(printf '%s\n' "$ENC_OUT" | grep -m1 '"encryption"' | sed 's/.*: "\(.*\)"/\1/')
fi
[ -n "$DEC" ] && [ -n "$ENC" ] || die "❌ Не удалось получить пару vlessenc"
UUID=$(xray uuid)
XD=$(jq -n --arg f "$FOLDER" --arg tok "$TOKEN" --arg t "$(printf '%s' "$TMPL" | jq -c .)" \
    '{service:"template", remoteFolder:$f, secrets:[$tok], template:$t, pollIntervalMs:200, maxPollIntervalMs:3000}')
INB=$(jq -n --arg u "$UUID" --arg d "$DEC" --argjson x "$XD" '{
    tag:"vsXDRIVEydisk", listen:"127.0.0.1", port:10996, protocol:"vless",
    settings:{clients:[{id:$u}], decryption:$d},
    streamSettings:{network:"xdrive", xdriveSettings:$x},
    sniffing:{enabled:true, destOverride:["http","tls","quic"]}}')
OB=$(jq -n --arg u "$UUID" --arg e "$ENC" --argjson x "$XD" '{
    tag:"proxy-xdrive-yd", protocol:"vless",
    settings:{vnext:[{address:"127.0.0.1", port:10996, users:[{id:$u, encryption:$e}]}]},
    streamSettings:{network:"xdrive", xdriveSettings:$x},
    mux:{enabled:true, concurrency:128}}')
jq --argjson in "$INB" '.inbounds = ([.inbounds[] | select(.tag != "vsXDRIVEydisk")] + [$in])' "$CFG" > "$CFG.yd" || die "❌ jq inbound"
jq empty "$CFG.yd" && xray run -test -config "$CFG.yd" >/dev/null 2>&1 || { rm -f "$CFG.yd"; die "❌ xray -test не прошёл (проверьте template)"; }
chown root:"$XG" "$CFG.yd" 2>/dev/null; chmod 640 "$CFG.yd"; mv "$CFG.yd" "$CFG"
systemctl restart xray; sleep 3

warn "[3/5] Живая самопроверка туннеля через Яндекс.Диск (до 120 с)..."
BASE=$(jq '.[0]' "$SUB")
AU=$(openssl rand -hex 4); AP=$(openssl rand -hex 12)
TCLI=$(jq -n --argjson base "$BASE" --argjson o "$OB" --arg au "$AU" --arg ap "$AP" '
    $base
    | .remarks = "ydisk-selftest"
    | .outbounds = [($o + {tag:"proxy"}),{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}]
    | .routing = {domainStrategy:"AsIs",rules:[{ip:["geoip:private"],outboundTag:"direct"}]}
    | .inbounds = [{tag:"s",protocol:"socks",listen:"127.0.0.1",port:18845,
        settings:{udp:true,auth:"password",accounts:[{user:$au,pass:$ap}]}}]
    | del(.burstObservatory, .observatory)')
TD=$(mktemp -d); printf '%s' "$TCLI" > "$TD/c.json"
xray run -config "$TD/c.json" > "$TD/c.log" 2>&1 & CPID=$!
sleep 2
RES=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 120 -x "socks5h://${AU}:${AP}@127.0.0.1:18845" https://www.google.com/generate_204)
kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null
if [ "${RES%% *}" != "204" ]; then
    cp "$TD/c.log" /root/aegis-ydisk-selftest.log 2>/dev/null
    rm -rf "$TD"
    jq '.inbounds |= map(select(.tag != "vsXDRIVEydisk"))' "$CFG" > "$CFG.yd" \
        && xray run -test -config "$CFG.yd" >/dev/null 2>&1 \
        && { chown root:"$XG" "$CFG.yd" 2>/dev/null; chmod 640 "$CFG.yd"; mv "$CFG.yd" "$CFG"; systemctl restart xray; } \
        || rm -f "$CFG.yd"
    die "❌ Самопроверка не прошла (ответ: ${RES:-нет}). Канал удалён. Лог: /root/aegis-ydisk-selftest.log"
fi
rm -rf "$TD"
info "✅ Туннель через Яндекс.Диск работает (${RES#* } с)"

warn "[4/5] Подписка: AUTO + RESERVE + standalone..."
umask 077
printf '%s' "$TCLI" | jq --argjson sp 10808 '
    .remarks = "☁️ AEGIS XDRIVE Yandex Disk"
    | .inbounds[0].port = $sp
    | .routing = {domainMatcher:"hybrid",domainStrategy:"AsIs",rules:[
        {domain:["geosite:category-ads"],outboundTag:"block"},
        {protocol:["bittorrent"],outboundTag:"block"},
        {ip:["geoip:private"],outboundTag:"direct"}]}' > /root/aegis-xdrive-ydisk-client.json
umask 022
jq --argjson o "$OB" '
  map(
    if ((.remarks // "") | (startswith("🛡️ AEGIS AUTO") or startswith("☁️ AEGIS XDRIVE RESERVE"))) then
      .outbounds = ((.outbounds | map(select(.tag != "proxy-xdrive-yd")))[0:-2] + [$o] + (.outbounds | map(select(.tag != "proxy-xdrive-yd")))[-2:])
    else . end)
' "$SUB" > "$SUB.yd" || die "❌ jq подписки, откат: cp $SUB.bak-ydisk $SUB"
jq empty "$SUB.yd" || die "❌ подписка невалидна, откат: cp $SUB.bak-ydisk $SUB"
mv "$SUB.yd" "$SUB"; chmod 644 "$SUB"

warn "[5/5] Готово."
info "Канал Яндекс.Диск добавлен в AEGIS AUTO и XDRIVE RESERVE."
info "standalone: /root/aegis-xdrive-ydisk-client.json (socks 10808, логин $AU пароль $AP)"
warn "Экспериментально: list без пагинации (лимит 1000 объектов) — при очень высокой нагрузке возможны пропуски; используйте как аварийный канал."
warn "Откат: cp $CFG.bak-ydisk $CFG && cp $SUB.bak-ydisk $SUB && systemctl restart xray"
