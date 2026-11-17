#!/bin/bash
# ============================================================================
# aegis-xdrive-gdrive.sh — аварийный канал XDRIVE через Google Drive
# Запускать НА EU-СЕРВЕРЕ, где уже выполнен aegis-upgrade.sh (есть AEGIS AUTO).
# Бэкенд Google Drive оптимизирован в Xray v26.11.9 (кольцо слотов, read-ahead,
# hedged reads, фоновый refresh токена) — дефолты ядра не переопределяются.
#
# Требования (проверено по transport/internet/xdrive/drive.go):
#   - Xray >= 26.11.9;
#   - ровно 3 секрета в порядке: ClientID, ClientSecret, RefreshToken;
#   - remoteFolder = id папки Google Drive.
#
# Использование:
#   bash aegis-xdrive-gdrive.sh FOLDER_ID CLIENT_ID CLIENT_SECRET REFRESH_TOKEN [--pq]
#
# Безопасность: refresh token в клиентском конфиге даёт доступ к Drive в рамках
# выданного scope. Используйте ОТДЕЛЬНЫЙ Google-аккаунт и отдельную папку.
# Откат: cp config.json.bak-gdrive config.json; cp <подписка>.json.bak-gdrive <подписка>.json; systemctl restart xray
# ============================================================================
set -u
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GRN}$*${NC}"; }; warn(){ echo -e "${YEL}$*${NC}"; }; die(){ echo -e "${RED}$*${NC}"; exit 1; }
[[ $EUID -eq 0 ]] || die "❌ Нужны root права"
for b in jq curl openssl xray systemctl; do command -v "$b" >/dev/null 2>&1 || die "❌ Нет команды: $b"; done
PQ=false; ARGS=()
for a in "$@"; do if [ "$a" = "--pq" ]; then PQ=true; else ARGS+=("$a"); fi; done
[ "${#ARGS[@]}" -eq 4 ] || die "❌ Использование: $0 FOLDER_ID CLIENT_ID CLIENT_SECRET REFRESH_TOKEN [--pq]"
FOLDER="${ARGS[0]}"; CID="${ARGS[1]}"; CSEC="${ARGS[2]}"; RTOK="${ARGS[3]}"
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
cp "$CFG" "$CFG.bak-gdrive"; cp "$SUB" "$SUB.bak-gdrive"
XG=$(id -gn xray 2>/dev/null || echo root)

warn "[1/4] Проверка OAuth-токена (oauth2.googleapis.com/token)..."
TRESP=$(curl -s --max-time 20 \
    --data-urlencode "client_id=$CID" --data-urlencode "client_secret=$CSEC" \
    --data-urlencode "refresh_token=$RTOK" --data-urlencode "grant_type=refresh_token" \
    https://oauth2.googleapis.com/token)
printf '%s' "$TRESP" | jq -e '.access_token' >/dev/null 2>&1 || die "❌ Google не выдал access token: $(printf '%s' "$TRESP" | head -c 300)"
info "✅ OAuth-credentials работают"

warn "[2/4] Ключи VLESS и inbound XDRIVE (google-drive)..."
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
XD=$(jq -n --arg f "$FOLDER" --arg a "$CID" --arg b "$CSEC" --arg c "$RTOK" \
    '{service:"google-drive", remoteFolder:$f, secrets:[$a,$b,$c]}')
INB=$(jq -n --arg u "$UUID" --arg d "$DEC" --argjson x "$XD" '{
    tag:"vsXDRIVEgdrive", listen:"127.0.0.1", port:10995, protocol:"vless",
    settings:{clients:[{id:$u}], decryption:$d},
    streamSettings:{network:"xdrive", xdriveSettings:$x},
    sniffing:{enabled:true, destOverride:["http","tls","quic"]}}')
OB=$(jq -n --arg u "$UUID" --arg e "$ENC" --argjson x "$XD" '{
    tag:"proxy-xdrive-gd", protocol:"vless",
    settings:{vnext:[{address:"127.0.0.1", port:10995, users:[{id:$u, encryption:$e}]}]},
    streamSettings:{network:"xdrive", xdriveSettings:$x},
    mux:{enabled:true, concurrency:128}}')
jq --argjson in "$INB" '.inbounds = ([.inbounds[] | select(.tag != "vsXDRIVEgdrive")] + [$in])' "$CFG" > "$CFG.gd" || die "❌ jq inbound"
jq empty "$CFG.gd" && xray run -test -config "$CFG.gd" >/dev/null 2>&1 || { rm -f "$CFG.gd"; die "❌ xray -test не прошёл"; }
chown root:"$XG" "$CFG.gd" 2>/dev/null; chmod 640 "$CFG.gd"; mv "$CFG.gd" "$CFG"
systemctl restart xray; sleep 3

warn "[3/4] Живая самопроверка туннеля через Google Drive (до 120 с)..."
BASE=$(jq '.[0]' "$SUB")
AU=$(openssl rand -hex 4); AP=$(openssl rand -hex 12)
TCLI=$(jq -n --argjson base "$BASE" --argjson o "$OB" --arg au "$AU" --arg ap "$AP" '
    $base
    | .remarks = "gdrive-selftest"
    | .outbounds = [($o + {tag:"proxy"}),{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}]
    | .routing = {domainStrategy:"AsIs",rules:[{ip:["geoip:private"],outboundTag:"direct"}]}
    | .inbounds = [{tag:"s",protocol:"socks",listen:"127.0.0.1",port:18840,
        settings:{udp:true,auth:"password",accounts:[{user:$au,pass:$ap}]}}]
    | del(.burstObservatory, .observatory)')
TD=$(mktemp -d); printf '%s' "$TCLI" > "$TD/c.json"
xray run -config "$TD/c.json" > "$TD/c.log" 2>&1 & CPID=$!
sleep 2
RES=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 120 -x "socks5h://${AU}:${AP}@127.0.0.1:18840" https://www.google.com/generate_204)
kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; rm -rf "$TD"
if [ "${RES%% *}" != "204" ]; then
    jq '.inbounds |= map(select(.tag != "vsXDRIVEgdrive"))' "$CFG" > "$CFG.gd" \
        && xray run -test -config "$CFG.gd" >/dev/null 2>&1 \
        && { chown root:"$XG" "$CFG.gd" 2>/dev/null; chmod 640 "$CFG.gd"; mv "$CFG.gd" "$CFG"; systemctl restart xray; } \
        || rm -f "$CFG.gd"
    die "❌ Самопроверка не прошла (ответ: ${RES:-нет}). Канал удалён, конфиг откачен. Лог: journalctl -u xray -n 50"
fi
info "✅ Туннель через Google Drive работает (${RES#* } с)"

warn "[4/4] Подписка: AUTO + RESERVE + standalone..."
umask 077
printf '%s' "$TCLI" | jq --argjson sp 10808 '
    .remarks = "☁️ AEGIS XDRIVE Google Drive"
    | .inbounds[0].port = $sp
    | .routing = {domainMatcher:"hybrid",domainStrategy:"AsIs",rules:[
        {domain:["geosite:category-ads"],outboundTag:"block"},
        {protocol:["bittorrent"],outboundTag:"block"},
        {ip:["geoip:private"],outboundTag:"direct"}]}' > /root/aegis-xdrive-gdrive-client.json
umask 022
jq --argjson o "$OB" '
  map(
    if ((.remarks // "") | (startswith("🛡️ AEGIS AUTO") or startswith("☁️ AEGIS XDRIVE RESERVE"))) then
      .outbounds = ((.outbounds | map(select(.tag != "proxy-xdrive-gd")))[0:-2] + [$o] + (.outbounds | map(select(.tag != "proxy-xdrive-gd")))[-2:])
    else . end)
' "$SUB" > "$SUB.gd" || die "❌ jq подписки, откат: cp $SUB.bak-gdrive $SUB"
jq empty "$SUB.gd" || die "❌ подписка невалидна, откат: cp $SUB.bak-gdrive $SUB"
mv "$SUB.gd" "$SUB"; chmod 644 "$SUB"
echo
info "Готово. Канал Google Drive добавлен в AEGIS AUTO и XDRIVE RESERVE."
info "standalone-конфиг: /root/aegis-xdrive-gdrive-client.json (socks 10808, логин $AU пароль $AP)"
info "Квоты Drive API соблюдаются ядром автоматически (backoff при rate limit)."
warn "Откат: cp $CFG.bak-gdrive $CFG && cp $SUB.bak-gdrive $SUB && systemctl restart xray"
