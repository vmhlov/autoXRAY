#!/bin/bash
# ============================================================================
# aegis-imap-lane.sh — аварийный канал через IMAP-черновики (true-imap-tunnel)
# Запускать НА EU-СЕРВЕРЕ. Поднимает IMAP-relay (mail.ru) и профиль для десктопа.
#
# Проверено по noiseonwires/true-imap-tunnel v0.5.0 (README + docs/configuration.md):
#   - TCP-туннель внутри IMAP-черновиков, БЕЗ SMTP/отправки писем;
#   - обе стороны логинятся в один IMAP-ящик, две папки (C2S/S2C), IDLE/поллинг;
#   - провайдер: Mail.ru быстрый/стабильный (лучший), Yandex-почта медленная и
#     отваливается через ~минуту (ratelimit) -> используем imap.mail.ru:993;
#   - для уже-шифрованного VLESS passphrase можно пустой (без двойного шифрования);
#   - готовые бинарники v0.5.0: linux-amd64/arm64, windows-amd64, android-arm64.
#
# Цепочка: Xray-клиент -> локальный imap-клиент -> IMAP mail.ru -> imap-сервер(EU)
#          -> Xray EU:443 -> WARP -> интернет. Клиент видит только mail.ru.
#
# Использование:
#   bash aegis-imap-lane.sh IMAP_USER IMAP_APP_PASSWORD [--host imap.mail.ru:993] [--passphrase SECRET]
#   IMAP_APP_PASSWORD — пароль для внешнего приложения (mail.ru: Настройки -> Пароли для приложений).
#
# Откат: systemctl disable --now aegis-imap; rm /usr/local/etc/aegis-imap -r
# ============================================================================
set -u
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GRN}$*${NC}"; }; warn(){ echo -e "${YEL}$*${NC}"; }; die(){ echo -e "${RED}$*${NC}"; exit 1; }
[[ $EUID -eq 0 ]] || die "❌ Нужны root права"
for b in jq curl tar xray systemctl; do command -v "$b" >/dev/null 2>&1 || die "❌ Нет команды: $b"; done
[ $# -ge 2 ] || die "❌ Использование: $0 IMAP_USER IMAP_APP_PASSWORD [--host HOST:993] [--passphrase SECRET]"
IMAP_USER="$1"; IMAP_PASS="$2"; shift 2
IMAP_HOST="imap.mail.ru:993"; PASSPHRASE=""
while [ $# -gt 0 ]; do case "$1" in
  --host) IMAP_HOST="$2"; shift 2;;
  --passphrase) PASSPHRASE="$2"; shift 2;;
  *) die "❌ Неизвестный аргумент: $1";; esac; done
CFG=/usr/local/etc/xray/config.json
[ -s "$CFG" ] || die "❌ Не найден $CFG"
SUB=""
for f in /var/www/*/*.json; do
  [ -s "$f" ] || continue
  if jq -e 'type=="array" and length>0 and (.[0].outbounds|type=="array")' "$f" >/dev/null 2>&1; then SUB="$f"; break; fi
done
[ -n "$SUB" ] || die "❌ Подписка не найдена"
DOMAIN=$(basename "$(dirname "$SUB")")
UUID=$(jq -r '.inbounds[] | select(.tag=="vsRAWtlsVISION") | .settings.clients[0].id // empty' "$CFG")
[ -n "$UUID" ] || die "❌ Не найден UUID инбаунда vsRAWtlsVISION"
cp "$SUB" "$SUB.bak-imap"
D=/usr/local/etc/aegis-imap; mkdir -p "$D"; chmod 700 "$D"
C2S="AeC$(openssl rand -hex 3)"; S2C="AeS$(openssl rand -hex 3)"

warn "[1/5] Установка бинарника true-imap-tunnel v0.5.0..."
ARCH=$(uname -m); case "$ARCH" in x86_64) A=amd64;; aarch64) A=arm64;; *) die "❌ Архитектура $ARCH не поддержана готовым бинарником";; esac
TD=$(mktemp -d)
curl -fsSL --max-time 120 -o "$TD/t.tar.gz" "https://github.com/noiseonwires/true-imap-tunnel/releases/download/v0.5.0/true-imap-tunnel-linux-$A.tar.gz" || { rm -rf "$TD"; die "❌ Не скачался бинарник"; }
tar xzf "$TD/t.tar.gz" -C "$TD" || { rm -rf "$TD"; die "❌ Не распаковался архив"; }
BIN=$(find "$TD" -type f -name 'true-imap-tunnel*' ! -name '*.tar.gz' | head -n1)
[ -n "$BIN" ] || { rm -rf "$TD"; die "❌ Бинарник не найден в архиве"; }
install -m 755 "$BIN" /usr/local/bin/true-imap-tunnel; rm -rf "$TD"
info "✅ /usr/local/bin/true-imap-tunnel установлен"

warn "[2/5] Конфиги server.yaml + client.yaml (папки $C2S / $S2C)..."
yaml_account(){ # $1=send $2=recv
  printf '  - name: "primary"\n    host: "%s"\n    username: "%s"\n    password: "%s"\n    tls: "implicit"\n    folder_send: "%s"\n    folder_recv: "%s"\n' \
    "$IMAP_HOST" "$IMAP_USER" "$IMAP_PASS" "$1" "$2"
}
{
  echo 'mode: server'
  echo 'target: "127.0.0.1:443"'
  echo 'log_level: info'
  echo 'accounts:'
  yaml_account "$S2C" "$C2S"
  echo 'async_data_send: true'
  echo 'batch_delay_ms: 2'
  echo 'throttle_backoff_ms: 60000'
  echo 'reorder: true'
  [ -n "$PASSPHRASE" ] && printf 'client_encryption_passphrases:\n  1: "%s"\n' "$PASSPHRASE"
} > "$D/server.yaml"
{
  echo 'mode: client'
  echo 'listen: "127.0.0.1:10997"'
  echo 'client_id: 1'
  echo 'log_level: info'
  echo 'accounts:'
  yaml_account "$C2S" "$S2C"
  echo 'async_data_send: true'
  echo 'batch_delay_ms: 2'
  echo 'throttle_backoff_ms: 60000'
  echo 'reorder: true'
  [ -n "$PASSPHRASE" ] && printf 'encryption_passphrase: "%s"\n' "$PASSPHRASE"
} > "$D/client.yaml"
chmod 600 "$D/server.yaml" "$D/client.yaml"

warn "[3/5] systemd-сервис imap-сервера..."
cat > /etc/systemd/system/aegis-imap.service <<UNIT
[Unit]
Description=AEGIS IMAP relay (true-imap-tunnel server)
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/usr/local/bin/true-imap-tunnel -config $D/server.yaml
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload; systemctl enable --now aegis-imap.service >/dev/null 2>&1
sleep 3
systemctl is-active --quiet aegis-imap.service || { journalctl -u aegis-imap -n 20 --no-pager; die "❌ imap-сервер не стартовал (проверь логин/пароль/папки)"; }

warn "[4/5] Живая самопроверка сквозь IMAP (Xray->imap->mail.ru->EU:443)..."
TD=$(mktemp -d)
sed 's/127.0.0.1:10997/127.0.0.1:18860/' "$D/client.yaml" > "$D/test-client.yaml"
/usr/local/bin/true-imap-tunnel -config "$D/test-client.yaml" > "$TD/ic.log" 2>&1 & IPID=$!
sleep 3
XCLI=$(jq -n --arg u "$UUID" --arg sni "$DOMAIN" '
  {log:{loglevel:"warning"},
   dns:{servers:["https://1.1.1.1/dns-query"],queryStrategy:"UseIPv4"},
   routing:{domainStrategy:"AsIs",rules:[{ip:["geoip:private"],outboundTag:"direct"}]},
   inbounds:[{tag:"s",protocol:"socks",listen:"127.0.0.1",port:18861,settings:{udp:true}}],
   outbounds:[{tag:"proxy",protocol:"vless",
     settings:{vnext:[{address:"127.0.0.1",port:18860,users:[{id:$u,flow:"xtls-rprx-vision",encryption:"none"}]}]},
     streamSettings:{network:"raw",security:"tls",tlsSettings:{serverName:$sni,fingerprint:"chrome"}}},
    {tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}]}')
printf '%s' "$XCLI" > "$TD/x.json"
xray run -config "$TD/x.json" > "$TD/x.log" 2>&1 & XPID=$!
sleep 2
RES=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 90 -x socks5h://127.0.0.1:18861 https://www.google.com/generate_204)
kill "$XPID" "$IPID" 2>/dev/null; wait "$XPID" "$IPID" 2>/dev/null
rm -f "$D/test-client.yaml"; rm -rf "$TD"
if [ "${RES%% *}" != "204" ]; then
  systemctl disable --now aegis-imap.service >/dev/null 2>&1
  die "❌ Самопроверка IMAP не прошла (ответ: ${RES:-нет}). Сервис остановлен. Лог: journalctl -u aegis-imap -n 30"
fi
info "✅ IMAP-канал работает (${RES#* } с)"

warn "[5/5] Профиль подписки + клиентский пакет..."
BASE=$(jq '.[0]' "$SUB")
AU=$(openssl rand -hex 4); AP=$(openssl rand -hex 12)
IMAP_OB=$(jq -n --arg u "$UUID" --arg sni "$DOMAIN" '
  {tag:"proxy",protocol:"vless",
   settings:{vnext:[{address:"127.0.0.1",port:10997,users:[{id:$u,flow:"xtls-rprx-vision",encryption:"none"}]}]},
   streamSettings:{network:"raw",security:"tls",tlsSettings:{serverName:$sni,fingerprint:"chrome"}}}')
PROFILE=$(jq -n --argjson base "$BASE" --argjson o "$IMAP_OB" --arg au "$AU" --arg ap "$AP" '
  $base
  | .remarks = "📧 AEGIS IMAP (desktop: нужен локальный imap-клиент)"
  | .outbounds = [$o,{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}]
  | .inbounds |= map(if .protocol=="http" then .settings=((.settings//{})+{accounts:[{user:$au,pass:$ap}]}) else .settings=((.settings//{})+{auth:"password",accounts:[{user:$au,pass:$ap}]}) end)
  | .routing = {domainMatcher:"hybrid",domainStrategy:"AsIs",rules:[
      {domain:["geosite:category-ads"],outboundTag:"block"},
      {protocol:["bittorrent"],outboundTag:"block"},
      {ip:["geoip:private"],outboundTag:"direct"}]}
  | del(.burstObservatory,.observatory)')
jq --argjson p "$PROFILE" 'map(select(((.remarks//"")|startswith("📧 AEGIS IMAP"))|not)) + [$p]' "$SUB" > "$SUB.im" || die "❌ jq подписки"
jq empty "$SUB.im" || die "❌ подписка невалидна, откат: cp $SUB.bak-imap $SUB"
mv "$SUB.im" "$SUB"; chmod 644 "$SUB"
cp "$D/client.yaml" /root/aegis-imap-client.yaml; chmod 600 /root/aegis-imap-client.yaml
echo
info "Готово. IMAP-канал (mail.ru) поднят и проверен."
info "Клиентский YAML: /root/aegis-imap-client.yaml (скопируй на ПК)"
info "Профиль подписки: «📧 AEGIS IMAP (desktop)». Пароль локальных прокси: $AU / $AP"
echo
warn "НА КЛИЕНТЕ (Windows): скачай true-imap-tunnel-windows-amd64.7z (v0.5.0), распакуй,"
warn "положи рядом aegis-imap-client.yaml и запусти: true-imap-tunnel.exe -config aegis-imap-client.yaml"
warn "Затем в Happ/v2rayN выбери профиль «📧 AEGIS IMAP». Весь трафик пойдёт через mail.ru IMAP."
warn "Android: нужен Termux (бинарник android-arm64) либо SIP003-плагин с Shadowsocks-клиентом."
warn "Откат: systemctl disable --now aegis-imap && rm -rf $D && cp $SUB.bak-imap $SUB"
