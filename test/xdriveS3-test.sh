#!/bin/bash
# autoXRAY: VLESS через S3-хранилище (транспорт XDRIVE, Xray-core >= v26.11.9).
# Клиент и сервер не соединяются напрямую: оба читают и пишут объекты в один бакет.
# Описание и ограничения: test/xdrive-readme.md
#
# bash xdriveS3-test.sh ENDPOINT BUCKET ACCESS_KEY SECRET_KEY [REGION]
#   Yandex Object Storage: https://storage.yandexcloud.net  регион ru-central1 (по умолчанию)
#   VK Cloud:              https://hb.ru-msk.vkcloud-solutions.com  регион ru-msk

GRN='\033[1;32m'
RED='\033[1;31m'
YEL='\033[1;33m'
NC='\033[0m'

[[ $EUID -eq 0 ]] || { echo -e "${RED}❌ скрипту нужны root права ${NC}"; exit 1; }

S3_ENDPOINT=${1%/}
S3_BUCKET=$2
S3_KEY=$3
S3_SECRET=$4
S3_REGION=${5:-ru-central1}
S3_FOLDER="xd$(openssl rand -hex 3)"

if [ -z "$S3_ENDPOINT" ] || [ -z "$S3_BUCKET" ] || [ -z "$S3_KEY" ] || [ -z "$S3_SECRET" ]; then
    echo -e "${RED}❌ Использование: bash $0 ENDPOINT BUCKET ACCESS_KEY SECRET_KEY [REGION]${NC}"
    exit 1
fi

XRAY_MIN_VERSION="26.11.9"
XRAY_CONFIG=/usr/local/etc/xray/config.json
CLIENT_FILE=/root/xdriveS3-client.json
TAG="vsXDRIVEs3"

xray_version_ok() {
    local v
    v=$(xray version 2>/dev/null | awk 'NR==1 {print $2}')
    [ -n "$v" ] && [ "$(printf '%s\n' "$XRAY_MIN_VERSION" "$v" | sort -V | head -n1)" = "$XRAY_MIN_VERSION" ]
}

echo -e "${YEL}Установка необходимых пакетов...${NC}"
apt-get update && apt-get install curl jq openssl -y

# Проверяем ключи и бакет до изменения конфигурации (curl >= 7.75 умеет подпись AWS SigV4)
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
    --aws-sigv4 "aws:amz:$S3_REGION:s3" --user "$S3_KEY:$S3_SECRET" \
    "$S3_ENDPOINT/$S3_BUCKET?list-type=2&max-keys=1")
if [ "$code" != "200" ]; then
    echo -e "${RED}❌ S3 ответил HTTP $code на запрос к бакету $S3_BUCKET. Проверьте endpoint, регион, имя бакета и права ключа.${NC}"
    exit 1
fi
echo -e "${GRN}✅ Доступ к бакету $S3_BUCKET есть${NC}"

if ! xray_version_ok; then
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
    xray_version_ok || { echo -e "${RED}❌ Нужен Xray >= $XRAY_MIN_VERSION${NC}"; exit 1; }
fi
echo -e "${GRN}Xray $(xray version | awk 'NR==1 {print $2}')${NC}"

uuid=$(xray uuid)
enc_pair=$(xray vlessenc)
# Первая пара в выводе vlessenc — аутентификация X25519 (короткие ключи, удобно для ссылок)
decryption=$(echo "$enc_pair" | grep -m1 '"decryption"' | sed 's/.*: "\(.*\)"/\1/')
encryption=$(echo "$enc_pair" | grep -m1 '"encryption"' | sed 's/.*: "\(.*\)"/\1/')

# Порт фиктивный: XDRIVE слушает папку в бакете, а не сокет. Клиент должен указать тот же порт.
xdrive=$(jq -n --arg e "$S3_ENDPOINT" --arg r "$S3_REGION" --arg b "$S3_BUCKET" \
    --arg k "$S3_KEY" --arg s "$S3_SECRET" --arg f "$S3_FOLDER" '{
    service: "s3", remoteFolder: $f, secrets: [$k, $s],
    s3: { endpoint: $e, region: $r, bucket: $b, pathStyle: true },
    pollIntervalMs: 200, maxPollIntervalMs: 3000
}')

inbound=$(jq -n --arg tag "$TAG" --arg u "$uuid" --arg d "$decryption" --argjson x "$xdrive" '{
    tag: $tag, listen: "127.0.0.1", port: 10999, protocol: "vless",
    settings: { clients: [ { id: $u } ], decryption: $d },
    streamSettings: { network: "xdrive", xdriveSettings: $x },
    sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] }
}')

mkdir -p "$(dirname "$XRAY_CONFIG")"
[ -s "$XRAY_CONFIG" ] || echo '{}' > "$XRAY_CONFIG"
cp "$XRAY_CONFIG" "$XRAY_CONFIG.bak-xdrive"

# Повторный запуск заменяет прежний XDRIVE inbound, остальные inbound'ы autoXRAY не трогаем
jq --argjson in "$inbound" --arg tag "$TAG" '
    .inbounds = ([(.inbounds // [])[] | select(.tag != $tag)] + [$in])
    | if (.outbounds // []) == [] then .outbounds = [{tag: "direct", protocol: "freedom"}] else . end
' "$XRAY_CONFIG.bak-xdrive" > "${XRAY_CONFIG%.json}.new.json" || { echo -e "${RED}❌ Не удалось разобрать $XRAY_CONFIG${NC}"; exit 1; }

if ! xray run -test -config "${XRAY_CONFIG%.json}.new.json" >/dev/null 2>&1; then
    xray run -test -config "${XRAY_CONFIG%.json}.new.json" | tail -3
    rm -f "${XRAY_CONFIG%.json}.new.json"
    echo -e "${RED}❌ Xray отклонил конфигурацию, старый конфиг не изменён${NC}"
    exit 1
fi
mv "${XRAY_CONFIG%.json}.new.json" "$XRAY_CONFIG"
chown root:"$(id -gn xray 2>/dev/null || echo root)" "$XRAY_CONFIG"
chmod 640 "$XRAY_CONFIG"
systemctl restart xray

print_client() {
    local socks_port=$1 http_port=$2
    jq -n --arg u "$uuid" --arg e "$encryption" --argjson x "$xdrive" \
        --argjson sp "$socks_port" --argjson hp "$http_port" '{
    log: { loglevel: "warning" },
    dns: { servers: ["https://8.8.8.8/dns-query", "https://1.1.1.1/dns-query"], queryStrategy: "UseIPv4" },
    routing: {
        domainStrategy: "IPIfNonMatch",
        rules: [
            { domain: ["geosite:category-ads"], outboundTag: "block" },
            { domain: ["geosite:private", "geosite:category-ru"], outboundTag: "direct" },
            { ip: ["geoip:private"], outboundTag: "direct" }
        ]
    },
    inbounds: [
        { tag: "socks-in", protocol: "socks", listen: "127.0.0.1", port: $sp, settings: { udp: true },
          sniffing: { enabled: true, destOverride: ["http", "tls", "quic"] } },
        { tag: "http-in", protocol: "http", listen: "127.0.0.1", port: $hp }
    ],
    outbounds: [
        { tag: "proxy", protocol: "vless",
          settings: { vnext: [ { address: "127.0.0.1", port: 10999, users: [ { id: $u, encryption: $e } ] } ] },
          streamSettings: { network: "xdrive", xdriveSettings: $x },
          mux: { enabled: true, concurrency: 128 } },
        { tag: "direct", protocol: "freedom" },
        { tag: "block", protocol: "blackhole" }
    ],
    remarks: "🇷🇺☁️ VLESS XDRIVE S3"
}'
}

umask 077
print_client 10808 10809 > "$CLIENT_FILE"

# Самопроверка: временный клиент на этом же сервере ходит в интернет через бакет
echo -e "${YEL}Проверка туннеля через S3 (до 90 секунд)...${NC}"
selftest=$(mktemp -d)
print_client 18808 18809 > "$selftest/client.json"
xray run -config "$selftest/client.json" > "$selftest/client.log" 2>&1 &
client_pid=$!
sleep 2
result=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 90 \
    -x socks5h://127.0.0.1:18808 https://www.google.com/generate_204)
kill "$client_pid" 2>/dev/null
wait "$client_pid" 2>/dev/null
rm -rf "$selftest"

if [ "${result%% *}" = "204" ]; then
    echo -e "${GRN}✅ Туннель через S3 работает (первый запрос: ${result#* } с)${NC}"
else
    echo -e "${RED}❌ Самопроверка не прошла (ответ: ${result:-нет}). Смотрите: journalctl -u xray -n 50${NC}"
    exit 1
fi

echo -e "
${YEL}Клиентский конфиг сохранён:${NC} $CLIENT_FILE

${YEL}Нужен клиент на Xray-core >= v26.11.9${NC} (например, v2rayN с обновлённым ядром: импорт custom-конфига).
Ссылки vless:// для XDRIVE не существует, переносите JSON-файл целиком.

${RED}В конфиге лежат ключи от бакета.${NC} Используйте отдельный бакет и ключ сервисного аккаунта с доступом только к нему.
Подробности: https://github.com/vmhlov/autoXRAY/blob/main/test/xdrive-readme.md
"
