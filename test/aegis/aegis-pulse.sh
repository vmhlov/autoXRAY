#!/bin/bash
# ============================================================================
# aegis-pulse.sh — монитор сигнатур заморозки/блокировки на RU-мосту
# Запускать НА RU-СЕРВЕРЕ, где стоит bridgeTLSxhttp.sh (там есть outbound proxy-N).
# Методика: Хабр 1105268 (направленная блокировка RU->EU) + net4people #490
# (заморозка после ~15-20 КБ ответа). Качает >20 КБ через каждый EU-канал,
# чтобы спровоцировать/детектить заморозку, и отличает её от блокировки IP.
#
# Использование:
#   bash aegis-pulse.sh                 # один цикл проверок
#   bash aegis-pulse.sh --install       # поставить systemd-таймер (120 с)
#   bash aegis-pulse.sh --url URL --bytes 65536 --webhook https://...
#
# Перед первым запуском: bash -n aegis-pulse.sh
# ============================================================================
set -u
GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GRN}$*${NC}"; }; warn(){ echo -e "${YEL}$*${NC}"; }; die(){ echo -e "${RED}$*${NC}"; exit 1; }
[[ $EUID -eq 0 ]] || die "❌ Нужны root права"
for b in jq curl xray awk; do command -v "$b" >/dev/null 2>&1 || die "❌ Нет команды: $b"; done

CFG=/usr/local/etc/xray/config.json
LOG=/var/log/xray/aegis-pulse.log
BULK_URL="https://speed.cloudflare.com/__down?bytes=65536"
BYTES=65536
WEBHOOK=""
INSTALL=false
while [ $# -gt 0 ]; do
  case "$1" in
    --install) INSTALL=true; shift;;
    --url) BULK_URL="$2"; shift 2;;
    --bytes) BYTES="$2"; shift 2;;
    --webhook) WEBHOOK="$2"; shift 2;;
    *) die "❌ Неизвестный аргумент: $1";;
  esac
done

if $INSTALL; then
  install -m 750 "$0" /usr/local/bin/aegis-pulse.sh
  cat > /etc/systemd/system/aegis-pulse.service <<'UNIT'
[Unit]
Description=AEGIS pulse: freeze/block monitor (RU vantage)
After=network-online.target xray.service
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/aegis-pulse.sh
UNIT
  cat > /etc/systemd/system/aegis-pulse.timer <<'UNIT'
[Unit]
Description=Run AEGIS pulse every 120s
[Timer]
OnBootSec=120
OnUnitActiveSec=120
AccuracySec=20
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now aegis-pulse.timer >/dev/null 2>&1
  info "✅ Таймер aegis-pulse установлен (120 с). Лог: $LOG"
  exit 0
fi

[ -s "$CFG" ] || die "❌ Не найден $CFG (запусти на RU-мосту)"
OBS=$(jq -c '[.outbounds[] | select((.tag // "") | startswith("proxy-"))]' "$CFG")
[ "$(printf '%s' "$OBS" | jq 'length')" -ge 1 ] || die "❌ В конфиге нет outbound proxy-N (это не мост?)"
mkdir -p "$(dirname "$LOG")"; touch "$LOG"
AU=$(openssl rand -hex 4 2>/dev/null || echo au); AP=$(openssl rand -hex 12 2>/dev/null || echo ap)
HOST=$(hostname)
healthy=0; i=0
warn "== AEGIS pulse: $HOST -> EU (RU->EU, provoke >20KB) =="
while IFS= read -r ob; do
  i=$((i+1))
  tag=$(printf '%s' "$ob" | jq -r '.tag')
  addr=$(printf '%s' "$ob" | jq -r '.settings.vnext[0].address // "?"')
  sp=$((18850+i))
  cli=$(jq -n --argjson o "$ob" --arg au "$AU" --arg ap "$AP" --argjson sp "$sp" '
    {log:{loglevel:"warning"},
     dns:{servers:["https://1.1.1.1/dns-query","https://8.8.8.8/dns-query"],queryStrategy:"UseIPv4"},
     routing:{domainStrategy:"AsIs",rules:[{ip:["geoip:private"],outboundTag:"direct"}]},
     inbounds:[{tag:"s",protocol:"socks",listen:"127.0.0.1",port:$sp,
       settings:{udp:true,auth:"password",accounts:[{user:$au,pass:$ap}]}}],
     outbounds:[($o + {tag:"proxy"}),{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}]}')
  td=$(mktemp -d); printf '%s' "$cli" > "$td/c.json"
  if ! xray run -test -config "$td/c.json" >/dev/null 2>&1; then
    rm -rf "$td"; warn "$tag: xray -test не прошёл — пропуск"; continue
  fi
  xray run -config "$td/c.json" > "$td/c.log" 2>&1 & pid=$!
  sleep 2
  reach=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 \
     -x "socks5h://${AU}:${AP}@127.0.0.1:${sp}" https://www.google.com/generate_204)
  bulk=$(curl -s -o /dev/null -w '%{http_code} %{size_download} %{time_total}' --max-time 25 \
     -x "socks5h://${AU}:${AP}@127.0.0.1:${sp}" "$BULK_URL")
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -rf "$td"
  code=${bulk%% *}; rest=${bulk#* }; size=${rest%% *}; time=${rest#* }
  verdict="degraded"
  if [ "$code" = "000" ]; then verdict="block"
  elif [ "$code" = "200" ] || [ "$code" = "206" ]; then
    h=$(awk -v s="$size" -v b="$BYTES" 'BEGIN{print (s>=b*0.9)?1:0}')
    st=$(awk -v s="$size" -v t="$time" -v b="$BYTES" 'BEGIN{print (s<b*0.5 && t>=20)?1:0}')
    if [ "$h" = "1" ]; then verdict="healthy"; healthy=$((healthy+1))
    elif [ "$st" = "1" ]; then verdict="freeze"
    fi
  fi
  jq -n --arg ts "$(date -u +%FT%TZ)" --arg tag "$tag" --arg addr "$addr" \
     --arg reach "$reach" --arg code "$code" --argjson bytes "${size:-0}" \
     --arg time "$time" --arg verdict "$verdict" \
     '{ts:$ts,tag:$tag,addr:$addr,reach:$reach,bulk_code:$code,bytes:$bytes,time:$time,verdict:$verdict}' >> "$LOG"
  case "$verdict" in
    healthy) info "$tag ($addr): HEALTHY (reach=$reach, ${size}B за ${time}s)";;
    freeze)  warn "$tag ($addr): FREEZE — соединение есть, но обрыв после частичной передачи (сигнатура ~15-20KB)";;
    block)   echo -e "${RED}$tag ($addr): BLOCK — тихий дроп (сигнатура точечной IP-блокировки)${NC}";;
    *)       warn "$tag ($addr): DEGRADED (reach=$reach, code=$code, ${size}B)";;
  esac
done < <(printf '%s' "$OBS" | jq -c '.[]')

if [ "$healthy" -eq 0 ]; then
  echo -e "${RED}❌ Все EU-каналы недоступны/заморожены. Балансировщик моста уже fail-closed (block).${NC}"
  echo -e "${YEL}Действие: проверь aegis-probe.py (разведка), держи XDRIVE-каналы (S3/Диск) как резерв.${NC}"
  if [ -n "$WEBHOOK" ]; then
    curl -s --max-time 10 -X POST -H 'Content-Type: application/json' \
      -d "$(jq -n --arg t "AEGIS pulse: все EU-каналы недоступны/заморожены на $HOST" '{text:$t}')" \
      "$WEBHOOK" >/dev/null 2>&1
  fi
else
  info "Живых EU-каналов: $healthy из $i"
fi
