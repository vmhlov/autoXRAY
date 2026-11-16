#!/bin/bash
# ============================================================================
# aegis-upgrade.sh — апгрейд установленного autoXRAY2.sh до схемы AEGIS
# Репозиторий: https://github.com/vmhlov/autoXRAY
#
# Что делает (только поверх уже установленного autoXRAY2, ничего не ломает):
#   1. Сервер: routing.domainStrategy IPIfNonMatch -> IPOnDemand; убирает
#      отдельную блокировку IP-чекеров (по методичке от 07.11.2026 это вредно).
#   2. Подписка: fingerprint всех профилей -> chrome (ядро v26.11.9, Chrome 155,
#      по релиз-ноутам TSPU его пока не таргетит); bittorrent direct -> block;
#      IP-чекеры убираются из direct-правил клиента.
#   3. Флагман: профиль "AEGIS AUTO" — burstObservatory (случайные моменты проверок)
#      + balancer leastPing по XHTTP/VISION/HY2, fallbackTag -> XDRIVE (если задан)
#      или blackhole. Весь трафик в туннель, RU-сплит остаётся в legacy-профилях.
#   4. Опционально до 2 аварийных каналов XDRIVE S3 (--s3 ... --s3 ...):
#      клиент ходит ТОЛЬКО в бакет облака, IP сервера не светится вообще.
#      Каждый канал проходит живую самопроверку через бакет перед выдачей.
#   5. Egress-guard: systemd-таймер следит за WARP; если WARP умер — первый
#      outbound становится blackhole (НЕ direct, вход не раскрывается),
#      при восстановлении WARP возвращается автоматически.
#   6. Локальные SOCKS/HTTP клиента защищаются паролем (методичка, раздел 5).
#
# Использование:
#   bash aegis-upgrade.sh
#   bash aegis-upgrade.sh --pq \
#     --s3 "https://storage.yandexcloud.net|BUCKET|KEY_ID|SECRET|ru-central1" \
#     --s3 "https://hb.ru-msk.vkcloud-solutions.com|BUCKET2|KEY2|SECRET2|ru-msk"
#
# Откат:
#   cp /usr/local/etc/xray/config.json.bak-aegis /usr/local/etc/xray/config.json
#   cp <подписка>.json.bak-aegis <подписка>.json
#   systemctl restart xray
#   systemctl disable --now aegis-egress-guard.timer
# ============================================================================
set -u

GRN='\033[1;32m'; RED='\033[1;31m'; YEL='\033[1;33m'; NC='\033[0m'
info(){ echo -e "${GRN}$*${NC}"; }
warn(){ echo -e "${YEL}$*${NC}"; }
die(){ echo -e "${RED}$*${NC}"; exit 1; }

[[ $EUID -eq 0 ]] || die "❌ Нужны root права"
for b in jq curl openssl xray systemctl; do
    command -v "$b" >/dev/null 2>&1 || die "❌ Нет команды: $b"
done
jq -n '{} | walk(.)' >/dev/null 2>&1 || die "❌ Нужен jq >= 1.6 (функция walk)"

CFG=/usr/local/etc/xray/config.json
[ -s "$CFG" ] || die "❌ Не найден $CFG — сначала установите autoXRAY2.sh"

# ---------- аргументы ----------
S3_SPECS=(); PQ=false
while [ $# -gt 0 ]; do
    case "$1" in
        --s3) [ $# -ge 2 ] || die "❌ --s3 требует аргумент"; S3_SPECS+=("$2"); shift 2 ;;
        --pq) PQ=true; shift ;;
        -h|--help) grep '^#' "$0" | head -40; exit 0 ;;
        *) die "❌ Неизвестный аргумент: $1 (см. --help)" ;;
    esac
done
[ "${#S3_SPECS[@]}" -le 2 ] || die "❌ Максимум 2 канала --s3"

# ---------- поиск подписки ----------
SUB=""
for f in /var/www/*/*.json; do
    [ -s "$f" ] || continue
    if jq -e 'type=="array" and length>0 and (.[0].outbounds|type=="array")' "$f" >/dev/null 2>&1; then
        SUB="$f"; break
    fi
done
[ -n "$SUB" ] || die "❌ Подписка autoXRAY не найдена в /var/www/*/*.json"
DOMAIN=$(basename "$(dirname "$SUB")")
HTML="${SUB%.json}.html"
info "Подписка: $SUB (домен $DOMAIN)"

# ---------- бэкапы ----------
cp "$CFG" "$CFG.bak-aegis" || die "❌ Не удалось сделать бэкап конфига"
cp "$SUB" "$SUB.bak-aegis" || die "❌ Не удалось сделать бэкап подписки"
[ -s "$HTML" ] && cp "$HTML" "$HTML.bak-aegis"

XRAY_GROUP=$(id -gn xray 2>/dev/null || echo root)
own_cfg(){ chown root:"$XRAY_GROUP" "$1" 2>/dev/null; chmod 640 "$1"; }

apply_cfg(){ # $1 — файл-кандидат; проверка xray -test перед заменой
    jq empty "$1" >/dev/null 2>&1 || return 1
    xray run -test -config "$1" >/dev/null 2>&1 || return 1
    own_cfg "$1"; mv "$1" "$CFG"; return 0
}

# ---------- 1. серверный routing ----------
warn "[1/6] Правка серверного routing (IPOnDemand, снятие блока IP-чекеров)..."
jq '
  .routing.domainStrategy = "IPOnDemand"
  | .routing.rules |= map(select(((.domain // []) | index("domain:ifconfig.me")) == null))
' "$CFG" > "$CFG.aegis" || die "❌ jq не разобрал $CFG"
if apply_cfg "$CFG.aegis"; then
    systemctl restart xray
    info "✅ routing обновлён"
else
    rm -f "$CFG.aegis"; die "❌ Xray отклонил новый routing, конфиг не изменён"
fi

# ---------- 2. каналы XDRIVE S3 ----------
XD_OBJS="[]"          # клиентские outbound для подписки
XD_LANES_OK=0
xray_ver=$(xray version 2>/dev/null | awk 'NR==1 {print $2}')
ver_ok(){ [ -n "$xray_ver" ] && [ "$(printf '%s\n' "26.11.9" "$xray_ver" | sort -V | head -n1)" = "26.11.9" ]; }

if [ "${#S3_SPECS[@]}" -gt 0 ]; then
    ver_ok || die "❌ Для XDRIVE нужен Xray >= 26.11.9 (сейчас: ${xray_ver:-нет})"
    warn "[2/6] Настройка каналов XDRIVE S3 (${#S3_SPECS[@]} шт.)..."
    # убрать старые aegis-каналы (идемпотентность)
    jq '.inbounds |= map(select((.tag // "") | startswith("vsXDRIVEaegis") | not))' \
        "$CFG" > "$CFG.aegis" && apply_cfg "$CFG.aegis" || { rm -f "$CFG.aegis"; die "❌ Не удалось очистить старые каналы"; }

    ENC_OUT=$(xray vlessenc 2>/dev/null)
    [ -n "$ENC_OUT" ] || die "❌ xray vlessenc не вернул ключей"
    get_pair(){ # $1 — фильтр (пусто = первая пара)
        local d e
        if [ -n "$1" ]; then
            d=$(printf '%s\n' "$ENC_OUT" | grep '"decryption"' | grep -m1 "$1" | sed 's/.*: "\(.*\)"/\1/')
            e=$(printf '%s\n' "$ENC_OUT" | grep '"encryption"' | grep -m1 "$1" | sed 's/.*: "\(.*\)"/\1/')
        else
            d=$(printf '%s\n' "$ENC_OUT" | grep -m1 '"decryption"' | sed 's/.*: "\(.*\)"/\1/')
            e=$(printf '%s\n' "$ENC_OUT" | grep -m1 '"encryption"' | sed 's/.*: "\(.*\)"/\1/')
        fi
        [ -n "$d" ] && [ -n "$e" ] || return 1
        printf '%s\n%s\n' "$d" "$e"
    }
    if $PQ; then
        PAIR=$(get_pair "mlkem768x25519plus") || { warn "⚠️ mlkem-пара не найдена, беру первую пару"; PAIR=$(get_pair "") || die "❌ vlessenc: нет пары"; }
    else
        PAIR=$(get_pair "") || die "❌ vlessenc: нет пары"
    fi
    DEC=$(printf '%s\n' "$PAIR" | sed -n 1p)
    ENC=$(printf '%s\n' "$PAIR" | sed -n 2p)

    n=0
    for spec in "${S3_SPECS[@]}"; do
        n=$((n+1))
        IFS='|' read -r EP BKT KEY SEC REG <<< "$spec"
        REG=${REG:-ru-central1}; EP=${EP%/}
        if [ -z "$EP" ] || [ -z "$BKT" ] || [ -z "$KEY" ] || [ -z "$SEC" ]; then
            warn "⚠️ Канал $n: неверный формат --s3, пропуск"; continue
        fi
        code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 \
            --aws-sigv4 "aws:amz:$REG:s3" --user "$KEY:$SEC" \
            "$EP/$BKT?list-type=2&max-keys=1")
        if [ "$code" != "200" ]; then
            warn "⚠️ Канал $n: S3 ответил HTTP $code — пропуск (проверьте endpoint/регион/ключи)"; continue
        fi
        UUID=$(xray uuid); FOLDER="xa$(openssl rand -hex 3)"; PORT=$((10990+n)); TAG="vsXDRIVEaegis$n"
        XD=$(jq -n --arg e "$EP" --arg r "$REG" --arg b "$BKT" --arg k "$KEY" --arg s "$SEC" --arg f "$FOLDER" '{
            service:"s3", remoteFolder:$f, secrets:[$k,$s],
            s3:{endpoint:$e, region:$r, bucket:$b, pathStyle:true},
            pollIntervalMs:200, maxPollIntervalMs:3000
        }')
        INB=$(jq -n --arg t "$TAG" --arg u "$UUID" --arg d "$DEC" --argjson p "$PORT" --argjson x "$XD" '{
            tag:$t, listen:"127.0.0.1", port:$p, protocol:"vless",
            settings:{clients:[{id:$u}], decryption:$d},
            streamSettings:{network:"xdrive", xdriveSettings:$x},
            sniffing:{enabled:true, destOverride:["http","tls","quic"]}
        }')
        jq --argjson in "$INB" --arg t "$TAG" '.inbounds = ([.inbounds[] | select(.tag != $t)] + [$in])' \
            "$CFG" > "$CFG.aegis" || { warn "⚠️ Канал $n: ошибка jq, пропуск"; continue; }
        if ! apply_cfg "$CFG.aegis"; then
            rm -f "$CFG.aegis"; warn "⚠️ Канал $n: xray -test не прошёл, пропуск"; continue
        fi
        OB=$(jq -n --arg t "proxy-xdrive$n" --arg u "$UUID" --arg e "$ENC" --argjson p "$PORT" --argjson x "$XD" '{
            tag:$t, protocol:"vless",
            settings:{vnext:[{address:"127.0.0.1", port:$p, users:[{id:$u, encryption:$e}]}]},
            streamSettings:{network:"xdrive", xdriveSettings:$x},
            mux:{enabled:true, concurrency:128}
        }')
        XD_OBJS=$(printf '%s' "$XD_OBJS" | jq --argjson o "$OB" '. + [$o]')
        XD_LANES_OK=$((XD_LANES_OK+1))
        info "✅ Канал $n ($BKT) добавлен в конфиг"
    done

    if [ "$XD_LANES_OK" -gt 0 ]; then
        systemctl restart xray; sleep 3
        # живая самопроверка каждого канала через бакет
        BASE=$(jq '.[0]' "$SUB")
        AU=$(openssl rand -hex 4); AP=$(openssl rand -hex 12)
        n=0; FAILED=""
        while IFS= read -r ob; do
            n=$((n+1))
            SP=$((18810+n)); HP=$((18820+n))
            TCLI=$(jq -n --argjson base "$BASE" --argjson o "$ob" --arg au "$AU" --arg ap "$AP" \
                --argjson sp "$SP" --argjson hp "$HP" '
                $base
                | .remarks = "aegis-selftest"
                | .outbounds = [($o + {tag:"proxy"}), {tag:"direct",protocol:"freedom"}, {tag:"block",protocol:"blackhole"}]
                | .routing = {domainStrategy:"AsIs", rules:[{ip:["geoip:private"],outboundTag:"direct"}]}
                | .inbounds = [
                    {tag:"s",protocol:"socks",listen:"127.0.0.1",port:$sp,
                     settings:{udp:true,auth:"password",accounts:[{user:$au,pass:$ap}]}},
                    {tag:"h",protocol:"http",listen:"127.0.0.1",port:$hp,
                     settings:{accounts:[{user:$au,pass:$ap}]}}
                  ]
                | del(.burstObservatory, .observatory)
            ')
            TD=$(mktemp -d)
            printf '%s' "$TCLI" > "$TD/c.json"
            xray run -config "$TD/c.json" > "$TD/c.log" 2>&1 &
            CPID=$!
            sleep 2
            RES=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 90 \
                -x "socks5h://${AU}:${AP}@127.0.0.1:${SP}" https://www.google.com/generate_204)
            kill "$CPID" 2>/dev/null; wait "$CPID" 2>/dev/null; rm -rf "$TD"
            if [ "${RES%% *}" = "204" ]; then
                info "✅ Самопроверка канала $n: туннель через бакет работает (${RES#* } с)"
                # standalone-конфиг для клиента (полный туннель, пароль на локальных прокси)
                umask 077
                printf '%s' "$TCLI" | jq --arg r "☁️ AEGIS XDRIVE $n" \
                    --argjson sp 10808 --argjson hp 10809 '
                    .remarks = $r
                    | .inbounds[0].port = $sp | .inbounds[1].port = $hp
                    | .routing = {domainMatcher:"hybrid", domainStrategy:"AsIs", rules:[
                        {domain:["geosite:category-ads"],outboundTag:"block"},
                        {protocol:["bittorrent"],outboundTag:"block"},
                        {ip:["geoip:private"],outboundTag:"direct"}
                      ]}
                ' > "/root/aegis-xdrive$n-client.json"
                info "   Клиентский конфиг: /root/aegis-xdrive$n-client.json (socks 10808 / http 10809, логин $AU пароль $AP)"
            else
                warn "❌ Самопроверка канала $n не прошла (ответ: ${RES:-нет}) — канал убирается"
                FAILED="$FAILED $n"
            fi
        done < <(printf '%s' "$XD_OBJS" | jq -c '.[]')
        umask 022
        for n in $FAILED; do
            XD_OBJS=$(printf '%s' "$XD_OBJS" | jq --arg t "proxy-xdrive$n" 'map(select(.tag != $t))')
            jq --arg t "vsXDRIVEaegis$n" '.inbounds |= map(select(.tag != $t))' "$CFG" > "$CFG.aegis" \
                && apply_cfg "$CFG.aegis" || rm -f "$CFG.aegis"
            XD_LANES_OK=$((XD_LANES_OK-1))
        done
        [ "$XD_LANES_OK" -gt 0 ] && systemctl restart xray
    fi
else
    warn "[2/6] Каналы XDRIVE пропущены (не заданы --s3)"
fi

# ---------- 3. подписка: чистка, fingerprint, hardening ----------
warn "[3/6] Обновление подписки..."
OLDFP=$(jq -r '.[0].outbounds[0].streamSettings.tlsSettings.fingerprint // "firefox"' "$SUB")
jq 'map(select(((.remarks // "") | (startswith("🛡️ AEGIS AUTO") or startswith("☁️ AEGIS XDRIVE RESERVE"))) | not))' \
    "$SUB" > "$SUB.aegis" || die "❌ jq: чистка подписки"
jq 'walk(if type == "object" and has("fingerprint") then .fingerprint = "chrome" else . end)' \
    "$SUB.aegis" > "$SUB.aegis2" && mv "$SUB.aegis2" "$SUB.aegis" || die "❌ jq: fingerprint"
jq '
  map(
    .routing.rules |= map(
      if (.outboundTag == "direct") and (((.domain // []) | length) > 0) then
        .domain |= map(select(. as $d |
          (["domain:ifconfig.me","domain:checkip.amazonaws.com","domain:ipify.org","domain:2ip.io","geosite:category-ip-geo-detect"]
           | index($d)) == null))
      else . end)
    | .routing.rules |= map(if ((.protocol // []) | index("bittorrent")) != null then .outboundTag = "block" else . end)
  )
' "$SUB.aegis" > "$SUB.aegis2" && mv "$SUB.aegis2" "$SUB.aegis" || die "❌ jq: hardening"

# ---------- 4. флагманский профиль AEGIS AUTO ----------
warn "[4/6] Сборка профиля AEGIS AUTO (burstObservatory + leastPing)..."
[ "$(jq 'length' "$SUB.aegis")" -ge 3 ] || die "❌ В подписке меньше 3 профилей — AUTO не собран, откат: cp $SUB.bak-aegis $SUB"
BASE=$(jq '.[0]' "$SUB.aegis")
AU=$(openssl rand -hex 4); AP=$(openssl rand -hex 12)
FAST=$(jq -n \
    --argjson a "$(jq '.[0].outbounds[0]' "$SUB.aegis")" \
    --argjson b "$(jq '.[1].outbounds[0]' "$SUB.aegis")" \
    --argjson c "$(jq '.[2].outbounds[0]' "$SUB.aegis")" \
    '[$a + {tag:"proxy-fast-xhttp"}, $b + {tag:"proxy-fast-vision"}, $c + {tag:"proxy-fast-hy2"}]')
if [ "$XD_LANES_OK" -gt 0 ]; then FB=$(printf '%s' "$XD_OBJS" | jq -r '.[0].tag // "block"'); else FB="block"; fi
AUTO=$(jq -n --argjson base "$BASE" --argjson fast "$FAST" --argjson xd "$XD_OBJS" \
    --arg fb "$FB" --arg au "$AU" --arg ap "$AP" '
    $base
    | .remarks = "🛡️ AEGIS AUTO (XHTTP/VISION/HY2 -> XDRIVE)"
    | .outbounds = ($fast + $xd + [{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}])
    | .inbounds |= map(
        if .protocol == "http" then
          .settings = ((.settings // {}) + {accounts:[{user:$au,pass:$ap}]})
        else
          .settings = ((.settings // {}) + {auth:"password",accounts:[{user:$au,pass:$ap}]})
        end)
    | .routing = {
        domainMatcher:"hybrid", domainStrategy:"AsIs",
        rules:[
          {domain:["geosite:category-ads"],outboundTag:"block"},
          {protocol:["bittorrent"],outboundTag:"block"},
          {ip:["geoip:private"],outboundTag:"direct"},
          {network:"tcp,udp",balancerTag:"auto"}
        ],
        balancers:[{tag:"auto",selector:["proxy-fast-"],strategy:{type:"leastPing"},fallbackTag:$fb}]
      }
    | .burstObservatory = {
        subjectSelector:["proxy-fast-"],
        pingConfig:{destination:"https://www.google.com/generate_204",interval:"1m",sampling:5,timeout:"5s",httpMethod:"HEAD"}
      }
')
if [ "$XD_LANES_OK" -gt 0 ]; then
    RESERVE=$(jq -n --argjson base "$BASE" --argjson xd "$XD_OBJS" --arg au "$AU" --arg ap "$AP" '
        $base
        | .remarks = "☁️ AEGIS XDRIVE RESERVE"
        | .outbounds = ($xd + [{tag:"direct",protocol:"freedom"},{tag:"block",protocol:"blackhole"}])
        | .inbounds |= map(
            if .protocol == "http" then
              .settings = ((.settings // {}) + {accounts:[{user:$au,pass:$ap}]})
            else
              .settings = ((.settings // {}) + {auth:"password",accounts:[{user:$au,pass:$ap}]})
            end)
        | .routing = {
            domainMatcher:"hybrid", domainStrategy:"AsIs",
            rules:[
              {domain:["geosite:category-ads"],outboundTag:"block"},
              {protocol:["bittorrent"],outboundTag:"block"},
              {ip:["geoip:private"],outboundTag:"direct"},
              {network:"tcp,udp",balancerTag:"reserve"}
            ],
            balancers:[{tag:"reserve",selector:["proxy-xdrive"],strategy:{type:"random"},fallbackTag:"block"}]
          }
        | del(.burstObservatory, .observatory)
    ')
    jq --argjson a "$AUTO" --argjson r "$RESERVE" '. + [$a, $r]' "$SUB.aegis" > "$SUB.aegis2" \
        || die "❌ jq: добавление AUTO/RESERVE"
else
    jq --argjson a "$AUTO" '. + [$a]' "$SUB.aegis" > "$SUB.aegis2" || die "❌ jq: добавление AUTO"
fi
jq empty "$SUB.aegis2" || die "❌ Итоговая подписка невалидна, откат: cp $SUB.bak-aegis $SUB"
mv "$SUB.aegis2" "$SUB"; rm -f "$SUB.aegis"; chmod 644 "$SUB"
if [ -s "$HTML" ] && [ "$OLDFP" != "chrome" ]; then
    sed -i "s/fp=$OLDFP/fp=chrome/g" "$HTML"
fi
info "✅ Подписка обновлена: legacy-профили + AEGIS AUTO$( [ "$XD_LANES_OK" -gt 0 ] && echo ' + XDRIVE RESERVE' )"
info "   Пароль локальных прокси AUTO/RESERVE: логин $AU пароль $AP"

# ---------- 5. egress-guard (WARP -> blackhole при аварии) ----------
warn "[5/6] Установка egress-guard (защита от раскрытия IP входа при падении WARP)..."
cat > /usr/local/bin/aegis-egress-guard.sh <<'GUARD'
#!/bin/bash
CFG=/usr/local/etc/xray/config.json
LOG=/var/log/xray/egress-guard.log
STATE=/var/lib/xray/aegis-guard.count
exec 9>/run/aegis-guard.lock
flock -n 9 || exit 0
[ -s "$CFG" ] || exit 0
first=$(jq -r '.outbounds[0].tag // empty' "$CFG")
case "$first" in warp|egress-lock) ;; *) exit 0 ;; esac
user=$(jq -r '.inbounds[] | select(.tag=="socks5") | .settings.accounts[0].user // empty' "$CFG")
pass=$(jq -r '.inbounds[] | select(.tag=="socks5") | .settings.accounts[0].pass // empty' "$CFG")
[ -n "$user" ] && [ -n "$pass" ] || exit 0
grp=$(id -gn xray 2>/dev/null || echo root)
log(){ echo "$(date -u +%FT%TZ) $1" >> "$LOG"; }
check(){ curl -s --max-time 15 -x "socks5h://${user}:${pass}@127.0.0.1:10443" \
    https://www.cloudflare.com/cdn-cgi/trace | grep -q '^warp=on'; }
apply(){
    jq "$1" "$CFG" > "$CFG.guard" || { rm -f "$CFG.guard"; return 1; }
    jq empty "$CFG.guard" || { rm -f "$CFG.guard"; return 1; }
    xray run -test -config "$CFG.guard" >/dev/null 2>&1 || { rm -f "$CFG.guard"; return 1; }
    chown root:"$grp" "$CFG.guard" 2>/dev/null; chmod 640 "$CFG.guard"
    mv "$CFG.guard" "$CFG"; systemctl restart xray; sleep 3
}
if [ "$first" = "warp" ]; then
    check && exit 0
    apply '.outbounds = [{tag:"egress-lock",protocol:"blackhole"}] + .outbounds' \
        && log "WARP down -> egress LOCKED (blackhole, IP входа не раскрыт)"
    exit 0
fi
n=$(cat "$STATE" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$STATE"
[ $((n % 5)) -eq 0 ] || exit 0
apply '.outbounds |= map(select(.tag != "egress-lock"))' || exit 0
if check; then
    log "WARP recovered -> egress UNLOCKED"; echo 0 > "$STATE"
else
    apply '.outbounds = [{tag:"egress-lock",protocol:"blackhole"}] + .outbounds'
    log "WARP still down -> re-LOCKED"
fi
GUARD
chmod 750 /usr/local/bin/aegis-egress-guard.sh
cat > /etc/systemd/system/aegis-egress-guard.service <<'UNIT'
[Unit]
Description=AEGIS egress guard: WARP health -> fail-closed blackhole
After=network-online.target xray.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/aegis-egress-guard.sh
UNIT
cat > /etc/systemd/system/aegis-egress-guard.timer <<'UNIT'
[Unit]
Description=Run AEGIS egress guard every 60s

[Timer]
OnBootSec=90
OnUnitActiveSec=60
AccuracySec=15

[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now aegis-egress-guard.timer >/dev/null 2>&1
info "✅ egress-guard активен (лог: /var/log/xray/egress-guard.log)"

# ---------- 6. итог ----------
warn "[6/6] Финальная проверка..."
systemctl is-active --quiet xray && info "Xray: RUNNING" || warn "Xray: STOPPED — смотрите journalctl -u xray -n 50"
systemctl is-active --quiet nginx && info "Nginx: RUNNING" || warn "Nginx: STOPPED"
TRACE=$(curl -s --max-time 15 -x "socks5h://$(jq -r '.inbounds[] | select(.tag=="socks5") | .settings.accounts[0].user' "$CFG"):$(jq -r '.inbounds[] | select(.tag=="socks5") | .settings.accounts[0].pass' "$CFG")@127.0.0.1:10443" https://www.cloudflare.com/cdn-cgi/trace)
if printf '%s' "$TRACE" | grep -q '^warp=on'; then
    info "Выход в интернет: WARP (IP входа скрыт)"
else
    warn "Выход: НЕ WARP — IP входа не скрыт. Guard защищает только конфигурации с WARP"
fi
echo
info "Готово. Подписка: https://$DOMAIN/$(basename "$SUB")"
info "В клиенте выберите профиль «🛡️ AEGIS AUTO». Пароль локальных прокси: $AU / $AP"
[ "$XD_LANES_OK" -gt 0 ] && info "Аварийные XDRIVE-каналы: $XD_LANES_OK. standalone-конфиги: /root/aegis-xdrive*-client.json"
echo
warn "Откат: cp $CFG.bak-aegis $CFG && cp $SUB.bak-aegis $SUB && systemctl restart xray && systemctl disable --now aegis-egress-guard.timer"
