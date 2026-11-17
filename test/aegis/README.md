# AEGIS / HYDRA — адаптивная система обхода для autoXRAY

Набор надстроек поверх autoXRAY2.sh / bridgeTLSxhttp.sh. Ничего не перегенерирует,
все изменения проходят `xray run -test` и живые самопроверки до применения, с бэкапами и откатом.

## Файлы и порядок запуска
1. `aegis-upgrade.sh` — EU-сервер: IPOnDemand, chrome fp, fail-closed WARP (egress-guard),
   профиль AEGIS AUTO (burstObservatory + leastPing), опционально XDRIVE S3 (Yandex/VK), --pq.
2. `aegis-xdrive-gdrive.sh` — EU: аварийный XDRIVE через Google Drive (3 секрета: ClientID/Secret/RefreshToken).
3. `aegis-xdrive-ydisk.sh` — EU: аварийный XDRIVE через Яндекс.Диск (template-бэкенд, двухшаговый href; бесплатно, RU-домен).
4. `aegis-bridge-upgrade.sh` — RU-мост: IPOnDemand, fallbackTag->block, DNS localhost, chrome, AEGIS BRIDGE AUTO.
5. `aegis-ru-entry.sh` — EU: встраивает RU-мост в AEGIS AUTO (RU-трафик всегда с RU-IP), профиль RU ENTRY.
6. `aegis-probe.py` — RU: разведка канала (какие протоколы проходят, асимметрия, штрафная скамейка).
7. `aegis-pulse.sh` — RU-мост: монитор заморозки/блокировки (provocate >20KB), JSON-лог, алерт, таймер 120с.
8. `aegis-imap-lane.sh` — EU: аварийный IMAP-relay через mail.ru (true-imap-tunnel v0.5.0), профиль для десктопа. Провайдер: Mail.ru лучший; Yandex-почта медленная/отваливается.

## Статус проверки
- Машинно проверено (bash -n / py_compile / JSON / логика): upgrade, bridge, ru-entry, gdrive, ydisk, probe, pulse.
- Каждый скрипт сам делает `xray run -test` и живые самопроверки перед применением; при провале — откат.

## Честные ограничения
- Ни один метод не обходит всё. Белые списки per-operator/per-cell; надёжный тест — SIM в день режима.
- XDRIVE (S3/Drive/Диск): задержка ~0.8с+, аварийные каналы; Диск — list без пагинации (лимит 1000).
- ИИ-фильтр РКН (13.11.2026, 2.27 млрд ₽): возможности публично не подтверждены; против статистики потока
  помогает смена поведенческого профиля (диапазоны паддингов/интервалов) и relay через разрешённый сервис.
- finalmask fragment: issue #6453 — паника REALITY-сервера, ломает xhttp+reality и plain tcp → не использовать до фикса.
- Ротация XHTTP-path НЕ влияет на TLS-заморозку (path внутри TLS, цензору не виден).

## Откат
Каждый скрипт печатает команду отката; бэкапы: config.json.bak-*, <подписка>.json.bak-*.
