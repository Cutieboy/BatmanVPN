# MouseVPN: установка сервера и терминального Linux-клиента

Этот мануал описывает ручное развёртывание текущего MouseVPN MVP:

- сервер — Debian/Ubuntu-подобный VPS с публичным IPv4;
- клиент — Linux с `systemd-resolved` (команды установки приведены для CachyOS);
- транспорт — UDP, по умолчанию порт `51820`;
- туннель — только IPv4, сеть `10.77.0.0/24`;
- один уникальный ключ и один уникальный адрес на каждое устройство.

MouseVPN остаётся экспериментальным проектом без независимого аудита. Он не
гарантирует анонимность, неуязвимость или доступность всех ресурсов с любого
VPS. Перед выдачей друзьям сохраните резервные копии конфигов и протестируйте
маршруты провайдера до нужных сервисов.

## 1. Что понадобится

На сервере:

- VPS с публичным IPv4;
- root или пользователь с `sudo`;
- открытый входящий UDP-порт `51820` в firewall VPS и панели хостинга;
- `/dev/net/tun`;
- `nftables`, `iproute2` и `systemd`.

На клиенте:

- Linux и root-доступ через `sudo`;
- `systemd-resolved` и команда `resolvectl`;
- выключенный AmneziaVPN, WireGuard или другой full-tunnel VPN;
- клиентский TOML-конфиг с правами `0600`.

В примерах ниже заменяйте:

- `203.0.113.10` — на публичный IPv4 своего VPS;
- `eth0` — на реальное имя внешнего интерфейса сервера;
- пути к проекту — на свои.

Адрес `203.0.113.10` является документационным и в интернете не работает.

## 2. Получение исходников

Репозиторий приватный, поэтому на каждой машине должен быть настроен GitHub SSH
ключ с доступом к нему:

```sh
git clone git@github.com:Zumka1991/MouseVPN.git
cd MouseVPN
```

Можно вместо этого собрать бинарники на доверенной машине и передать их по
`scp`. Сервер и машина сборки должны быть совместимы по архитектуре и glibc;
для первого развёртывания надёжнее собирать сервер непосредственно на VPS.

## 3. Установка Rust

Проект фиксирует Rust `1.97.1` в `rust-toolchain.toml`.

### Debian/Ubuntu на сервере

```sh
sudo apt update
sudo apt install -y build-essential ca-certificates curl git nftables iproute2
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
. "$HOME/.cargo/env"
rustup toolchain install 1.97.1 --profile minimal
```

### CachyOS на клиенте

```sh
sudo pacman -S --needed base-devel git rustup nftables iproute2
rustup toolchain install 1.97.1 --profile minimal
rustup default 1.97.1
```

Проверка:

```sh
rustc --version
cargo --version
```

## 4. Сборка

В каталоге проекта:

```sh
cargo build --release \
  -p mousevpn-server \
  -p mousevpn-linux-client \
  -p mousevpn-device-cli \
  -p mousevpn-profile-cli
```

Полная проверка перед развёртыванием:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Основные артефакты появятся в `target/release/`:

- `mousevpn-server`;
- `mousevpn-linux-client`;
- `mousevpn-device`;
- `mousevpn-profile`.

## 5. Создание первой пары конфигов

Запускайте генерацию в доверенной среде. Команда создаёт новый ключ сервера и
ключ первого устройства. Существующие файлы она не перезаписывает.

```sh
umask 077
mkdir -p "$HOME/mousevpn-provisioning"

./target/release/mousevpn-server generate-example \
  --server-config "$HOME/mousevpn-provisioning/server.toml" \
  --client-config "$HOME/mousevpn-provisioning/owner.toml" \
  --server-endpoint 203.0.113.10:51820
```

Получатся:

- `server.toml` — серверный приватный ключ и список разрешённых устройств;
- `owner.toml` — приватный ключ первого клиента.

Никогда не отправляйте `server.toml` друзьям и не публикуйте оба файла в Git.
Для каждого нового устройства создавайте отдельный клиентский конфиг.

Если конфиги создавались на VPS, сразу скопируйте `owner.toml` на клиент через
`scp`, проверьте копию и удалите клиентский файл с сервера.

## 6. Настройка сети VPS

Узнайте имя внешнего интерфейса:

```sh
ip route show default
```

Пример результата:

```text
default via 203.0.113.1 dev eth0
```

Если интерфейс называется не `eth0`, замените его в двух файлах до установки:

- `deploy/server/mousevpn.nft` — `mousevpn_wan`;
- `deploy/server/mousevpn-network` — `WAN_INTERFACE`.

Не очищайте общий nftables ruleset. MouseVPN использует отдельную таблицу
`inet mousevpn` и не должен удалять правила Docker, Amnezia или firewall VPS.

## 7. Установка серверных файлов

Создайте отдельного системного пользователя:

```sh
sudo useradd --system \
  --home-dir /var/lib/mousevpn \
  --create-home \
  --shell /usr/sbin/nologin \
  mousevpn
```

Если пользователь уже существует, сообщение об этом можно проигнорировать.

Установите каталоги, бинарник, конфиг и сетевые файлы:

```sh
sudo install -d -m 0750 -o root -g mousevpn /etc/mousevpn
sudo install -d -m 0755 /usr/local/libexec

sudo install -m 0755 \
  target/release/mousevpn-server \
  /usr/local/bin/mousevpn-server

sudo install -m 0640 -o root -g mousevpn \
  "$HOME/mousevpn-provisioning/server.toml" \
  /etc/mousevpn/server.toml

sudo install -m 0644 \
  deploy/server/mousevpn.nft \
  /etc/mousevpn/mousevpn.nft

sudo install -m 0755 \
  deploy/server/mousevpn-network \
  /usr/local/libexec/mousevpn-network

sudo install -m 0644 \
  deploy/server/mousevpn-network.service \
  /etc/systemd/system/mousevpn-network.service

sudo install -m 0644 \
  deploy/server/mousevpn-server.service.in \
  /etc/systemd/system/mousevpn-server.service

sudo install -m 0644 \
  deploy/server/98-mousevpn-udp-buffers.conf \
  /etc/sysctl.d/98-mousevpn-udp-buffers.conf

sudo install -m 0644 \
  deploy/server/99-mousevpn-forwarding.conf \
  /etc/sysctl.d/99-mousevpn-forwarding.conf
```

Примените sysctl:

```sh
sudo sysctl --system
```

Проверьте важные значения:

```sh
sysctl net.ipv4.ip_forward
sysctl net.core.rmem_max
sysctl net.core.wmem_max
```

Ожидается `ip_forward = 1`, а UDP max buffers — не меньше `8388608`.

## 8. Firewall и запуск сервера

Откройте UDP `51820` в firewall панели хостинга. Если используется UFW:

```sh
sudo ufw allow 51820/udp
sudo ufw route allow in on mousevpn0 out on eth0 from 10.77.0.0/24
```

Замените `eth0` на внешний интерфейс VPS. Если используется другой firewall с
политикой `forward drop`, добавьте эквивалентное разрешение для исходящего
`10.77.0.0/24` и обратного `established,related` трафика.

Файл `mousevpn.nft` настраивает только NAT и сам входящий порт не открывает.

Запустите службы:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now mousevpn-network.service
sudo systemctl enable --now mousevpn-server.service
```

Проверка:

```sh
systemctl status mousevpn-network.service --no-pager
systemctl status mousevpn-server.service --no-pager
sudo journalctl -u mousevpn-server.service -n 100 --no-pager
sudo ss -lunp | grep 51820
ip -brief address show mousevpn0
sudo nft list table inet mousevpn
```

Сервер должен слушать `0.0.0.0:51820`, а `mousevpn0` получить адрес
`10.77.0.1/24`.

## 9. Подготовка терминального клиента на CachyOS

Соберите клиент по разделам 2–4 или скопируйте совместимый release-бинарник.

Установите конфиг:

```sh
mkdir -p "$HOME/.config/mousevpn"
install -m 0600 \
  "$HOME/mousevpn-provisioning/owner.toml" \
  "$HOME/.config/mousevpn/client.toml"
```

Убедитесь, что `systemd-resolved` и `resolvectl` доступны:

```sh
command -v resolvectl
systemctl is-active systemd-resolved
```

Если `systemd-resolved` не используется, сначала настройте DNS backend своей
системы. Текущий клиент умеет безопасно переключать DNS только через
`resolvectl`.

Полностью отключите другой VPN. Особо проверьте split-default маршруты:

```sh
ip -4 route show
```

Не должно быть маршрутов `0.0.0.0/1` и `128.0.0.0/1` через `amn0` или другой
VPN-интерфейс.

## 10. Запуск терминального клиента

Из корня проекта:

```sh
sudo ./target/release/mousevpn-linux-client \
  --config "$HOME/.config/mousevpn/client.toml"
```

Процесс остаётся в текущем терминале. Нормальное сообщение:

```text
MouseVPN connected; press Ctrl+C to disconnect safely
```

Остановить VPN нужно сочетанием `Ctrl+C`. При нормальной остановке клиент сам
удаляет маршруты, DNS-настройки и свою nftables-таблицу.

В отдельном терминале проверьте:

```sh
curl -4 --max-time 15 https://api.ipify.org
resolvectl status mousevpn0
ip -4 route show
ip -s link show mousevpn0
```

`api.ipify.org` должен показать публичный IPv4 VPS. В `resolvectl` ожидаются DNS
из серверного конфига и домен `~.`.

## 11. Диагностический запуск клиента

Готовый скрипт запускает VPN на 40 секунд, проверяет IP/DNS и сохраняет лог без
приватных ключей:

```sh
MOUSEVPN_CLIENT_CONFIG="$HOME/.config/mousevpn/client.toml" \
  ./scripts/diagnose-linux-client.sh
```

Результат:

```text
/tmp/mousevpn-diagnostic.log
```

Не публикуйте лог целиком, не просмотрев IP-адреса и другую сетевую метаинформацию.

## 12. Добавление отдельного устройства или друга

Адрес каждого устройства должен быть уникальным внутри `10.77.0.0/24`.
Например, первый клиент использует `10.77.0.2`, следующий может использовать
`10.77.0.3`.

На доверенной машине:

```sh
umask 077

./target/release/mousevpn-device \
  --base-config "$HOME/.config/mousevpn/client.toml" \
  --client-out "$HOME/mousevpn-provisioning/friend-phone.toml" \
  --server-entry-out "$HOME/mousevpn-provisioning/friend-phone.server.toml" \
  --name friend-phone \
  --address 10.77.0.3
```

Команда создаёт:

- `friend-phone.toml` — секретный клиентский конфиг;
- `friend-phone.server.toml` — публичный блок `[[clients]]` для сервера.

Перед редактированием сделайте резервную копию:

```sh
sudo install -m 0640 -o root -g mousevpn \
  /etc/mousevpn/server.toml \
  /etc/mousevpn/server.toml.backup
```

Добавьте содержимое `friend-phone.server.toml` в конец
`/etc/mousevpn/server.toml`, не меняя существующие ключи и записи. Затем
перезапустите службу и сразу проверьте журнал:

```sh
sudo systemctl restart mousevpn-server.service
sudo journalctl -u mousevpn-server.service -n 50 --no-pager
```

Перезапуск кратко отключит активных клиентов; клиенты с watchdog должны
переподключиться. Передавайте секретный клиентский конфиг только по защищённому
каналу и удаляйте лишние копии.

Никогда не выдавайте двум устройствам один `client_private_key` или один
`10.77.0.x` — новая сессия вытеснит старую.

## 13. Профиль для Android

Из отдельного клиентского TOML создайте зашифрованную строку `MV1.…`:

```sh
./target/release/mousevpn-profile \
  --config "$HOME/mousevpn-provisioning/friend-phone.toml" \
  --name "MouseVPN — основной сервер"
```

Введите пароль длиной не менее 8 символов. Вставьте полученную строку в Android
клиент и передайте пароль другим защищённым каналом.

Строка содержит приватный ключ устройства в зашифрованном виде. Не публикуйте её
в чате или репозитории даже при наличии пароля.

## 14. Отзыв устройства

В текущем файловом сервере отзыв выполняется удалением соответствующего блока
`[[clients]]` из `/etc/mousevpn/server.toml` и перезапуском службы:

```sh
sudo systemctl restart mousevpn-server.service
```

Экспериментальный admin API из `docs/ADMIN_API.md` использует отдельное
in-memory состояние. Сейчас он не редактирует `/etc/mousevpn/server.toml` и не
является постоянным источником авторизации для основного daemon.

## 15. Обновление сервера

Сначала соберите и проверьте новый бинарник:

```sh
git pull --ff-only
cargo test --workspace
cargo build --release -p mousevpn-server
sha256sum target/release/mousevpn-server
```

Сделайте резервную копию и замените бинарник:

```sh
sudo install -m 0755 \
  /usr/local/bin/mousevpn-server \
  /usr/local/bin/mousevpn-server.backup

sudo install -m 0755 \
  target/release/mousevpn-server \
  /usr/local/bin/mousevpn-server

sudo systemctl restart mousevpn-server.service
sudo systemctl status mousevpn-server.service --no-pager
```

Если новая версия не запускается, верните резервную копию и снова перезапустите
службу.

## 16. Частые проблемы

### `another full-tunnel VPN appears to be active`

Отключите AmneziaVPN/WireGuard/OpenVPN и проверьте `ip -4 route show`.

### `Connection refused`

Проверьте службу, UDP listener и firewall:

```sh
sudo systemctl status mousevpn-server.service --no-pager
sudo journalctl -u mousevpn-server.service -n 100 --no-pager
sudo ss -lunp | grep 51820
```

UDP не имеет постоянного «соединения», поэтому проверка TCP-порта здесь не
подходит.

### IP работает, DNS не работает

На клиенте:

```sh
resolvectl status mousevpn0
ping -c 2 1.1.1.1
curl -4 --max-time 10 https://api.ipify.org
```

Если IP доступен, но имена не разрешаются, проверьте `systemd-resolved` и
системный `/etc/resolv.conf`.

### После аварийного `SIGKILL` остался kill switch

Удаляйте только таблицу MouseVPN, не очищайте весь nftables ruleset:

```sh
sudo nft delete table inet mousevpn_client_runtime
```

После этого проверьте маршруты и DNS:

```sh
ip -4 route show
resolvectl status
```

### Telegram: текст работает, отдельные медиа не грузятся

Проверьте доступность конкретного Telegram DC непосредственно с VPS. Разные
файлы могут находиться в разных data center, а некоторые VPS-провайдеры или
выходные IP имеют проблемные маршруты:

```sh
nc -vz -w 5 TELEGRAM_DC_IP 443
nc -vz -w 5 TELEGRAM_DC_IP 5222
```

Если тот же адрес доступен из другой сети, но недоступен с VPS, смените IP или
провайдера VPS. Это не исправляется переподключением клиента.

### Серверные метрики

```sh
systemctl show mousevpn-server.service -p MainPID -p NRestarts
sudo ss -u -a -n -m | grep -A1 51820
nstat -az | grep -E 'Udp(InErrors|RcvbufErrors|SndbufErrors)'
ip -s link show mousevpn0
```

У серверного UDP-сокета желательно видеть пустые очереди и `d0` в `skmem`.

## 17. Ограничения текущей версии

- поддерживается только IPv4 внутри туннеля;
- IPv6 не проходит через MouseVPN;
- нет автоматического постоянного хранилища пользователей через admin API;
- изменение `/etc/mousevpn/server.toml` требует рестарта daemon;
- нет автоматической смены endpoint при плохом маршруте VPS;
- протокол и реализация не проходили независимый security audit.

Для повседневного тестирования храните запасной VPS-профиль и выдавайте каждому
устройству отдельные credentials.
