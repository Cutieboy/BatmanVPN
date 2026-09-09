# Arch Linux

Пакет `mousevpn` устанавливает графический клиент, иконку и пункт MouseVPN
в меню приложений. Подключение запрашивает права через PolicyKit;
сам интерфейс работает от обычного пользователя.

Из корня репозитория:

```sh
sudo pacman -S --needed base-devel rust webkit2gtk-4.1
./packaging/arch/build-arch.sh
sudo pacman -U packaging/arch/build/mousevpn-*.pkg.tar.zst
```

Скрипт собирает архив из текущего содержимого отслеживаемых исходников,
фиксирует контрольные суммы и запускает `makepkg`. Новые исходные файлы
перед сборкой нужно добавить в Git. Версия берётся из Cargo.toml GUI.
Для повторной сборки той же версии передайте `--force`.

Для работы VPN нужны `systemd-resolved` и агент PolicyKit рабочего стола.
Проверка DNS-службы: `systemctl is-active systemd-resolved`.
Пакет не меняет настройки сети и не подключает VPN автоматически.

Запуск: MouseVPN в меню приложений или `mousevpn-linux-gui` в терминале.
Удаление: `sudo pacman -R mousevpn`.
