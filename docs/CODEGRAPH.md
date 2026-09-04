# CodeGraph для MouseVPN

Используется [colbymchenry/codegraph](https://github.com/colbymchenry/codegraph),
версия 1.6.0. Утилита установлена в `~/.local/bin/codegraph`, индекс проекта
находится в `.codegraph/` и исключён из Git.

Из корня проекта:

```sh
codegraph status
codegraph explore "crates/linux-platform/src/firewall.rs"
codegraph explore "RouteGuard refresh_server_route"
codegraph sync
```

`sync` обновляет индекс после изменений. Пока MCP-сервер запущен, он следит
за изменениями автоматически. Для полного пересоздания индекса используйте
`codegraph index`.

Подключение к Codex настроено только для этого проекта в `.codex/config.toml`.
В конфигурации указаны абсолютные пути этой машины; при переносе проекта их
нужно обновить. После изменения MCP-конфигурации перезапустите Codex.
В `AGENTS.md` записана инструкция использовать CodeGraph для исследования кода.
Телеметрия отключена.

Для повторной установки:

```sh
npm install --global --prefix "$HOME/.local" @colbymchenry/codegraph@1.6.0
codegraph install --target=codex --location=local --yes --no-permissions
codegraph telemetry off
codegraph init --yes
```

Каталог `~/.local/bin` должен быть в `PATH`. Повторный `install` может заменить
абсолютные пути в `.codex/config.toml` на стандартную команду `codegraph`.
