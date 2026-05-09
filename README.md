# BadVPN routing

Публичные правила и шаблон подписки для Mihomo/Clash.Meta.

## Структура

- `mihomo/badvpn-template.yaml` - основной шаблон подписки.
- `rulesets/` - собственные rule-provider файлы BadVPN.
- `routing-sources.yaml` - список локальных и внешних источников.
- `scripts/sync_sources.py` - проверка доступности и валидности источников.

## Как использовать

Подключи `mihomo/badvpn-template.yaml` как subscription template в панели.

Собственные правила подключаются из этого репозитория:

```text
https://raw.githubusercontent.com/Rerowros/badvpn-routing/refs/heads/main/rulesets
```

Mihomo будет обновлять `type: http` providers автоматически по `interval`.

Если нужно отдавать правила со своего домена, передай в шаблон:

```yaml
badvpn_ruleset_base_url: "https://badvpn.pro/rulesets"
```

## Проверка

```powershell
uv run scripts/sync_sources.py --check
```
