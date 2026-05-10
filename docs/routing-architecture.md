# Routing Architecture

## Layout

The main subscription template stays in `mihomo/badvpn-template.yaml`.

Custom BadVPN rules are split into standalone Mihomo classical providers:

- `rulesets/proxy/youtube-discord.yaml`
- `rulesets/proxy/ai.yaml`
- `rulesets/proxy/gemini.yaml`
- `rulesets/proxy/telegram-extra.yaml`
- `rulesets/proxy/github-extra.yaml`
- `rulesets/games/games-core.yaml`
- `rulesets/direct/ru-core.yaml`
- `rulesets/direct/torrents.yaml`

Third-party providers remain referenced directly from their upstream URLs.

## Runtime update model

Mihomo clients automatically update `type: http` rule-providers by each provider's `interval`.

For custom BadVPN providers this only works after publishing `rulesets/` to an HTTPS endpoint. The template currently defaults to:

```text
https://raw.githubusercontent.com/Rerowros/badvpn-routing/refs/heads/main/rulesets
```

If GitHub is used instead, set the base URL to a raw URL, for example:

```text
https://raw.githubusercontent.com/<owner>/<repo>/refs/heads/main/rulesets
```

For the existing Next.js website, export static files before deployment:

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/export-rulesets.ps1
```

The default target is the main website's `public/rulesets` directory, which is served by Next.js as `/rulesets/...`.

## Automation

`scripts/sync_sources.py` validates both:

- remote upstream providers from Nemu-x, hydraponique, roscomvpn, legiz-ru;
- local BadVPN providers from `rulesets/`.

The script writes `dist/upstream-sources.lock.json` with source hashes. This lock file is useful for detecting unexpected upstream changes and verifying local rule edits before deployment.
