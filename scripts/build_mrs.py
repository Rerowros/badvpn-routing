# /// script
# requires-python = ">=3.12"
# dependencies = ["pyyaml>=6.0.2"]
# ///
"""Build compiled .mrs rule-providers and clean classical split YAMLs.

Derives all Option A rule-provider artifacts deterministically from the YAML
sources under rulesets/ (plus upstream Nemu-x/privWL-clash clV2_provider.yaml
when --with-nemu / --only-nemu / --nemu-file is passed).

Requires a mihomo (or veles) binary supporting `convert-ruleset`.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Iterable

import yaml

ROOT = Path(__file__).resolve().parents[1]
NEMU_WL_URL = "https://raw.githubusercontent.com/Nemu-x/privWL-clash/main/clV2_provider.yaml"
USER_AGENT = "BadVPN-routing-build/1.0"
MIN_NEMU_DOMAINS = 500


def find_mihomo(explicit: str | None) -> Path:
    """Locate the mihomo/veles binary used for convert-ruleset."""
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"mihomo binary not found: {path}")
        return path

    for candidate in ("mihomo", "veles", r"D:\vpn-wiki\bin\mihomo.exe"):
        found = shutil.which(candidate) or (candidate if Path(candidate).is_file() else None)
        if found:
            return Path(found).resolve()
    raise FileNotFoundError("Cannot find mihomo/veles binary; pass --mihomo <path>")


def load_payload(path: Path) -> list[str]:
    """Read a YAML rule-provider payload list as stripped strings."""
    data = yaml.safe_load(path.read_text(encoding="utf-8-sig"))
    if not isinstance(data, dict) or not isinstance(data.get("payload"), list):
        raise ValueError(f"{path}: expected YAML mapping with list 'payload'")
    return [str(item).strip() for item in data["payload"] if str(item).strip()]


def split_entry(entry: str) -> tuple[str, str]:
    """Return (RULE_TYPE, value) for a classical rule entry."""
    parts = [part.strip() for part in entry.split(",")]
    if len(parts) < 2:
        raise ValueError(f"Malformed classical entry: {entry!r}")
    return parts[0].upper(), parts[1]


def extract_domain_lines(entries: Iterable[str]) -> list[str]:
    """Convert DOMAIN / DOMAIN-SUFFIX rules into unique mihomo domain text lines."""
    seen: set[str] = set()
    lines: list[str] = []
    for entry in entries:
        rule_type, val = split_entry(entry)
        if rule_type == "DOMAIN":
            line = val.lower()
        elif rule_type == "DOMAIN-SUFFIX":
            line = f"+.{val.lower()}"
        else:
            continue
        if line not in seen:
            seen.add(line)
            lines.append(line)
    return lines


def extract_ipcidr_lines(entries: Iterable[str]) -> list[str]:
    """Convert IP-CIDR / IP-CIDR6 rules into unique mihomo ipcidr text lines."""
    seen: set[str] = set()
    lines: list[str] = []
    for entry in entries:
        rule_type, val = split_entry(entry)
        if rule_type not in ("IP-CIDR", "IP-CIDR6"):
            continue
        if val not in seen:
            seen.add(val)
            lines.append(val)
    return lines


def compile_mrs(mihomo: Path, behavior: str, lines: list[str], out_path: Path) -> int:
    """Compile text lines to binary .mrs and verify round-trip dump is non-empty."""
    if not lines:
        raise ValueError(f"Refusing to compile empty {behavior} ruleset: {out_path}")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp = Path(tmp_dir)
        txt_path = tmp / "input.txt"
        mrs_path = tmp / "output.mrs"
        dump_path = tmp / "dump.txt"
        txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

        subprocess.run(
            [str(mihomo), "convert-ruleset", behavior, "text", str(txt_path), str(mrs_path)],
            check=True,
        )
        if mrs_path.stat().st_size < 16:
            raise ValueError(f"Compiled {out_path} is too small ({mrs_path.stat().st_size} B)")

        subprocess.run(
            [str(mihomo), "convert-ruleset", behavior, "mrs", str(mrs_path), str(dump_path)],
            check=True,
        )
        dumped_count = sum(1 for line in dump_path.read_text(encoding="utf-8").splitlines() if line.strip())
        if dumped_count == 0:
            raise ValueError(f"Round-trip dump of {out_path} produced 0 entries")

        os.replace(mrs_path, out_path)
    return dumped_count


def write_yaml_payload(out_path: Path, payload: list[str], header_comments: list[str]) -> None:
    """Write a minimal deterministic classical YAML ruleset."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = list(header_comments) + ["payload:"] + [f"  - {item}" for item in payload]
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def dedupe_case_insensitive(entries: Iterable[str]) -> list[str]:
    """Keep first occurrence of each classical rule ignoring case."""
    seen: set[str] = set()
    result: list[str] = []
    for entry in entries:
        key = entry.lower()
        if key not in seen:
            seen.add(key)
            result.append(entry)
    return result


def build_ru_auto(mihomo: Path) -> None:
    src = ROOT / "rulesets" / "direct" / "ru-auto.min.yaml"
    out = ROOT / "rulesets" / "direct" / "ru-auto.mrs"
    n = compile_mrs(mihomo, "domain", extract_domain_lines(load_payload(src)), out)
    print(f"BUILT {out.relative_to(ROOT)}: {n} dumped rules, {out.stat().st_size} B")


def build_nemu_wl(mihomo: Path, nemu_file: Path | None) -> None:
    if nemu_file is not None:
        raw_bytes = nemu_file.read_bytes()
        data = yaml.safe_load(raw_bytes.decode("utf-8-sig"))
        payload = [str(item).strip() for item in data["payload"] if str(item).strip()]
    else:
        req = urllib.request.Request(NEMU_WL_URL, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=60) as resp:
            data = yaml.safe_load(resp.read().decode("utf-8-sig"))
        payload = [str(item).strip() for item in data["payload"] if str(item).strip()]

    lines = extract_domain_lines(payload)
    if len(lines) < MIN_NEMU_DOMAINS:
        raise ValueError(f"Nemu-X-WL unexpectedly small ({len(lines)} < {MIN_NEMU_DOMAINS})")

    out = ROOT / "rulesets" / "proxy" / "nemu-x-wl.mrs"
    n = compile_mrs(mihomo, "domain", lines, out)
    print(f"BUILT {out.relative_to(ROOT)}: {n} dumped rules, {out.stat().st_size} B")


def build_local_sets(mihomo: Path) -> None:
    direct_dir = ROOT / "rulesets" / "direct"
    proxy_dir = ROOT / "rulesets" / "proxy"
    games_dir = ROOT / "rulesets" / "games"

    # 1. Pure 1:1 local YAML -> .mrs
    targets: list[tuple[str, list[str], Path]] = [
        ("domain", extract_domain_lines(load_payload(direct_dir / "ru-services.min.yaml")), direct_dir / "ru-services.mrs"),
        ("domain", extract_domain_lines(load_payload(direct_dir / "ru-auto.min.yaml")), direct_dir / "ru-auto.mrs"),
        ("ipcidr", extract_ipcidr_lines(load_payload(direct_dir / "ru-asn.min.yaml")), direct_dir / "ru-asn.mrs"),
        ("ipcidr", extract_ipcidr_lines(load_payload(proxy_dir / "telegram-extra.yaml")), proxy_dir / "telegram-extra.mrs"),
    ]

    # 2. Split + merged AI & Gemini domains / IPs / classical apps
    ai_entries = load_payload(proxy_dir / "ai.yaml")
    gemini_entries = load_payload(proxy_dir / "gemini.yaml")
    ai_doms = extract_domain_lines(ai_entries + gemini_entries)
    ai_ips = extract_ipcidr_lines(ai_entries)
    ai_apps = [
        e for e in ai_entries
        if split_entry(e)[0] not in ("DOMAIN", "DOMAIN-SUFFIX", "IP-CIDR", "IP-CIDR6")
    ]
    targets.append(("domain", ai_doms, proxy_dir / "ai-domains.mrs"))
    targets.append(("ipcidr", ai_ips, proxy_dir / "ai-ip.mrs"))
    write_yaml_payload(
        proxy_dir / "ai-apps.yaml",
        ai_apps,
        [
            "# BadVPN: не-MRS правила для AI (PROCESS-NAME и DOMAIN-REGEX) -> VPN.",
            "# Домены и IP вынесены в ai-domains.mrs и ai-ip.mrs.",
        ],
    )
    print(f"WROTE rulesets/proxy/ai-apps.yaml: {len(ai_apps)} rules, {(proxy_dir / 'ai-apps.yaml').stat().st_size} B")

    # 3. TikTok domains -> .mrs (5 non-MRS rules go inline in template)
    tiktok_entries = load_payload(proxy_dir / "tiktok.yaml")
    targets.append(("domain", extract_domain_lines(tiktok_entries), proxy_dir / "tiktok-domains.mrs"))

    # 4. Games-Core domains / IPs / deduplicated classical apps
    games_entries = load_payload(games_dir / "games-core.yaml")
    games_apps = dedupe_case_insensitive(
        e for e in games_entries if split_entry(e)[0] == "PROCESS-NAME"
    )
    targets.append(("domain", extract_domain_lines(games_entries), games_dir / "games-core-domains.mrs"))
    targets.append(("ipcidr", extract_ipcidr_lines(games_entries), games_dir / "games-core-ip.mrs"))
    write_yaml_payload(
        games_dir / "games-core-apps.yaml",
        games_apps,
        [
            "# BadVPN: процессы лаунчеров и игр без дублей по регистру -> Игры.",
            "# Домены и IP вынесены в games-core-domains.mrs и games-core-ip.mrs.",
        ],
    )
    print(f"WROTE rulesets/games/games-core-apps.yaml: {len(games_apps)} rules, {(games_dir / 'games-core-apps.yaml').stat().st_size} B")

    # 5. RU-Keywords clean keyword-only list (+otkritie, bspb from ru-core.yaml)
    kw_base = [
        e for e in load_payload(direct_dir / "ru-keywords-replacement.min.yaml")
        if split_entry(e)[0] == "DOMAIN-KEYWORD"
    ]
    existing_kw = {split_entry(e)[1].lower() for e in kw_base}
    core_kws = [
        e for e in load_payload(direct_dir / "ru-core.yaml")
        if split_entry(e)[0] == "DOMAIN-KEYWORD" and split_entry(e)[1].lower() not in existing_kw
    ]
    kw_final = kw_base + core_kws
    write_yaml_payload(
        direct_dir / "ru-keywords.yaml",
        kw_final,
        [
            "# BadVPN: только DOMAIN-KEYWORD для российских сервисов -> DIRECT.",
            "# Дубли доменов из ru-keywords-replacement убраны (покрыты ru-services.mrs);",
            "# добавлены otkritie и bspb из ru-core.yaml.",
        ],
    )
    print(f"WROTE rulesets/direct/ru-keywords.yaml: {len(kw_final)} rules, {(direct_dir / 'ru-keywords.yaml').stat().st_size} B")

    for behavior, lines, out_path in targets:
        n = compile_mrs(mihomo, behavior, lines, out_path)
        print(f"BUILT {out_path.relative_to(ROOT)}: {n} dumped rules, {out_path.stat().st_size} B")


def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(description="Build .mrs and clean YAML rule-providers.")
    ap.add_argument("--mihomo", help="Path to mihomo/veles binary.")
    ap.add_argument("--only-ru-auto", action="store_true", help="Only rebuild ru-auto.mrs.")
    ap.add_argument("--only-nemu", action="store_true", help="Only rebuild nemu-x-wl.mrs.")
    ap.add_argument("--with-nemu", action="store_true", help="Also fetch and compile Nemu-X-WL.")
    ap.add_argument("--nemu-file", type=Path, help="Local copy of clV2_provider.yaml instead of downloading.")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    mihomo = find_mihomo(args.mihomo)

    if args.only_ru_auto:
        build_ru_auto(mihomo)
        if args.with_nemu or args.nemu_file:
            build_nemu_wl(mihomo, args.nemu_file)
        return 0

    if args.only_nemu:
        build_nemu_wl(mihomo, args.nemu_file)
        return 0

    build_local_sets(mihomo)
    if args.with_nemu or args.nemu_file:
        build_nemu_wl(mihomo, args.nemu_file)
    return 0


if __name__ == "__main__":
    sys.exit(main())
