# /// script
# requires-python = ">=3.12"
# dependencies = ["pyyaml>=6.0.2"]
# ///
"""Сборка rulesets/direct/ru-auto.yaml — российские сервисы вне .ru/.su/.рф, которых нет в ручных наборах.

Источник — geosite.dat runetfreedom (собирается ежедневно из v2fly domain-list-community и своих списков):
  CATEGORY-RU                — российские компании и их домены вне российских зон;
  RU-AVAILABLE-ONLY-INSIDE   — сайты, которые открываются только из России.
Вычитается:
  - российские зоны (их шаблон ловит раньше по DOMAIN-SUFFIX);
  - то, что уже есть в ручных наборах ru-services / ru-keywords-replacement / ru-core;
  - заблокированное в РФ (RU-BLOCKED-ALL того же файла): напрямую оно не откроется;
  - хостинги, облака и конструкторы сайтов с чужими клиентами, виджеты и трекеры (EXCLUDE_CATEGORIES);
  - всё, что шаблон намеренно ведёт через VPN (наборы rulesets/proxy/* и VPN_DENY);
  - ручные исключения rulesets/direct/ru-auto-exclude.txt;
  - записи с атрибутом @ads.

Защита от плохого обновления (без --force файл не перезаписывается):
  - размер изменился больше чем на MAX_SHRINK / MAX_GROW от прошлой сборки;
  - домен из MUST_EXCLUDE попал в результат;
  - домен из MUST_COVER не покрыт ни ручными наборами, ни результатом.

  uv run scripts/build_ru_auto.py                       # собрать, записать при прохождении проверок
  uv run scripts/build_ru_auto.py --check               # только проверить, ничего не писать
  uv run scripts/build_ru_auto.py --geosite geosite.dat # взять локальный файл
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "rulesets" / "direct" / "ru-auto.yaml"
OUT_MIN = ROOT / "rulesets" / "direct" / "ru-auto.min.yaml"
EXCLUDE_FILE = ROOT / "rulesets" / "direct" / "ru-auto-exclude.txt"
CURATED = ["ru-services.yaml", "ru-keywords-replacement.yaml", "ru-core.yaml"]
GEOSITE_URL = "https://github.com/runetfreedom/russia-v2ray-rules-dat/releases/latest/download/geosite.dat"

SOURCES = {"CATEGORY-RU": "category-ru", "RU-AVAILABLE-ONLY-INSIDE": "только из РФ"}
RU_ZONES = ("ru", "su", "xn--p1ai", "moscow", "tatar", "xn--80adxhks", "xn--d1acj3b")
# хостинги, облака и конструкторы сайтов: на их доменах живут чужие сайты; виджеты, трекеры, анти-DDoS
EXCLUDE_CATEGORIES = ["BEGET", "SELECTEL", "TIMEWEB", "REGRU", "NIC-RU", "TILDA", "UCOZ", "SERVICEPIPE",
                      "CARROTQUEST", "ENVYBOX", "MINDBOX", "CATEGORY-BETTING-RU", "CATEGORY-ADS-ALL"]
# через VPN намеренно (шаблон ведёт их в свои группы) — не должны уйти в прямые ни при каком источнике
VPN_DENY = ["google.com", "googlevideo.com", "youtube.com", "ytimg.com", "ggpht.com", "gstatic.com",
            "telegram.org", "t.me", "telegram.me", "discord.com", "discordapp.com", "discord.gg",
            "twitch.tv", "x.com", "twitter.com", "openai.com", "chatgpt.com", "anthropic.com", "claude.ai",
            "tiktok.com", "instagram.com", "facebook.com", "whatsapp.com", "github.com", "cloudflare.com"]
MUST_EXCLUDE = ["youtube.com", "googlevideo.com", "telegram.org", "discord.com", "openai.com",
                "chatgpt.com", "instagram.com", "rutracker.org"]
MUST_COVER = ["sberbank.com", "yandex.com", "x5static.net", "gismeteo.com", "ozonusercontent.com"]
MAX_SHRINK, MAX_GROW = 0.15, 0.30


# --- geosite.dat (protobuf: GeoSiteList{1: GeoSite{1: code, 2: Domain{1: type, 2: value, 3: Attribute{1: key}}}}) ---
def _varint(b: bytes, i: int) -> tuple[int, int]:
    r = s = 0
    while True:
        x = b[i]
        i += 1
        r |= (x & 0x7F) << s
        s += 7
        if x < 0x80:
            return r, i


def _fields(b: bytes):
    i = 0
    while i < len(b):
        k, i = _varint(b, i)
        f, t = k >> 3, k & 7
        if t == 0:
            v, i = _varint(b, i)
        elif t == 2:
            n, i = _varint(b, i)
            v = b[i:i + n]
            i += n
        elif t == 5:
            v, i = b[i:i + 4], i + 4
        elif t == 1:
            v, i = b[i:i + 8], i + 8
        else:
            raise ValueError(f"wire type {t}")
        yield f, v


def read_geosite(data: bytes, wanted: set[str]) -> dict[str, list[tuple[str, set[str]]]]:
    """{код: [(домен, атрибуты)]} — только типы Domain (2) и Full (3); keyword/regexp не переносятся."""
    out: dict[str, list[tuple[str, set[str]]]] = {}
    for f, site in _fields(data):
        if f != 1:
            continue
        code, doms = None, []
        for f2, v2 in _fields(site):
            if f2 == 1:
                code = v2.decode()
                if code not in wanted:
                    break
            elif f2 == 2:
                typ, val, attrs = 0, "", set()
                for f3, v3 in _fields(v2):
                    if f3 == 1:
                        typ = v3
                    elif f3 == 2:
                        val = v3.decode().lower()
                    elif f3 == 3:
                        attrs |= {v4.decode() for f4, v4 in _fields(v3) if f4 == 1}
                if typ in (2, 3) and val:
                    doms.append((val, attrs))
        if code in wanted:
            out[code] = doms
    return out


# --- помощники ---
def parents(d: str):
    p = d.split(".")
    for i in range(len(p)):
        yield ".".join(p[i:])


def covered(d: str, s: set[str]) -> bool:
    return any(x in s for x in parents(d))


def ruleset_domains(path: Path) -> set[str]:
    out = set()
    if not path.exists():
        return out
    for ln in path.read_text(encoding="utf-8").splitlines():
        m = re.match(r"\s*-\s*(?:DOMAIN-SUFFIX|DOMAIN),([^,#\s]+)", ln)
        if m:
            out.add(m.group(1).lower().lstrip("."))
        m = re.match(r"\s*-\s*'?\+\.([^'#\s]+)", ln)
        if m:
            out.add(m.group(1).lower())
    return out


def prev_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for ln in path.read_text(encoding="utf-8").splitlines() if ln.lstrip().startswith("- "))


def build(geo: bytes) -> tuple[dict[str, str], dict[str, int]]:
    wanted = set(SOURCES) | set(EXCLUDE_CATEGORIES) | {"RU-BLOCKED-ALL"}
    g = read_geosite(geo, wanted)
    missing = [c for c in SOURCES if not g.get(c)]
    if missing:
        sys.exit(f"в geosite нет категорий: {missing}")
    blocked = {d for d, _ in g.get("RU-BLOCKED-ALL", [])}
    excl_cat = {d for c in EXCLUDE_CATEGORIES for d, _ in g.get(c, [])}
    deny = set(VPN_DENY)
    for p in (ROOT / "rulesets" / "proxy").glob("*.yaml"):
        deny |= ruleset_domains(p)
    manual = set()
    if EXCLUDE_FILE.exists():
        manual = {ln.split("#")[0].strip().lower() for ln in EXCLUDE_FILE.read_text(encoding="utf-8").splitlines()} - {""}
    curated = set()
    for name in CURATED:
        curated |= ruleset_domains(ROOT / "rulesets" / "direct" / name)

    stats = {"blocked_ru": len(blocked)}
    cand: dict[str, str] = {}
    drop = {"ads": 0, "ru_zone": 0, "curated": 0, "blocked": 0, "hosting_widgets": 0, "vpn": 0, "manual": 0}
    for code, label in SOURCES.items():
        stats[code] = len(g[code])
        for d, attrs in g[code]:
            if "ads" in attrs:
                drop["ads"] += 1
            elif d.rsplit(".", 1)[-1] in RU_ZONES:
                drop["ru_zone"] += 1
            elif covered(d, curated):
                drop["curated"] += 1
            elif covered(d, blocked):
                drop["blocked"] += 1
            elif covered(d, excl_cat):
                drop["hosting_widgets"] += 1
            elif covered(d, deny):
                drop["vpn"] += 1
            elif covered(d, manual):
                drop["manual"] += 1
            else:
                cand.setdefault(d, label)
    # сжатие: поддомен не нужен, если в наборе есть родитель
    result = {d: s for d, s in cand.items() if not any(p in cand for p in list(parents(d))[1:])}
    stats.update({f"drop_{k}": v for k, v in drop.items()})
    stats["result"] = len(result)
    return result, stats, curated


def guards(result: dict[str, str], curated: set[str], prev: int) -> list[str]:
    errs = []
    for d in MUST_EXCLUDE:
        if covered(d, set(result)):
            errs.append(f"в прямые попал домен из MUST_EXCLUDE: {d}")
    for d in MUST_COVER:
        if not (covered(d, set(result)) or covered(d, curated)):
            errs.append(f"не покрыт домен из MUST_COVER: {d}")
    if prev:
        ch = (len(result) - prev) / prev
        if ch < -MAX_SHRINK or ch > MAX_GROW:
            errs.append(f"размер {prev} -> {len(result)} ({ch:+.0%}), допустимо -{MAX_SHRINK:.0%}/+{MAX_GROW:.0%}")
    return errs


def render(result: dict[str, str], stats: dict[str, int], with_comments: bool) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    head = [] if not with_comments else [
        "# BadVPN: российские сервисы вне .ru/.su/.рф, которых нет в ручных наборах -> «РУ сайты». Автосборка.",
        "# Источник: geosite.dat runetfreedom (CATEGORY-RU из v2fly + RU-AVAILABLE-ONLY-INSIDE).",
        "# Вычтено: российские зоны, ru-services/ru-keywords-replacement/ru-core, заблокированное в РФ,",
        "# хостинги/облака/конструкторы/виджеты, всё из rulesets/proxy и ru-auto-exclude.txt, @ads.",
        f"# Собрано scripts/build_ru_auto.py {now}: {stats['result']} доменов. Не править руками —",
        "# исключения в ru-auto-exclude.txt, добавления в ru-services.yaml.",
    ]
    lines = head + ["payload:"]
    for d in sorted(result):
        lines.append(f"  - DOMAIN-SUFFIX,{d}" + (f" # {result[d]}" if with_comments else ""))
    return "\n".join(lines) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--geosite", help="локальный geosite.dat вместо скачивания")
    ap.add_argument("--check", action="store_true", help="только проверить, не писать")
    ap.add_argument("--force", action="store_true", help="записать, даже если не прошла проверка размера")
    a = ap.parse_args()

    if a.geosite:
        geo = Path(a.geosite).read_bytes()
    else:
        req = urllib.request.Request(GEOSITE_URL, headers={"User-Agent": "BadVPN-routing-build/1.0"})
        with urllib.request.urlopen(req, timeout=300) as r:
            geo = r.read()
    result, stats, curated = build(geo)
    prev = prev_count(OUT_MIN)
    errs = guards(result, curated, prev)
    print(" ".join(f"{k}={v}" for k, v in stats.items()), f"prev={prev}")
    hard = [e for e in errs if not e.startswith("размер")]
    if hard or (errs and not a.force):
        for e in errs:
            print("ОШИБКА:", e)
        sys.exit(1)
    if a.check:
        print("check ok")
        return
    OUT.write_text(render(result, stats, True), encoding="utf-8", newline="\n")
    OUT_MIN.write_text(render(result, stats, False), encoding="utf-8", newline="\n")
    print(f"записано {OUT.relative_to(ROOT)} и {OUT_MIN.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
