# /// script
# requires-python = ">=3.13"
# dependencies = ["pyyaml>=6.0.2"]
# ///
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "routing-sources.yaml"
DEFAULT_LOCK = ROOT / "dist" / "upstream-sources.lock.json"
DEFAULT_CACHE_DIR = ROOT / "cache" / "upstream"
USER_AGENT = "BadVPN-routing-source-check/1.0"


@dataclass(frozen=True)
class SourceResult:
    name: str
    provider: str
    owner: str
    url: str
    path: str | None
    format: str
    behavior: str
    route: str
    ok: bool
    status: int | None = None
    bytes: int = 0
    sha256: str | None = None
    item_count: int | None = None
    etag: str | None = None
    last_modified: str | None = None
    content_type: str | None = None
    error: str | None = None

    def as_json(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "owner": self.owner,
            "url": self.url,
            "path": self.path,
            "format": self.format,
            "behavior": self.behavior,
            "route": self.route,
            "ok": self.ok,
            "status": self.status,
            "bytes": self.bytes,
            "sha256": self.sha256,
            "item_count": self.item_count,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "content_type": self.content_type,
            "error": self.error,
        }


def load_manifest(path: Path) -> dict[str, dict[str, Any]]:
    with path.open("r", encoding="utf-8") as file:
        data = yaml.safe_load(file)
    if not isinstance(data, dict) or not isinstance(data.get("sources"), dict):
        raise ValueError(f"{path} must contain a top-level 'sources' mapping")
    return data["sources"]


def fetch(url: str, timeout: float) -> tuple[bytes, dict[str, str], int]:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        headers = {key.lower(): value for key, value in response.headers.items()}
        return response.read(), headers, response.status


def read_local(path: str) -> tuple[bytes, dict[str, str], int | None]:
    source_path = (ROOT / path).resolve()
    if not source_path.is_file():
        raise FileNotFoundError(f"{path}: file not found")
    if not source_path.is_relative_to(ROOT):
        raise ValueError(f"{path}: local source must stay inside {ROOT}")
    return source_path.read_bytes(), {"content-type": "local/file"}, None


def count_yaml_payload(content: bytes, source_name: str) -> int:
    text = content.decode("utf-8-sig")
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or "payload" not in data:
        raise ValueError(f"{source_name}: YAML provider must contain payload")
    payload = data["payload"]
    if not isinstance(payload, list):
        raise ValueError(f"{source_name}: payload must be a list")
    invalid = [item for item in payload if not isinstance(item, str)]
    if invalid:
        raise ValueError(f"{source_name}: payload contains non-string entries")
    return len(payload)


def validate_mrs(content: bytes, source_name: str) -> None:
    if len(content) < 16:
        raise ValueError(f"{source_name}: MRS payload is too small")


def cache_name(source_name: str, source_format: str) -> str:
    suffix = ".mrs" if source_format == "mrs" else ".yaml"
    return f"{source_name}{suffix}"


def check_source(
    name: str,
    meta: dict[str, Any],
    timeout: float,
    retries: int,
    retry_delay: float,
    cache_dir: Path | None,
) -> SourceResult:
    required_fields = ["provider", "owner", "format", "behavior", "route"]
    missing = [field for field in required_fields if not meta.get(field)]
    if not meta.get("url") and not meta.get("path"):
        missing.append("url or path")
    if missing:
        return SourceResult(
            name=name,
            provider=str(meta.get("provider", "")),
            owner=str(meta.get("owner", "")),
            url=str(meta.get("url", "")),
            path=str(meta["path"]) if meta.get("path") else None,
            format=str(meta.get("format", "")),
            behavior=str(meta.get("behavior", "")),
            route=str(meta.get("route", "")),
            ok=False,
            error=f"missing fields: {', '.join(missing)}",
        )

    source_format = str(meta["format"])
    source_url = str(meta.get("url", ""))
    source_path = str(meta["path"]) if meta.get("path") else None

    if source_url:
        last_error: Exception | None = None
        for attempt in range(retries + 1):
            try:
                content, headers, status = fetch(source_url, timeout)
                break
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = exc
                if attempt < retries:
                    time.sleep(retry_delay)
                continue
        else:
            return SourceResult(
                name=name,
                provider=str(meta.get("provider", "")),
                owner=str(meta.get("owner", "")),
                url=source_url,
                path=source_path,
                format=source_format,
                behavior=str(meta.get("behavior", "")),
                route=str(meta.get("route", "")),
                ok=False,
                error=str(last_error),
            )
    else:
        try:
            content, headers, status = read_local(str(source_path))
        except (OSError, ValueError) as exc:
            return SourceResult(
                name=name,
                provider=str(meta.get("provider", "")),
                owner=str(meta.get("owner", "")),
                url=source_url,
                path=source_path,
                format=source_format,
                behavior=str(meta.get("behavior", "")),
                route=str(meta.get("route", "")),
                ok=False,
                error=str(exc),
            )

    try:
        if not content:
            raise ValueError(f"{name}: empty response")

        item_count: int | None = None
        if source_format == "yaml":
            item_count = count_yaml_payload(content, name)
        elif source_format == "mrs":
            validate_mrs(content, name)
        else:
            raise ValueError(f"{name}: unsupported format {source_format!r}")

        if cache_dir is not None:
            cache_dir.mkdir(parents=True, exist_ok=True)
            (cache_dir / cache_name(name, source_format)).write_bytes(content)

        return SourceResult(
            name=name,
            provider=str(meta["provider"]),
            owner=str(meta["owner"]),
            url=source_url,
            path=source_path,
            format=source_format,
            behavior=str(meta["behavior"]),
            route=str(meta["route"]),
            ok=True,
            status=status,
            bytes=len(content),
            sha256=hashlib.sha256(content).hexdigest(),
            item_count=item_count,
            etag=headers.get("etag"),
            last_modified=headers.get("last-modified"),
            content_type=headers.get("content-type"),
        )
    except (urllib.error.URLError, TimeoutError, ValueError, UnicodeDecodeError, yaml.YAMLError) as exc:
        return SourceResult(
            name=name,
            provider=str(meta.get("provider", "")),
            owner=str(meta.get("owner", "")),
            url=source_url,
            path=source_path,
            format=source_format,
            behavior=str(meta.get("behavior", "")),
            route=str(meta.get("route", "")),
            ok=False,
            error=str(exc),
        )


def load_previous_lock(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def changed_sources(previous_lock: dict[str, Any] | None, results: list[SourceResult]) -> list[str]:
    if not previous_lock:
        return []
    previous_sources = previous_lock.get("sources", {})
    changed: list[str] = []
    for result in results:
        previous = previous_sources.get(result.name, {})
        if previous.get("sha256") and previous.get("sha256") != result.sha256:
            changed.append(result.name)
    return changed


def build_lock(results: list[SourceResult]) -> dict[str, Any]:
    failed = [result.name for result in results if not result.ok]
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": {
            "source_count": len(results),
            "ok_count": len(results) - len(failed),
            "failed_count": len(failed),
            "failed": failed,
        },
        "sources": {result.name: result.as_json() for result in results},
    }


def write_lock(path: Path, lock: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as file:
        json.dump(lock, file, ensure_ascii=False, indent=2)
        file.write("\n")


def print_summary(results: list[SourceResult], changed: list[str]) -> None:
    for result in results:
        status = "OK" if result.ok else "FAIL"
        details = f"{result.bytes} bytes"
        if result.item_count is not None:
            details += f", {result.item_count} items"
        if result.error:
            details = result.error
        print(f"{status:4} {result.name:34} {result.provider:26} {details}")

    if changed:
        print("\nChanged since lock:")
        for name in changed:
            print(f"- {name}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check BadVPN routing upstream sources.")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--timeout", type=float, default=45.0)
    parser.add_argument("--retries", type=int, default=2)
    parser.add_argument("--retry-delay", type=float, default=2.0)
    parser.add_argument("--check", action="store_true", help="Do not write the lock file.")
    parser.add_argument("--write-lock", action="store_true", help="Write dist/upstream-sources.lock.json.")
    parser.add_argument("--write-cache", action="store_true", help="Cache downloaded sources under cache/upstream.")
    parser.add_argument("--fail-on-change", action="store_true", help="Exit non-zero if source hashes differ from lock.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    manifest = load_manifest(args.manifest)
    cache_dir = DEFAULT_CACHE_DIR if args.write_cache else None
    results = [
        check_source(
            name,
            meta,
            timeout=args.timeout,
            retries=args.retries,
            retry_delay=args.retry_delay,
            cache_dir=cache_dir,
        )
        for name, meta in manifest.items()
    ]

    previous_lock = load_previous_lock(args.lock)
    changed = changed_sources(previous_lock, results)
    lock = build_lock(results)
    print_summary(results, changed)

    failures = [result for result in results if not result.ok]
    if args.write_lock or not args.check:
        write_lock(args.lock, lock)
        print(f"\nWrote {args.lock.relative_to(ROOT)}")

    if failures:
        return 1
    if args.fail_on_change and changed:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
