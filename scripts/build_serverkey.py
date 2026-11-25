#!/usr/bin/env python3
"""
Packages hardened `serverkey` deployment artifact (`dist/serverkey/`):
- Compresses/packs PHP crypto engine (`lib/CoreEngine.php`) via zlib+base64 bootstrapper
  so plain business logic is not exposed on shared hosting webroots.
- Excludes secrets (.env), live JSON stores, debug/backup files.
- Optionally bundles compiled `serverkey_core` native Rust binary.
"""

import argparse
import base64
import shutil
import zlib
from pathlib import Path


def pack_php_file(src: Path, dst: Path) -> None:
    raw = src.read_text(encoding="utf-8")
    body = raw.lstrip()
    if body.startswith("<?php"):
        body = body[5:]
    if body.endswith("?>"):
        body = body[:-2]
    compressed = zlib.compress(body.strip().encode("utf-8"), level=9)
    b64 = base64.b64encode(compressed).decode("ascii")
    # Split base64 into randomized chunks so casual inspection/grep is defeated
    chunks = [b64[i : i + 76] for i in range(0, len(b64), 76)]
    joined = "'\n    .'".join(chunks)
    packed = (
        "<?php\n"
        "// Protected PHUCVN 3105 Security Module (Packed Artifact)\n"
        "$__p3105 = '"
        + joined
        + "';\n"
        "eval(@gzuncompress(base64_decode($__p3105)));\n"
    )
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(packed, encoding="utf-8")


def package_serverkey(serverkey_dir: Path, out_dir: Path, rust_bin: Path | None = None) -> Path:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    safe_top_files = [
        ".htaccess",
        ".env.example",
        "admin.php",
        "api.php",
        "api_v2.php",
        "config.php",
        "index.php",
        "nginx.conf.example",
        "schema_addon.sql",
    ]
    for name in safe_top_files:
        src = serverkey_dir / name
        if src.exists():
            shutil.copy2(src, out_dir / name)

    # Pack CoreEngine.php inside lib/
    pack_php_file(serverkey_dir / "lib" / "CoreEngine.php", out_dir / "lib" / "CoreEngine.php")

    # Copy retired api/ stubs
    if (serverkey_dir / "api").is_dir():
        (out_dir / "api").mkdir(parents=True, exist_ok=True)
        for p in (serverkey_dir / "api").glob("*.php"):
            shutil.copy2(p, out_dir / "api" / p.name)

    # Copy assets (logo)
    if (serverkey_dir / "assets").is_dir():
        shutil.copytree(serverkey_dir / "assets", out_dir / "assets")

    # Clean data template directory (empty JSON stores + .htaccess, zero live credentials)
    data_out = out_dir / "data"
    data_out.mkdir(parents=True, exist_ok=True)
    if (serverkey_dir / "data" / ".htaccess").exists():
        shutil.copy2(serverkey_dir / "data" / ".htaccess", data_out / ".htaccess")
    for fn in ("keys.json", "users.json", "logs.json", "build_manifests.json", "banned_devices.json"):
        (data_out / fn).write_text("[]\n", encoding="utf-8")
    shutil.copy2(serverkey_dir / "data" / "settings.json", data_out / "settings.json")

    if rust_bin and rust_bin.exists():
        bin_dir = out_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(rust_bin, bin_dir / rust_bin.name)
        try:
            (bin_dir / rust_bin.name).chmod(0o755)
        except OSError:
            pass

    return out_dir


def main() -> None:
    parser = argparse.ArgumentParser(description="Package hardened serverkey distribution")
    parser.add_argument("--src", type=Path, default=Path("serverkey"))
    parser.add_argument("--out", type=Path, default=Path("dist/serverkey"))
    parser.add_argument("--rust-bin", type=Path, default=None)
    args = parser.parse_args()
    out = package_serverkey(args.src, args.out, args.rust_bin)
    print(f"Packaged hardened serverkey -> {out}")


if __name__ == "__main__":
    main()
