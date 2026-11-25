#!/usr/bin/env python3
"""
Registers built IPA Mach-O `__TEXT,__text` SHA-256 hashes (`app_hash` and `sec_hash`)
with the Server Key via HMAC-authenticated `ci_register_build` endpoint.
"""

import argparse
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request


def sync_build(
    url: str,
    secret: str,
    package_id: str,
    version: str,
    build: str,
    app_hash: str,
    sec_hash: str,
    note: str = "",
    auto_update_latest: bool = False,
) -> dict:
    ts = int(time.time())
    nonce = os.urandom(16).hex()
    sign_input = f"CIREG|{package_id}|{version}|{build}|{app_hash.lower()}|{sec_hash.lower()}|{nonce}|{ts}".encode("utf-8")
    sig = hmac.new(secret.encode("utf-8"), sign_input, hashlib.sha256).hexdigest()

    body = json.dumps(
        {
            "package_id": package_id,
            "version": version,
            "build": build,
            "app_hash": app_hash.lower(),
            "sec_hash": sec_hash.lower(),
            "note": note,
            "auto_update_latest": auto_update_latest,
            "nonce": nonce,
            "ts": ts,
            "sig": sig,
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "3105-CI-Sync/3.0"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description="Register CI binary hashes with Server Key")
    parser.add_argument("--url", required=True)
    parser.add_argument("--secret", required=True)
    parser.add_argument("--package-id", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--build", default="")
    parser.add_argument("--app-hash", required=True)
    parser.add_argument("--sec-hash", required=True)
    parser.add_argument("--note", default="GitHub Actions Release")
    parser.add_argument("--auto-latest", action="store_true")
    args = parser.parse_args()

    res = sync_build(
        url=args.url,
        secret=args.secret,
        package_id=args.package_id,
        version=args.version,
        build=args.build,
        app_hash=args.app_hash,
        sec_hash=args.sec_hash,
        note=args.note,
        auto_update_latest=args.auto_latest,
    )
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
