#!/usr/bin/env python3
"""
Pure-Python V3/V4 Keypair Generator (matches tools/keygen Rust utility without requiring Cargo).
Prints fresh Server `.env` secrets AND corresponding GitHub Actions Secrets to stdout.
Never commit generated secret values to git.
"""

import secrets
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import v3_crypto


def main() -> None:
    x_priv = secrets.token_bytes(32)
    x_pub = v3_crypto.x25519_public_key(x_priv)

    ed_seed = secrets.token_bytes(32)
    ed_pub = v3_crypto.ed25519_public_key(ed_seed)

    pepper = secrets.token_bytes(32).hex()
    bundle_master = secrets.token_bytes(32).hex()
    ci_sync = secrets.token_bytes(32).hex()
    ipc_secret = secrets.token_bytes(32).hex()

    print("# ================= SERVER .env (DAT NGOAI THU MUC WEB) =================")
    print(f"SERVER_X25519_PRIV_HEX={x_priv.hex()}")
    print(f"SERVER_ED25519_PRIV_HEX={ed_seed.hex()}")
    print(f"PRE_SHARED_PEPPER={pepper}")
    print(f"BUNDLE_PATCH_MASTER_KEY_HEX={bundle_master}")
    print(f"CI_SYNC_SECRET={ci_sync}")
    print(f"RUST_CORE_IPC_SECRET={ipc_secret}")
    print()
    print("# ================= GITHUB ACTIONS SECRETS (Settings -> Actions) ======")
    print(f"SEC_SERVER_X25519_PUB={x_pub.hex()}")
    print(f"SEC_SERVER_ED25519_PUB={ed_pub.hex()}")
    print(f"SEC_PEPPER={pepper}")
    print(f"SEC_BUNDLE_MASTER_KEY={bundle_master}")
    print(f"SEC_CI_SYNC_SECRET={ci_sync}")


if __name__ == "__main__":
    main()
