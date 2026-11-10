"""The SAME service, written safely. ServerZEN should report little or nothing here.

This is the contrast case: it shows ServerZEN is context-aware, not just a
keyword grep. Egress goes through a recognised SSRF-safe wrapper, the MD5 is
marked non-security, and untrusted input is parsed with safe formats.

Try:  serverzen scan examples/guarded      # expect: no findings
"""
import hashlib
import json

import yaml

from mysvc.safe_http import make_safe_client  # a validated, DNS-pinning HTTP client


def memory_fingerprint(blob: bytes) -> str:
    # Strong hash for identity/integrity.
    return hashlib.sha256(blob).hexdigest()


def upload_checksum(blob: bytes) -> str:
    # MD5 is fine here: a non-security transport checksum, marked explicitly.
    return hashlib.md5(blob, usedforsecurity=False).hexdigest()


async def deliver_webhook(url: str, payload: dict) -> None:
    # Egress via the SSRF-safe wrapper — ServerZEN recognises this and does not flag it.
    client, _ = await make_safe_client(url)
    async with client:
        await client.post(url, json=payload)


def import_memory_bundle(raw: bytes):
    # Safe format for untrusted import bytes.
    return json.loads(raw)


def load_config(text: str) -> dict:
    # Safe loader — no arbitrary object construction.
    return yaml.safe_load(text)
