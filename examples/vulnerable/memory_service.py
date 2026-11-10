"""A deliberately-INSECURE mini "agent memory" service — a target to try ServerZEN on.

Every function below contains a planted weakness ServerZEN should flag. Do NOT
copy these patterns into real code.

Try:  serverzen scan examples/vulnerable
"""
import hashlib
import pickle

import httpx
import yaml


def memory_fingerprint(blob: bytes) -> str:
    # weak-hash-for-security: MD5 used as an identity/integrity hash.
    return hashlib.md5(blob).hexdigest()


async def deliver_webhook(url: str, payload: dict) -> None:
    # unguarded-egress: raw outbound HTTP, no SSRF validation / DNS pinning.
    async with httpx.AsyncClient() as client:
        await client.post(url, json=payload)


def fetch_provider(url: str):
    # unguarded-egress + unverified-tls: raw egress with cert checking disabled.
    return httpx.get(url, verify=False)


def import_memory_bundle(raw: bytes):
    # unsafe-deserialization (HIGH): pickle over attacker-supplied import bytes = RCE.
    return pickle.loads(raw)


def load_config(text: str) -> dict:
    # unsafe-deserialization: yaml.load without a SafeLoader.
    return yaml.load(text)
