# ServerZEN examples — a tiny test environment

Two versions of the same mini "agent memory" service, so you can see ServerZEN
in action and confirm it distinguishes risky code from safe code.

- [`vulnerable/`](vulnerable/memory_service.py) — every function has a planted
  weakness (weak hash, unguarded egress, unsafe deserialization, disabled TLS).
- [`guarded/`](guarded/memory_service.py) — the same features written safely.

## Try it

```bash
# From the repo root (no install needed):
python -m serverzen scan examples/vulnerable      # several findings
python -m serverzen scan examples/guarded         # expected: no findings
python -m serverzen scan examples                 # scan both at once
```

The point of the two folders: a generic scanner flags the egress and the MD5 in
**both** files. ServerZEN flags them in `vulnerable/` but stays quiet on
`guarded/`, because that code routes egress through a recognised SSRF-safe
wrapper and marks its MD5 as non-security. That context-awareness is the product.

See [`../docs/USAGE.md`](../docs/USAGE.md) for scanning your own code, output
formats (table/JSON/SARIF), CI gating, and a pre-commit hook.
