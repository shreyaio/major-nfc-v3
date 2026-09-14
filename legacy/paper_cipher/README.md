# NOT DEPLOYED. NOT IMPORTED.

`crypto_paper.py` in this directory is the custom lightweight block cipher that was
the subject of the accompanying research paper. It is kept **verbatim**, offline, for
reproducibility of that paper's results only.

Hard rules:

- **Nothing in `backend/` or `pi/` may import this module.** A CI check greps for it.
- It is not installed by `backend/requirements.txt` or `pi/requirements.txt`.
- It is not "hardened" or modified. Changing it would invalidate the paper's
  reproducibility. It is intentionally weak by modern standards (small keyspace,
  limited non-linearity).
- The deployed system has exactly one crypto version, `aes_gcm_v2` (AES-256-GCM).
  Anything else is a hard reject, never a fallback. See ARCHITECTURE.md §7.2.

Why it was removed from the deployed path: two ciphers side by side is a downgrade
surface (attacks E8 / D13). A `crypto_version` column that can select a weak cipher is
a weakness even when the weak branch is never taken in practice.

## Running it offline

```bash
cd legacy/paper_cipher
python -c "import crypto_paper; print(crypto_paper.__doc__)"
```

`test_vectors.json` holds fixed input/output pairs so a reviewer can confirm this copy
is byte-for-byte equivalent to the one the paper describes.
