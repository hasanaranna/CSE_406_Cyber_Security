# CSE 406 Assignment 01 — scaffolding

## Files

| File | Status | Covers |
|---|---|---|
| `aes_core.py` | **boilerplate + TODOs** | Task 1 (40 marks) |
| `dh_core.py` | **boilerplate + TODOs** | Task 2 (25 marks) |
| `netutil.py` | fully implemented | socket framing helpers used by Task 3 |
| `alice.py` | fully implemented | Task 3 sender |
| `bob.py` | fully implemented | Task 3 receiver |

All of this has been tested: `aes_core.py`'s round-orchestration reproduces the
official FIPS-197 test vector exactly once real transformations are plugged
in, its output format matches your `sampleio.png` line-for-line, and
`alice.py`/`bob.py` complete a full DH handshake + AES transfer over a real
socket. You're just filling in the TODOs.

## What's a TODO and why

Task 1 and Task 2 are graded as *independent implementations*, and the
assignment's plagiarism clause specifically calls out AES/DH as easy to find
online. So every function that **is** the cipher or the number theory is left
as a stub with a docstring describing exactly what it needs to do:

- `aes_core.py`: `sub_bytes`, `inv_sub_bytes`, `shift_rows`, `inv_shift_rows`,
  `mix_columns`, `inv_mix_columns`, `add_round_key`, `key_expansion`,
  `normalize_key_to_16_bytes`, `pkcs7_pad`, `pkcs7_unpad`, `ecb_encrypt`,
  `ecb_decrypt`, `cbc_encrypt`, `cbc_decrypt`.
- `dh_core.py`: `miller_rabin`, `generate_prime`, `find_generator`,
  `derive_aes_key`.

Everything around those (hex/ASCII formatting, timing, the byte↔state
layout, the Figure-1 round loop, the DH results table, the socket handshake)
is done, since none of that is what's being examined — it's scaffolding so
you can spend your time on the actual algorithms, which is also what you'll
want to know cold for the viva.

## Running things

```bash
# Task 1 — fill in aes_core.py, then:
python3 aes_core.py                 # prints a CBC then an ECB demo session

# Task 2 — fill in dh_core.py, then:
python3 dh_core.py                   # prints the k / A / B / s timing table

# Task 3 — needs both aes_core.py and dh_core.py finished:
python3 bob.py                       # terminal 1 — start this first
python3 alice.py                     # terminal 2
```

`aes_core.py`'s stubs raise `NotImplementedError` in the order the demo
touches them, so re-running it as you go tells you exactly which function to
write next.

## A few things you'll still need to decide (on purpose)

- **Key normalization** (`normalize_key_to_16_bytes`): the assignment lets you
  pad or truncate non-16-byte keys but wants you to justify it at the viva —
  so pick an approach yourself rather than using whatever's "given."
- **AES key derivation from the DH secret** (`derive_aes_key`): same deal —
  truncate vs. hash, your call, be ready to explain the trade-off.
- **Generator search** (`find_generator`): factoring `P-1` in general is
  expensive; look into *safe primes* (`P = 2q+1`) if you want a tractable
  approach — mentioned in the docstring, not implemented for you.

## Before you submit

1. Rename files per the assignment's convention: `2005XXX_aes.py`,
   `2005XXX_dh.py`, `2005XXX_alice.py`, `2005XXX_bob.py`, etc.
2. A bare `import 2005123_aes` is invalid Python (names can't start with a
   digit) — use `netutil.load_numeric_module(path, name)` if you need to
   import a renamed file, or just keep working filenames until the last
   step and rename only for the zip.
3. Don't include your own copy of `aes_helpers.py` in a way that overwrites
   the evaluator's — the assignment asks you to just import it as given.

## Bonus tasks (not built out here — happy to help with any of these)

- **ECB vs. CBC on an image**: read a small image's raw bytes (e.g. a `.bmp`
  or `.ppm`, which have simple fixed headers), keep the header intact,
  run only the pixel data through your (by-then-finished) `ecb_encrypt` /
  `cbc_encrypt`, write the result back out with the original header so it's
  still viewable. Your existing functions already work on raw `bytes`, so
  this is mostly file I/O, not new crypto.
- **Other file types**: your `ecb_encrypt`/`cbc_encrypt` already operate on
  raw bytes — open any file in `"rb"` mode and they work unmodified.
- **192/256-bit keys**: needs `key_expansion` generalized for `Nk = 6 or 8`
  words and `NUM_ROUNDS` for `Nr = 12 or 14`, instead of the hardcoded
  AES-128 constants at the top of `aes_core.py`.
