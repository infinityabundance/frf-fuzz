#!/usr/bin/env python3
"""Independent reference implementation of Philox4x32-10 (Random123).

Purpose: generate deterministic test vectors for the Rust implementation in
`frf-fuzz/src/mutation/prng.rs`. This file is NOT part of the crate; it is a
Phase-0 forensic spike artifact. It is cross-verified against numpy's Philox
bit generator with explicitly set state before vectors are trusted.

Reference: Random123 (Salmon, Castro, ~2011), Philox4x32-10 with the standard
multipliers/addends:
    M0 = 0xD2511F53, M1 = 0xCD9E8D57
    W0 = 0x9E3779B9, W1 = 0xBB67AE85
10 rounds; key is rotated (k0,k1) -> (k1, k0 ^ W0) per round.
"""

MASK32 = 0xFFFFFFFF
M0 = 0xD2511F53
M1 = 0xCD9E8D57
W0 = 0x9E3779B9
W1 = 0xBB67AE85


def mulhi(a: int, b: int) -> int:
    return ((a & MASK32) * (b & MASK32)) >> 32


def mullo(a: int, b: int) -> int:
    return ((a & MASK32) * (b & MASK32)) & MASK32


def mulhilo(a: int, b: int):
    """Return (lo, hi) of the 64-bit product a*b (a,b 32-bit)."""
    p = (a & MASK32) * (b & MASK32)
    return p & MASK32, p >> 32


def philox_round(c, k):
    """One Philox4x32 round, per Random123 philox.h `_philox4xWround_tpl`:
    out = { hi1 ^ c1 ^ k0,  lo1,  hi0 ^ c3 ^ k1,  lo0 }
    where lo_i/hi_i come from multiplying M_i by c_{2i}."""
    c0, c1, c2, c3 = c
    k0, k1 = k
    lo0, hi0 = mulhilo(M0, c0)
    lo1, hi1 = mulhilo(M1, c2)
    return [
        (hi1 ^ c1 ^ k0) & MASK32,
        lo1,
        (hi0 ^ c3 ^ k1) & MASK32,
        lo0,
    ]


def philox_bumpkey(k):
    """key.v[0] += W0; key.v[1] += W1 (addition mod 2^32)."""
    return [(k[0] + W0) & MASK32, (k[1] + W1) & MASK32]


def philox4x32_10_correct(ctr, key):
    """Philox4x32-10 (10 rounds, 9 key bumps): official Random123 semantics."""
    c = [x & MASK32 for x in ctr]
    k = [x & MASK32 for x in key]
    for rnd in range(10):
        c = philox_round(c, k)
        if rnd < 9:
            k = philox_bumpkey(k)
    return c


def stream(ctr0, key, n):
    out = []
    c = list(ctr0)
    for i in range(n):
        out.append(philox4x32_10_correct(c, key))
        c[0] = (c[0] + 1) & MASK32
        if c[0] == 0:
            c[1] = (c[1] + 1) & MASK32
    return out


if __name__ == "__main__":
    import json
    import sys

    # ---- 0. Gate on the OFFICIAL Random123 KAT vectors (tests/kat_vectors) ----
    KAT = [
        ("ctr0 key0", [0, 0, 0, 0], [0, 0],
         [0x6627E8D5, 0xE169C58D, 0xBC57AC4C, 0x9B00DBD8]),
        ("ctrmax keymax", [0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF],
         [0xFFFFFFFF, 0xFFFFFFFF],
         [0x408F276D, 0x41C83B0E, 0xA20BC7C6, 0x6D5451FD]),
        ("ctr2 key2", [0x243F6A88, 0x85A308D3, 0x13198A2E, 0x03707344],
         [0xA4093822, 0x299F31D0],
         [0xD16CFE09, 0x94FDCCEB, 0x5001E420, 0x24126EA1]),
    ]
    ok = True
    for name, ctr, key, want in KAT:
        got = philox4x32_10_correct(ctr, key)
        match = got == want
        ok = ok and match
        print(f"KAT {name}: {'PASS' if match else 'FAIL'} got {[hex(x) for x in got]}")
    if not ok:
        print("OFFICIAL KAT VECTORS FAILED — aborting", file=sys.stderr)
        sys.exit(1)

    # ---- 1. Cross-check against numpy with explicitly set Philox state ----
    try:
        import numpy as np
    except ImportError:
        print("numpy unavailable; skipping numpy cross-check", file=sys.stderr)
        numpy_ok = False
    else:
        # numpy state format: counter = [c0,c1,c2,c3] as Python ints (each < 2^32)
        # or as one big int? Probe with a known state, then compare.
        g = np.random.Philox()
        g.state = {
            "bit_generator": "Philox",
            "state": {
                "counter": np.array([0, 0, 0, 0], dtype=np.uint64),
                "key": np.array([0, 0], dtype=np.uint64),
            },
            "buffer": np.array([0, 0, 0, 0], dtype=np.uint64),
            "buffer_pos": 4,
            "has_uint32": 0,
            "uinteger": 0,
        }
        raw = g.random_raw(4)
        numpy_first = [int(x) for x in raw]
        mine = [philox4x32_10_correct([0, 0, 0, 0], [0, 0]) for _ in range(1)]
        w = mine[0]
        print("numpy counter=[0,0,0,0] key=[0,0] ->", [hex(x) for x in numpy_first])
        print("mine v0,v1,v2,v3                    ->", [hex(x) for x in w])
        cands = {
            "(v0<<32)|v1": (w[0] << 32) | w[1],
            "(v1<<32)|v0": (w[1] << 32) | w[0],
            "(v2<<32)|v3": (w[2] << 32) | w[3],
            "(v3<<32)|v2": (w[3] << 32) | w[2],
        }
        for name, val in cands.items():
            print(f"  {name} = {hex(val)}", "<== MATCH" if val == numpy_first[0] else "")
        if any(v == numpy_first[0] for v in cands.values()):
            print("numpy cross-check PASSED")
        else:
            print("numpy cross-check FAILED — do not trust vectors", file=sys.stderr)
        numpy_ok = True

    # ---- 2. Emit a vector table for the Rust tests ----
    cases = [
        ([0, 0, 0, 0], [0, 0]),
        ([0, 0, 0, 0], [1, 2]),
        ([1, 0, 0, 0], [0, 0]),
        ([0xDEADBEEF, 0x12345678, 0, 0], [0xDEAD, 0xBEEF]),
        ([0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF], [0xFFFFFFFF, 0xFFFFFFFF]),
        ([7, 0, 0, 0], [3, 1]),
    ]
    table = {"philox4x32_10": [], "stream_key0": []}
    for ctr, key in cases:
        r = philox4x32_10_correct(ctr, key)
        table["philox4x32_10"].append(
            {"ctr": ctr, "key": key, "out": r}
        )
    # A 32-block stream with key (0,0) starting at counter 0: used by the Rust
    # counter-RNG test (CounterRng over 128 bytes).
    table["stream_key0"] = [
        {"block": i, "out": o} for i, o in enumerate(stream([0, 0, 0, 0], [0, 0], 32))
    ]
    print(json.dumps(table, indent=1))
