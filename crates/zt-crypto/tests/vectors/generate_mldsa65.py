#!/usr/bin/env python3
"""Regenerates mldsa65.txt, the ML-DSA-65 known-answer vectors of tests/mldsa.rs (PQ-AUTH).

Decision D11 / finding AP-5 of review 0007: the ML-DSA verifier of the fleet must pass the
Wycheproof and NIST ACVP vectors, and the vectors must be re-derivable from their sources.

Usage (Python 3.8 or later, standard library only; run it with -I so that nothing from the
current directory is imported):

    curl -sSfL -o keygen.json https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json
    curl -sSfL -o verify.json https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/mldsa_65_verify_test.json
    curl -sSfL -o sign.json https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/mldsa_65_sign_seed_test.json
    python3 -I generate_mldsa65.py keygen.json verify.json sign.json 2026-11-09 > mldsa65.txt

The script refuses sources whose SHA-256 differs from the pinned one: a changed upstream file
is a deliberate update (new digests here, then a review of the diff), never a silent one.

Selection (to keep the file small; every invalid case that exercises parsing is kept):
- ACVP keyGen, ML-DSA-65 group: every test (`keygen <seed> <sha256(pk)>`).
- Wycheproof verify: every test of every group with a public key of the right length, except
  that the long "ZeroPublicKey" and "InfinityNormViolation" boundary groups are cut to their
  first 8 tests (`pk <hex>` then `verify <tcId> <valid|invalid> <ctx> <msg> <sig>`).
  Groups whose key has the wrong length become `badpk` lines (the verifier must refuse).
- Wycheproof sign_seed: the deterministic (`rnd` = 0) tests over a message, without an
  explicit `rnd`, first 12 (`sign <seed> <ctx> <msg> <sha256(sig)>`).
`-` stands for an empty field.
"""

import hashlib
import json
import sys

PINNED = {
    "keygen": "e67ee6540d40e11506c3c4e3b1f79fc1cefcd49820db99fc61f87cc8ba463baf",
    "verify": "1ca235f61928421a173a171780beb00264ae9155dc33c52a11e1766cc7979034",
    "sign": "e26b2bb9ab8d45ed570ba6828c7e40b6fa3e1545bb8bc2c449c77531760133e0",
}
PK_HEX_LEN = 1952 * 2


def load(path, name):
    raw = open(path, "rb").read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PINNED[name]:
        sys.exit(f"{name}: sha256 {digest} is not the pinned one")
    return json.loads(raw)


def field(v):
    return v if v else "-"


def main():
    keygen, verify, sign = (load(p, n) for p, n in zip(sys.argv[1:4], PINNED))
    date = sys.argv[4]
    out = [
        "# ML-DSA-65 known-answer vectors for crates/zt-crypto/tests/mldsa.rs. Generated, do not edit.",
        f"# Sources (fetched {date}):",
        "#   NIST ACVP-Server gen-val/json-files/ML-DSA-keyGen-FIPS204/internalProjection.json",
        f"#     sha256 {PINNED['keygen']} (public domain)",
        "#   C2SP Wycheproof testvectors_v1/mldsa_65_verify_test.json",
        f"#     sha256 {PINNED['verify']} (Apache-2.0)",
        "#   C2SP Wycheproof testvectors_v1/mldsa_65_sign_seed_test.json",
        f"#     sha256 {PINNED['sign']} (Apache-2.0)",
    ]
    for group in keygen["testGroups"]:
        if group.get("parameterSet") != "ML-DSA-65":
            continue
        for t in group["tests"]:
            pk = bytes.fromhex(t["pk"])
            out.append(f"keygen {t['seed'].lower()} {hashlib.sha256(pk).hexdigest()}")
    for group in verify["testGroups"]:
        pk = group["publicKey"].lower()
        tests = group["tests"]
        flags = {f for t in tests for f in t.get("flags", [])}
        if len(pk) != PK_HEX_LEN:
            for t in tests:
                out.append(f"badpk {t['tcId']} {field(pk)} {field(t.get('msg', ''))} {t['sig']}")
            continue
        if {"ZeroPublicKey", "InfinityNormViolation"} & flags:
            tests = tests[:8]
        out.append(f"pk {pk}")
        for t in tests:
            result = "valid" if t["result"] == "valid" else "invalid"
            out.append(
                f"verify {t['tcId']} {result} {field(t.get('ctx', ''))} "
                f"{field(t.get('msg', ''))} {field(t['sig'])}"
            )
    n = 0
    for group in sign["testGroups"]:
        seed = group.get("privateSeed", "")
        if len(seed) != 64:
            continue
        for t in group["tests"]:
            if "msg" not in t or "rnd" in t or t["result"] != "valid" or n >= 12:
                continue
            sig = bytes.fromhex(t["sig"])
            out.append(
                f"sign {seed.lower()} {field(t.get('ctx', ''))} {field(t['msg'])} "
                f"{hashlib.sha256(sig).hexdigest()}"
            )
            n += 1
    print("\n".join(out))


main()
