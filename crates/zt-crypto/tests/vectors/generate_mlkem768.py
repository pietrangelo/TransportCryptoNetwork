#!/usr/bin/env python3
"""Regenerates mlkem768.txt, the ML-KEM-768 known-answer vectors of tests/kem.rs.

Review 0008, finding A8-12: the vectors must be re-derivable from their published sources.

Usage (Python 3.8 or later, standard library only; run it with -I so that nothing from the
current directory is imported):

    curl -sSfLO https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json
    mv internalProjection.json keygen.json
    curl -sSfLO https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json
    mv internalProjection.json encapdecap.json
    curl -sSfL -o wycheproof.json https://raw.githubusercontent.com/C2SP/wycheproof/main/testvectors_v1/mlkem_768_test.json
    python3 -I generate_mlkem768.py keygen.json encapdecap.json wycheproof.json 2026-11-09 > mlkem768.txt

The script refuses sources whose SHA-256 differs from the pinned one: a changed upstream file
is a deliberate update (new digests here, then a review of the diff), never a silent one.

Selection:
- ACVP keyGen, ML-KEM-768 group: every test (`keygen`).
- ACVP encapDecap, ML-KEM-768 `encapsulation` group: every test (`encap`).
- ACVP encapDecap, ML-KEM-768 `encapsulationKeyCheck` group: every test (`ekcheck`).
- Wycheproof ML-KEM-768: every test that starts from a seed, except the "Private key too
  short/long" ones (TCN never parses an expanded decapsulation key) and only the first ten of
  the hundred "official round 3 seeds" vectors, to keep the file small (`decap`).
The ACVP decapsulation groups use expanded decapsulation keys and are not used, for the same
reason.
"""

import hashlib
import json
import sys

PINNED = {
    "keygen": "d7a62a2c3476957f56dd8d24f9004ea6776ccfe995ffe71a65bb9506dc9c7b1b",
    "encapdecap": "a556952ce869bb89c3a3196a701dad89647c193a34c86eafb61a9d710d5b810f",
    "wycheproof": "c59c067ae794c343df575dd90f6f7458f51881b11a22d6e9d8677c8d9ee21e90",
}

PARAMETER_SET = "ML-KEM-768"
ROUND3_SEEDS_KEPT = 10
SKIPPED_COMMENTS = ("Private key too short", "Private key too long")


def load(path, name):
    with open(path, "rb") as f:
        raw = f.read()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PINNED[name]:
        sys.exit(f"{path}: sha256 {digest}, expected {PINNED[name]} for {name}")
    return json.loads(raw)


def sha256_hex(hex_text):
    return hashlib.sha256(bytes.fromhex(hex_text)).hexdigest()


def group(document, function=None):
    for g in document["testGroups"]:
        if g.get("parameterSet") == PARAMETER_SET and g.get("function") == function:
            return g["tests"]
    sys.exit(f"no {PARAMETER_SET} group with function {function}")


def main(argv):
    if len(argv) != 5:
        sys.exit(__doc__)
    keygen = load(argv[1], "keygen")
    encapdecap = load(argv[2], "encapdecap")
    wycheproof = load(argv[3], "wycheproof")
    fetched = argv[4]

    out = [
        "# ML-KEM-768 known-answer vectors for crates/zt-crypto/tests/kem.rs. Generated, do not edit.",
        f"# Sources (fetched {fetched}):",
        "#   NIST ACVP-Server gen-val/json-files/ML-KEM-keyGen-FIPS203/internalProjection.json",
        f"#     sha256 {PINNED['keygen']} (public domain)",
        "#   NIST ACVP-Server gen-val/json-files/ML-KEM-encapDecap-FIPS203/internalProjection.json",
        f"#     sha256 {PINNED['encapdecap']} (public domain)",
        "#   C2SP Wycheproof testvectors_v1/mlkem_768_test.json",
        f"#     sha256 {PINNED['wycheproof']} (Apache-2.0)",
        "# Long outputs are stored as SHA-256 digests to keep the file small.",
        "# keygen <tcId> <d> <z> <sha256(ek)>",
        "# encap <tcId> <ek> <m> <sha256(c)> <k>",
        "# ekcheck <tcId> <ek> <valid:0|1>",
        "# decap <tcId> <seed d||z> <sha256(ek)> <c> <K> <valid|invalid>",
    ]

    # ACVP keyGen has no `function` field.
    for t in group(keygen):
        out.append(f"keygen {t['tcId']} {t['d']} {t['z']} {sha256_hex(t['ek'])}")
    for t in group(encapdecap, "encapsulation"):
        out.append(f"encap {t['tcId']} {t['ek']} {t['m']} {sha256_hex(t['c'])} {t['k']}")
    for t in group(encapdecap, "encapsulationKeyCheck"):
        out.append(f"ekcheck {t['tcId']} {t['ek']} {1 if t['testPassed'] else 0}")

    round3 = 0
    for g in wycheproof["testGroups"]:
        if g.get("parameterSet") != PARAMETER_SET:
            continue
        for t in g["tests"]:
            comment = t.get("comment", "")
            if comment.startswith(SKIPPED_COMMENTS) or "seed" not in t:
                continue
            if comment.startswith("Test vector based on official round 3 seeds"):
                round3 += 1
                if round3 > ROUND3_SEEDS_KEPT:
                    continue
            key = t["K"] if t["K"] else "-"
            out.append(
                f"decap {t['tcId']} {t['seed']} {sha256_hex(t['ek'])} {t['c']} {key} {t['result']}"
            )

    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main(sys.argv)
