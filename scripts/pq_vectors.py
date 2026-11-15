#!/usr/bin/env python3
"""Make test/vectors/pq.txt: ML-DSA and DSA keys and certificates.

From openssl: ML-DSA-44/65/87 keys in PKCS #8 as seed only, seed with
the expanded key, and the expanded key alone, with their
SubjectPublicKeyInfo; DSA keys of each (L, N) in PKCS #8 and openssl's
"DSA PRIVATE KEY", with theirs; and two hierarchies, an ML-DSA one
(ML-DSA-87 root, ML-DSA-65 intermediate, leaves on ML-DSA-44 and P-256
keys) and a DSA one (signed with SHA-256 and SHA-224), whose path cases
openssl verify must agree with. From Go (tools/govectors, `pq`): an
ML-DSA hierarchy made by crypto/x509 and Go's PKCS #8 for fixed seeds.

    mlkey <set> <seed-only> <seed+expanded> <expanded-only> <spki>
    dsakey <L>_<N> <pkcs8> <traditional> <spki>
    gokey <set> <seed> <pkcs8> <spki>
    cert <name> <hex DER>
    case <label> <leaf> <intermediates,...|-> <roots,...> <now> <host|-> <expected error>

And test/vectors/pq_slhdsa.txt, from openssl: a key of each of the twelve
SLH-DSA sets in PKCS #8 with its SubjectPublicKeyInfo (`slhkey <set>
<pkcs8> <spki>`, the set numbered as bignum.slhdsa numbers it), and three
hierarchies signed with "s" sets, whose signatures are the smallest
(SHA2-128s root, SHAKE-192s intermediate, SHA2-256s and P-256 leaves;
SHAKE-256s root, SHAKE-128s intermediate, SHA2-192s leaf; a SHA2-256s root
over a SHAKE-256f leaf), as cert and case lines. Go has no SLH-DSA, so
nothing comes from it.

    python3 scripts/pq_vectors.py            # both files
    python3 scripts/pq_vectors.py slhdsa     # pq_slhdsa.txt alone
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import PKI, ERR, NOW, CA, LEAF, ossl  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
DSA_SIZES = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]
# The SLH-DSA sets, in bignum.slhdsa's order (1 to 12).
SLHDSA = ["SHA2-128s", "SHA2-128f", "SHA2-192s", "SHA2-192f", "SHA2-256s", "SHA2-256f",
          "SHAKE-128s", "SHAKE-128f", "SHAKE-192s", "SHAKE-192f", "SHAKE-256s", "SHAKE-256f"]


class PQ(PKI):
    def key(self, name, kind):
        out = self.path(f"{name}.key")
        if kind.startswith("slhdsa-"):
            ossl("genpkey", "-algorithm", "SLH-DSA-" + kind[7:], "-out", out)
        elif kind.startswith("mldsa"):
            ossl("genpkey", "-algorithm", "ML-DSA-" + kind[5:], "-out", out)
        elif kind.startswith("dsa"):
            l, n = kind[3:].split("_")
            params = self.path(f"{name}.params")
            ossl("genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", f"dsa_paramgen_bits:{l}",
                 "-pkeyopt", f"dsa_paramgen_q_bits:{n}", "-out", params)
            ossl("genpkey", "-paramfile", params, "-out", out)
        else:
            super().key(name, kind)

    def is_ed(self, name):
        # Ed25519, ML-DSA and SLH-DSA sign without a separate digest.
        k = getattr(self, "kind", {}).get(name, "")
        return k == "ed25519" or k.startswith("mldsa") or k.startswith("slhdsa")


def der(pki, name):
    return pki.der[name].hex()


def path_case(pki, tmp, cases, label, leaf, inters, roots, host, want):
    """Appends a case line, after openssl verify agrees with `want`."""
    p = os.path.join(tmp, "chain.pem")
    with open(p, "w") as f:
        for i in inters:
            f.write(open(pki.path(f"{i}.pem")).read())
    ca = os.path.join(tmp, "roots.pem")
    with open(ca, "w") as f:
        for r in roots:
            f.write(open(pki.path(f"{r}.pem")).read())
    args = ["verify", "-attime", str(NOW), "-CAfile", ca, "-purpose", "sslserver"]
    if inters:
        args += ["-untrusted", p]
    if host != "-":
        args += ["-verify_hostname", host]
    ok = ossl(*args, pki.path(f"{leaf}.pem"), check=False).returncode == 0
    assert ok == (want == "ok"), (label, want)
    cases.append(f"case {label} {leaf} {','.join(inters) or '-'} {','.join(roots)} {NOW} {host} {ERR[want]}")


def slhdsa_lines():
    lines = []
    with tempfile.TemporaryDirectory() as tmp:
        for i, name in enumerate(SLHDSA):
            kp = os.path.join(tmp, f"s{i}.pem")
            ossl("genpkey", "-algorithm", f"SLH-DSA-{name}", "-out", kp)
            pkcs8 = ossl("pkey", "-in", kp, "-outform", "DER").stdout.hex()
            spki = ossl("pkey", "-in", kp, "-pubout", "-outform", "DER").stdout.hex()
            lines.append(f"slhkey {i + 1} {pkcs8} {spki}")
        pki = PQ(tmp)
        pki.cert("slh_root", "slhdsa-SHA2-128s", "/CN=Goose SLH-DSA Root/O=Goose", ext=CA)
        pki.cert("slh_int", "slhdsa-SHAKE-192s", "/CN=Goose SLH-DSA Issuing/O=Goose", "slh_root", ext=CA)
        pki.cert("slh_leaf", "slhdsa-SHA2-256s", "/CN=example.com", "slh_int", ext=LEAF)
        pki.cert("slh_leaf_ec", "p256", "/CN=example.com", "slh_int", ext=LEAF)
        pki.cert("slh_other_root", "slhdsa-SHA2-128s", "/CN=Goose SLH-DSA Issuing/O=Goose", ext=CA)
        pki.cert("slh_root2", "slhdsa-SHAKE-256s", "/CN=Goose SLH-DSA Root 2/O=Goose", ext=CA)
        pki.cert("slh_int2", "slhdsa-SHAKE-128s", "/CN=Goose SLH-DSA Issuing 2/O=Goose", "slh_root2", ext=CA)
        pki.cert("slh_leaf2", "slhdsa-SHA2-192s", "/CN=example.com", "slh_int2", ext=LEAF)
        pki.cert("slh_root3", "slhdsa-SHA2-256s", "/CN=Goose SLH-DSA Root 3/O=Goose", ext=CA)
        pki.cert("slh_leaf3", "slhdsa-SHAKE-256f", "/CN=example.com", "slh_root3", ext=LEAF)
        for name in pki.der:
            lines.append(f"cert {name} {der(pki, name)}")
        cases = []
        path_case(pki, tmp, cases, "slh_dsa_leaf", "slh_leaf", ["slh_int"], ["slh_root"], "www.example.com", "ok")
        path_case(pki, tmp, cases, "p256_leaf_under_slh_dsa", "slh_leaf_ec", ["slh_int"], ["slh_root"], "example.com", "ok")
        path_case(pki, tmp, cases, "slh_dsa_shake_chain", "slh_leaf2", ["slh_int2"], ["slh_root2"], "example.com", "ok")
        path_case(pki, tmp, cases, "slh_dsa_256s_root", "slh_leaf3", [], ["slh_root3"], "example.com", "ok")
        path_case(pki, tmp, cases, "slh_dsa_wrong_issuer_key", "slh_leaf", [], ["slh_other_root"], "-", "bad_signature")
        path_case(pki, tmp, cases, "slh_dsa_no_root", "slh_leaf", ["slh_int"], ["slh_root2"], "-", "unknown_issuer")
        lines += cases
    return lines


def write(name, lines):
    with open(os.path.join(ROOT, "test", "vectors", name), "w") as f:
        f.write("\n".join(lines) + "\n")


def main():
    if sys.argv[1:] != ["slhdsa"]:
        write("pq.txt", pq_lines())
    write("pq_slhdsa.txt", slhdsa_lines())


def pq_lines():
    lines = []
    with tempfile.TemporaryDirectory() as tmp:
        for s in (44, 65, 87):
            kp = os.path.join(tmp, f"k{s}.pem")
            ossl("genpkey", "-algorithm", f"ML-DSA-{s}", "-out", kp)
            forms = [ossl("pkey", "-in", kp, "-provparam", f"ml-dsa.output_formats={f}", "-outform", "DER").stdout.hex()
                     for f in ("seed-only", "seed-priv", "priv-only")]
            spki = ossl("pkey", "-in", kp, "-pubout", "-outform", "DER").stdout.hex()
            lines.append(f"mlkey {s} {' '.join(forms)} {spki}")
        for l, n in DSA_SIZES:
            params = os.path.join(tmp, "p.pem")
            kp = os.path.join(tmp, f"d{l}_{n}.pem")
            ossl("genpkey", "-genparam", "-algorithm", "DSA", "-pkeyopt", f"dsa_paramgen_bits:{l}",
                 "-pkeyopt", f"dsa_paramgen_q_bits:{n}", "-out", params)
            ossl("genpkey", "-paramfile", params, "-out", kp)
            pkcs8 = ossl("pkey", "-in", kp, "-outform", "DER").stdout.hex()
            trad = ossl("dsa", "-in", kp, "-outform", "DER").stdout.hex()
            spki = ossl("pkey", "-in", kp, "-pubout", "-outform", "DER").stdout.hex()
            lines.append(f"dsakey {l}_{n} {pkcs8} {trad} {spki}")

        pki = PQ(tmp)
        pki.cert("ml_root", "mldsa87", "/CN=Goose ML-DSA Root/O=Goose", ext=CA)
        pki.cert("ml_int", "mldsa65", "/CN=Goose ML-DSA Issuing/O=Goose", "ml_root", ext=CA)
        pki.cert("ml_leaf", "mldsa44", "/CN=example.com", "ml_int", ext=LEAF)
        pki.cert("ml_leaf_ec", "p256", "/CN=example.com", "ml_int", ext=LEAF)
        pki.cert("ml_other_root", "mldsa65", "/CN=Goose ML-DSA Issuing/O=Goose", ext=CA)
        pki.cert("dsa_root", "dsa2048_256", "/CN=Goose DSA Root/O=Goose", ext=CA)
        pki.cert("dsa_leaf", "dsa2048_224", "/CN=example.com", "dsa_root", ext=LEAF)
        pki.cert("dsa_leaf224", "p256", "/CN=example.com", "dsa_root", ext=LEAF, digest="sha224")
        pki.cert("dsa_leaf_by_ml", "dsa3072_256", "/CN=example.com", "ml_int", ext=LEAF)
        for name in pki.der:
            lines.append(f"cert {name} {der(pki, name)}")

        cases = []

        def case(label, leaf, inters, roots, host, want):
            p = os.path.join(tmp, "chain.pem")
            with open(p, "w") as f:
                for i in inters:
                    f.write(open(pki.path(f"{i}.pem")).read())
            ca = os.path.join(tmp, "roots.pem")
            with open(ca, "w") as f:
                for r in roots:
                    f.write(open(pki.path(f"{r}.pem")).read())
            args = ["verify", "-attime", str(NOW), "-CAfile", ca, "-purpose", "sslserver"]
            if inters:
                args += ["-untrusted", p]
            if host != "-":
                args += ["-verify_hostname", host]
            ok = ossl(*args, pki.path(f"{leaf}.pem"), check=False).returncode == 0
            assert ok == (want == "ok"), (label, want)
            cases.append(f"case {label} {leaf} {','.join(inters) or '-'} {','.join(roots)} {NOW} {host} {ERR[want]}")

        case("ml_dsa_44_leaf", "ml_leaf", ["ml_int"], ["ml_root"], "www.example.com", "ok")
        case("p256_leaf_under_ml_dsa", "ml_leaf_ec", ["ml_int"], ["ml_root"], "example.com", "ok")
        case("dsa_leaf_under_ml_dsa", "dsa_leaf_by_ml", ["ml_int"], ["ml_root"], "-", "ok")
        case("ml_dsa_wrong_issuer_key", "ml_leaf", [], ["ml_other_root"], "-", "bad_signature")
        case("ml_dsa_no_root", "ml_leaf", ["ml_int"], ["dsa_root"], "-", "unknown_issuer")
        case("dsa_sha256", "dsa_leaf", [], ["dsa_root"], "example.com", "ok")
        case("dsa_sha224", "dsa_leaf224", [], ["dsa_root"], "example.com", "ok")
        lines += cases

    go = subprocess.run([os.path.join(ROOT, "tools", "govectors.sh"), "pq"], capture_output=True, text=True)
    if go.returncode != 0:
        raise RuntimeError(go.stderr)
    lines += go.stdout.splitlines()
    return lines


if __name__ == "__main__":
    main()
