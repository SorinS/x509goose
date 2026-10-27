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

    python3 scripts/pq_vectors.py
"""

import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(__file__))
from gen_vectors import PKI, ERR, NOW, CA, LEAF, ossl  # noqa: E402

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
DSA_SIZES = [(1024, 160), (2048, 224), (2048, 256), (3072, 256)]


class PQ(PKI):
    def key(self, name, kind):
        out = self.path(f"{name}.key")
        if kind.startswith("mldsa"):
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
        # Ed25519 and ML-DSA sign without a separate digest.
        k = getattr(self, "kind", {}).get(name, "")
        return k == "ed25519" or k.startswith("mldsa")


def der(pki, name):
    return pki.der[name].hex()


def main():
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
    with open(os.path.join(ROOT, "test", "vectors", "pq.txt"), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
