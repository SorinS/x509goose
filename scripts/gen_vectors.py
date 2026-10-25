#!/usr/bin/env python3
"""Make the x509 test vectors with openssl.

test/vectors/certs.txt: a small PKI built with openssl, covering each
signature algorithm the package verifies (RSA PKCS #1 v1.5 with SHA-256,
384 and 512, RSA-PSS, ECDSA on P-256 and P-384, Ed25519) and one
certificate for each way a path can fail. Per certificate:

    cert <name> <hex DER>
    subject|issuer <name> <RFC 4514 text, from openssl -nameopt RFC2253>
    serial <name> <hex>
    dates <name> <notBefore> <notAfter>          (seconds since 1970)
    dns <name> <dNSName>...                       ip <name> <hex>...
    ca <name> <0|1> <pathLen or -1>

then the path cases, each also run through `openssl verify` (which must
agree on pass or fail):

    case <label> <leaf> <intermediates,...|-> <roots,...> <now> <host|-> <expected error>

test/vectors/roots.pem and roots.txt: the system's root store
(/etc/ssl/cert.pem) with openssl's subject for each, and whether its
self-signature is one this package can check.

    python3 scripts/gen_vectors.py
"""

import calendar
import os
import re
import shutil
import subprocess
import tempfile
import time

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
NOW = 1793000000           # 2026-10-26, fixed so the vectors never change meaning
DAY = 86400

ERR = {"ok": 0, "malformed": 1, "unsupported": 2, "bad_signature": 3, "expired": 4,
       "not_yet_valid": 5, "unknown_issuer": 6, "not_ca": 7, "path_length": 8,
       "key_usage": 9, "eku": 10, "hostname": 11, "critical": 12, "name_constraints": 14,
       "policy": 15, "revoked": 16, "revocation_unknown": 17}
POL = "1.3.6.1.4.1.55555."
ANY = "2.5.29.32.0"


def ossl(*args, input=None, check=True):
    p = subprocess.run(["openssl", *args], input=input, capture_output=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)}: {p.stderr.decode()}")
    return p


def gtime(t):
    return time.strftime("%Y%m%d%H%M%SZ", time.gmtime(t))


class PKI:
    def __init__(self, tmp):
        self.tmp = tmp
        self.der = {}

    def path(self, n):
        return os.path.join(self.tmp, n)

    def key(self, name, kind):
        args = {"rsa": ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
                "p256": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"],
                "p384": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"],
                "p521": ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"],
                "ed25519": ["-algorithm", "ED25519"]}[kind]
        ossl("genpkey", *args, "-out", self.path(f"{name}.key"))

    def cert(self, name, kind, subject, issuer=None, ext="", digest="sha256", pss=False,
             start=NOW - 30 * DAY, end=NOW + 3650 * DAY):
        """Makes name.pem, signed by issuer (itself when None)."""
        self.key(name, kind)
        with open(self.path(f"{name}.ext"), "w") as f:
            f.write((ext if "\n" in ext else ext.replace(";", "\n")) + "\n")
        ossl("req", "-new", "-key", self.path(f"{name}.key"), "-subj", subject,
             "-out", self.path(f"{name}.csr"))
        signer = issuer or name
        sign = ["-CA", self.path(f"{issuer}.pem"), "-CAkey", self.path(f"{issuer}.key")] if issuer \
            else ["-key", self.path(f"{name}.key")]
        opts = []
        if kind != "ed25519" and not self.is_ed(signer):
            opts += [f"-{digest}"]
        if pss:
            opts += ["-sigopt", "rsa_padding_mode:pss", "-sigopt", "rsa_pss_saltlen:digest"]
        ossl("x509", "-req", "-in", self.path(f"{name}.csr"), *sign, *opts,
             "-not_before", gtime(start), "-not_after", gtime(end),
             "-set_serial", str(0x1000 + len(self.der)), "-extfile", self.path(f"{name}.ext"),
             "-out", self.path(f"{name}.pem"))
        self.der[name] = ossl("x509", "-in", self.path(f"{name}.pem"), "-outform", "DER").stdout
        self.kind = getattr(self, "kind", {})
        self.kind[name] = kind

    def crl(self, name, issuer, revoked=(), start=NOW - DAY, end=NOW + 30 * DAY, md="sha256"):
        """name.pem: a CRL from issuer listing the named certificates."""
        db = self.path(f"{name}.idx")
        with open(db, "w") as f:
            for r, reason in revoked:
                serial = format(0x1000 + list(self.der).index(r), "X")
                if len(serial) % 2:
                    serial = "0" + serial
                f.write(f"R\t{time.strftime('%y%m%d%H%M%SZ', time.gmtime(NOW + 3650 * DAY))}\t"
                        f"{time.strftime('%y%m%d%H%M%SZ', time.gmtime(NOW - 2 * DAY))},{reason}\t{serial}\tunknown\t/CN=x\n")
        with open(self.path(f"{name}.num"), "w") as f:
            f.write("01\n")
        with open(self.path(f"{name}.cnf"), "w") as f:
            f.write(f"[ca]\ndefault_ca = d\n[d]\ndatabase = {db}\ncrlnumber = {self.path(name + '.num')}\n"
                    f"default_md = {md}\n")
        ossl("ca", "-gencrl", "-config", self.path(f"{name}.cnf"), "-keyfile", self.path(f"{issuer}.key"),
             "-cert", self.path(f"{issuer}.pem"), "-crl_lastupdate", gtime(start), "-crl_nextupdate", gtime(end),
             "-out", self.path(f"{name}.pem"))
        self.crls = getattr(self, "crls", {})
        self.crls[name] = ossl("crl", "-in", self.path(f"{name}.pem"), "-outform", "DER").stdout

    def is_ed(self, name):
        return getattr(self, "kind", {}).get(name) == "ed25519"


CA = "basicConstraints=critical,CA:TRUE;keyUsage=critical,keyCertSign,cRLSign"
LEAF = ("basicConstraints=critical,CA:FALSE;keyUsage=critical,digitalSignature;"
        "extendedKeyUsage=serverAuth;subjectAltName=DNS:example.com,DNS:*.example.com,IP:192.0.2.1")


def fields(pki, name):
    pem = pki.path(f"{name}.pem")
    out = ossl("x509", "-in", pem, "-noout", "-subject", "-issuer", "-serial", "-startdate",
               "-enddate", "-nameopt", "RFC2253,-esc_msb").stdout.decode()
    v = dict(line.split("=", 1) for line in out.splitlines())
    lines = [f"cert {name} {pki.der[name].hex()}",
             f"subject {name} {v['subject'] or '-'}", f"issuer {name} {v['issuer']}",
             f"serial {name} {v['serial']}"]
    def ts(s):
        return calendar.timegm(time.strptime(s.replace(" GMT", ""), "%b %d %H:%M:%S %Y"))
    lines.append(f"dates {name} {ts(v['notBefore'])} {ts(v['notAfter'])}")
    text = ossl("x509", "-in", pem, "-noout", "-ext", "subjectAltName,basicConstraints",
                check=False).stdout.decode()
    dns = re.findall(r"DNS:([^,\s]+)", text)
    ips = ["".join(f"{int(x):02x}" for x in ip.split(".")) for ip in re.findall(r"IP Address:([0-9.]+)", text)]
    lines.append(f"dns {name} {' '.join(dns) or '-'}")
    lines.append(f"ip {name} {' '.join(ips) or '-'}")
    ca = "CA:TRUE" in text
    pl = re.search(r"pathlen:(\d+)", text)
    lines.append(f"ca {name} {int(ca)} {pl.group(1) if pl else -1}")
    return lines


def main():
    lines, cases = [], []
    with tempfile.TemporaryDirectory() as tmp:
        k = PKI(tmp)
        k.cert("root_rsa", "rsa", "/C=US/O=Goose Test/CN=Goose Root R1", ext=CA)
        k.cert("root_p384", "p384", "/C=US/O=Goose Test/CN=Goose Root E1", ext=CA, digest="sha384")
        k.cert("root_ed", "ed25519", "/O=Goose Test/CN=Goose Root Ed", ext=CA)
        k.cert("int_ec", "p384", "/O=Goose Test/CN=Goose Issuing E1", "root_rsa",
               CA + ";basicConstraints=critical,CA:TRUE,pathlen:0".replace("basicConstraints=critical,CA:TRUE;", ""),
               digest="sha384")
        k.cert("int_pss", "rsa", "/O=Goose Test/CN=Goose Issuing PSS", "root_rsa",
               "basicConstraints=critical,CA:TRUE;keyUsage=critical,keyCertSign", pss=True)
        k.cert("int_noca", "p256", "/O=Goose Test/CN=Not A CA", "root_rsa",
               "basicConstraints=critical,CA:FALSE;keyUsage=critical,keyCertSign")
        k.cert("int_noku", "p256", "/O=Goose Test/CN=CA Without keyCertSign", "root_rsa",
               "basicConstraints=critical,CA:TRUE;keyUsage=critical,digitalSignature")
        k.cert("int_client", "p256", "/O=Goose Test/CN=Client Only CA", "root_rsa",
               CA + ";extendedKeyUsage=clientAuth")
        k.cert("int_sub", "p256", "/O=Goose Test/CN=Below Pathlen Zero", "int_ec", CA, digest="sha384")
        k.cert("leaf_ec", "p256", "/CN=example.com", "int_ec", LEAF, digest="sha384")
        k.cert("leaf_pss", "rsa", "/C=US/O=Ex\\, Inc./CN=example.com", "int_pss", LEAF,
               digest="sha512", pss=True)
        k.cert("leaf_ed", "ed25519", "/CN=example.com", "root_ed", LEAF)
        k.cert("leaf_p384", "p384", "/CN=example.com", "root_p384", LEAF, digest="sha512")
        k.cert("leaf_rsa384", "rsa", "/CN=example.com", "root_rsa", LEAF, digest="sha384")
        k.cert("int_p521", "p521", "/O=Goose Test/CN=Goose Issuing P-521", "root_p384", CA, digest="sha384")
        k.cert("leaf_p521", "p256", "/CN=example.com", "int_p521", LEAF, digest="sha512")
        k.cert("leaf_expired", "p256", "/CN=example.com", "int_ec", LEAF, digest="sha384",
               start=NOW - 400 * DAY, end=NOW - 30 * DAY)
        k.cert("leaf_future", "p256", "/CN=example.com", "int_ec", LEAF, digest="sha384",
               start=NOW + 30 * DAY)
        k.cert("leaf_client", "p256", "/CN=example.com", "int_ec",
               LEAF.replace("serverAuth", "clientAuth"), digest="sha384")
        k.cert("leaf_noca", "p256", "/CN=example.com", "int_noca", LEAF)
        k.cert("leaf_noku", "p256", "/CN=example.com", "int_noku", LEAF)
        k.cert("leaf_via_client", "p256", "/CN=example.com", "int_client", LEAF)
        k.cert("leaf_deep", "p256", "/CN=example.com", "int_sub", LEAF)
        k.cert("leaf_critical", "p256", "/CN=example.com", "int_ec",
               LEAF + ";1.2.3.4.5=critical,ASN1:NULL", digest="sha384")
        k.cert("leaf_ip_only", "p256", "/CN=ip", "int_ec",
               LEAF.replace("DNS:example.com,DNS:*.example.com,", ""), digest="sha384")
        # A signature changed by one bit, and a copy of a root with another key.
        bad = bytearray(k.der["leaf_ec"])
        bad[-1] ^= 1
        k.der["leaf_badsig"] = bytes(bad)
        with open(k.path("leaf_badsig.pem"), "wb") as f:
            f.write(ossl("x509", "-inform", "DER", input=bytes(bad)).stdout)
        k.cert("root_rsa_other", "rsa", "/C=US/O=Goose Test/CN=Goose Root R1", ext=CA)

        # Name constraints.
        k.cert("int_nc", "p256", "/O=Goose Test/CN=Constrained CA", "root_rsa",
               "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
               "nameConstraints=critical,permitted;DNS:example.com,permitted;IP:192.0.2.0/255.255.255.0,"
               "permitted;email:.example.com,permitted;dirName:dir_sect,excluded;DNS:bad.example.com\n"
               "[dir_sect]\nO=Goose Test\n")
        def nc_leaf(name, subject, san):
            k.cert(name, "p256", subject, "int_nc",
                   "basicConstraints=critical,CA:FALSE;keyUsage=critical,digitalSignature;"
                   f"extendedKeyUsage=serverAuth;subjectAltName={san}")
        nc_leaf("leaf_nc_ok", "/O=Goose Test/CN=www.example.com", "DNS:www.example.com,IP:192.0.2.7,email:a@mail.example.com")
        nc_leaf("leaf_nc_dns", "/O=Goose Test/CN=www.example.org", "DNS:www.example.org")
        nc_leaf("leaf_nc_excluded", "/O=Goose Test/CN=x.bad.example.com", "DNS:x.bad.example.com")
        nc_leaf("leaf_nc_ip", "/O=Goose Test/CN=www.example.com", "DNS:www.example.com,IP:198.51.100.1")
        nc_leaf("leaf_nc_dn", "/O=Other/CN=www.example.com", "DNS:www.example.com")
        nc_leaf("leaf_nc_email", "/O=Goose Test/CN=www.example.com", "DNS:www.example.com,email:a@example.org")

        # Policies.
        def pol_leaf(name, issuer, policies=None):
            ext = LEAF.replace("DNS:example.com,DNS:*.example.com,", "DNS:example.com,")
            if policies:
                ext += ";certificatePolicies=" + ",".join(policies)
            k.cert(name, "p256", "/CN=example.com", issuer, ext)
        k.cert("int_pol", "p256", "/O=Goose Test/CN=Policy CA", "root_rsa",
               CA + f";certificatePolicies={POL}1,{POL}2")
        pol_leaf("leaf_pol1", "int_pol", [POL + "1"])
        pol_leaf("leaf_nopol", "int_pol")
        k.cert("int_req", "p256", "/O=Goose Test/CN=Explicit Policy CA", "root_rsa",
               CA + f";certificatePolicies={ANY};policyConstraints=requireExplicitPolicy:0")
        pol_leaf("leaf_req_none", "int_req")
        pol_leaf("leaf_req_pol", "int_req", [POL + "1"])
        k.cert("int_map", "p256", "/O=Goose Test/CN=Mapping CA", "root_rsa",
               CA + f";certificatePolicies={POL}1;policyMappings={POL}1:{POL}7")
        pol_leaf("leaf_map", "int_map", [POL + "7"])
        k.cert("int_anyinh", "p256", "/O=Goose Test/CN=Inhibit Any CA", "root_rsa",
               CA + f";certificatePolicies={ANY};inhibitAnyPolicy=0")
        pol_leaf("leaf_any_inh", "int_anyinh", [ANY])
        k.cert("int_any", "p256", "/O=Goose Test/CN=Any Policy CA", "root_rsa",
               CA + f";certificatePolicies={ANY}")
        pol_leaf("leaf_any", "int_any", [ANY])

        # Revocation.
        k.cert("leaf_revoked", "p256", "/CN=example.com", "int_ec", LEAF, digest="sha384")
        k.cert("int_ec_fake", "p384", "/O=Goose Test/CN=Goose Issuing E1", "root_rsa", CA, digest="sha384")
        k.crl("crl_int", "int_ec", [("leaf_revoked", "keyCompromise")], md="sha384")
        k.crl("crl_int_expired", "int_ec", [], start=NOW - 60 * DAY, end=NOW - 30 * DAY, md="sha384")
        k.crl("crl_int_fake", "int_ec_fake", [], md="sha384")
        k.crl("crl_root", "root_rsa", [])
        k.crl("crl_root_revokes_int", "root_rsa", [("int_ec", "cACompromise")])

        for name in k.der:
            if name != "leaf_badsig":
                lines += fields(k, name)
        lines.append(f"cert leaf_badsig {k.der['leaf_badsig'].hex()}")
        for name, der in k.crls.items():
            lines.append(f"crl {name} {der.hex()}")
            t = ossl("crl", "-in", k.path(f"{name}.pem"), "-noout", "-text").stdout.decode()
            def ts(label):
                m = re.search(label + r": (\w+ +\d+ [\d:]+ \d+) GMT", t)
                return calendar.timegm(time.strptime(m.group(1), "%b %d %H:%M:%S %Y"))
            n = len(re.findall(r"Serial Number:", t))
            num = int(re.search(r"X509v3 CRL Number: *\n *(\w+)", t).group(1), 16)
            lines.append(f"crlinfo {name} {ts('Last Update')} {ts('Next Update')} {n} {num}")

        def case(label, leaf, inters, roots, host, want, now=NOW):
            # openssl's verdict, which must agree on pass or fail.
            with open(k.path("ca.pem"), "w") as f:
                for r in roots:
                    f.write(open(k.path(f"{r}.pem")).read())
            with open(k.path("un.pem"), "w") as f:
                for i in inters:
                    f.write(open(k.path(f"{i}.pem")).read())
            args = ["verify", "-attime", str(now), "-purpose", "sslserver", "-CAfile", k.path("ca.pem"),
                    "-x509_strict"]
            if inters:
                args += ["-untrusted", k.path("un.pem")]
            if host != "-":
                if re.fullmatch(r"[0-9.]+", host):
                    args += ["-verify_ip", host]
                else:
                    args += ["-verify_hostname", host]
            p = ossl(*args, k.path(f"{leaf}.pem"), check=False)
            openssl_ok = p.returncode == 0
            assert openssl_ok == (want == "ok"), (label, p.stdout, p.stderr)
            cases.append(f"case {label} {leaf} {','.join(inters) or '-'} {','.join(roots)} {now} {host} {ERR[want]}")

        case("ec_chain", "leaf_ec", ["int_ec"], ["root_rsa"], "example.com", "ok")
        case("wildcard", "leaf_ec", ["int_ec"], ["root_rsa"], "www.example.com", "ok")
        case("ip", "leaf_ec", ["int_ec"], ["root_rsa"], "192.0.2.1", "ok")
        case("no_host_check", "leaf_ec", ["int_ec"], ["root_rsa"], "-", "ok")
        case("pss_chain", "leaf_pss", ["int_pss"], ["root_rsa"], "example.com", "ok")
        case("ed25519", "leaf_ed", [], ["root_ed"], "example.com", "ok")
        case("p384_sha512", "leaf_p384", [], ["root_p384"], "example.com", "ok")
        case("rsa_sha384", "leaf_rsa384", [], ["root_rsa"], "example.com", "ok")
        case("p521_issuer", "leaf_p521", ["int_p521"], ["root_p384"], "example.com", "ok")
        case("extra_intermediates", "leaf_ec", ["int_noca", "int_pss", "int_ec"], ["root_ed", "root_rsa"],
             "example.com", "ok")
        case("wrong_root_key", "leaf_ec", ["int_ec"], ["root_rsa_other"], "example.com", "bad_signature")
        case("two_roots_same_name", "leaf_ec", ["int_ec"], ["root_rsa_other", "root_rsa"], "example.com", "ok")
        case("missing_intermediate", "leaf_ec", [], ["root_rsa"], "example.com", "unknown_issuer")
        case("wrong_root", "leaf_ec", ["int_ec"], ["root_p384"], "example.com", "unknown_issuer")
        case("bad_signature", "leaf_badsig", ["int_ec"], ["root_rsa"], "example.com", "bad_signature")
        case("expired", "leaf_expired", ["int_ec"], ["root_rsa"], "example.com", "expired")
        case("not_yet_valid", "leaf_future", ["int_ec"], ["root_rsa"], "example.com", "not_yet_valid")
        case("chain_expired_later", "leaf_ec", ["int_ec"], ["root_rsa"], "example.com", "expired",
             now=NOW + 3651 * DAY)
        case("wrong_host", "leaf_ec", ["int_ec"], ["root_rsa"], "example.org", "hostname")
        case("wildcard_two_labels", "leaf_ec", ["int_ec"], ["root_rsa"], "a.b.example.com", "hostname")
        case("wildcard_apex", "leaf_ec", ["int_ec"], ["root_rsa"], "com", "hostname")
        case("wrong_ip", "leaf_ec", ["int_ec"], ["root_rsa"], "192.0.2.2", "hostname")
        case("ip_not_dns", "leaf_ip_only", ["int_ec"], ["root_rsa"], "example.com", "hostname")
        case("client_only", "leaf_client", ["int_ec"], ["root_rsa"], "example.com", "eku")
        case("issuer_not_ca", "leaf_noca", ["int_noca"], ["root_rsa"], "example.com", "not_ca")
        case("issuer_no_keycertsign", "leaf_noku", ["int_noku"], ["root_rsa"], "example.com", "key_usage")
        case("issuer_client_eku", "leaf_via_client", ["int_client"], ["root_rsa"], "example.com", "eku")
        case("path_length", "leaf_deep", ["int_sub", "int_ec"], ["root_rsa"], "example.com", "path_length")
        case("unknown_critical", "leaf_critical", ["int_ec"], ["root_rsa"], "example.com", "critical")
        def case2(label, leaf, inters, roots, crls, opts, host, want):
            with open(k.path("ca.pem"), "w") as f:
                for r in roots:
                    f.write(open(k.path(f"{r}.pem")).read())
            with open(k.path("un.pem"), "w") as f:
                for i in inters:
                    f.write(open(k.path(f"{i}.pem")).read())
            with open(k.path("crls.pem"), "w") as f:
                for c in crls:
                    f.write(open(k.path(f"{c}.pem")).read())
            args = ["verify", "-attime", str(NOW), "-purpose", "sslserver", "-CAfile", k.path("ca.pem"),
                    "-x509_strict", "-policy_check"]
            if inters:
                args += ["-untrusted", k.path("un.pem")]
            if crls:
                args += ["-CRLfile", k.path("crls.pem")]
            for o in opts:
                if o == "crl_leaf": args.append("-crl_check")
                elif o == "crl_all": args.append("-crl_check_all")
                elif o == "explicit": args.append("-explicit_policy")
                elif o == "inhibit_map": args.append("-inhibit_map")
                elif o == "inhibit_any": args.append("-inhibit_any")
                elif o.startswith("policy="): args += ["-policy", o[7:]]
            # openssl verify's acceptable set is empty unless given;
            # RFC 5280's default, which the package uses, is anyPolicy.
            if not any(o.startswith("policy=") for o in opts):
                args += ["-policy", ANY]
            if host != "-":
                args += ["-verify_ip" if re.fullmatch(r"[0-9.]+", host) else "-verify_hostname", host]
            p = ossl(*args, k.path(f"{leaf}.pem"), check=False)
            assert (p.returncode == 0) == (want == "ok"), (label, p.stdout, p.stderr)
            cases.append(f"case2 {label} {leaf} {','.join(inters) or '-'} {','.join(roots)} "
                         f"{','.join(crls) or '-'} {','.join(opts) or '-'} {NOW} {host} {ERR[want]}")

        case2("nc_ok", "leaf_nc_ok", ["int_nc"], ["root_rsa"], [], [], "www.example.com", "ok")
        case2("nc_ip_ok", "leaf_nc_ok", ["int_nc"], ["root_rsa"], [], [], "192.0.2.7", "ok")
        case2("nc_dns", "leaf_nc_dns", ["int_nc"], ["root_rsa"], [], [], "www.example.org", "name_constraints")
        case2("nc_excluded", "leaf_nc_excluded", ["int_nc"], ["root_rsa"], [], [], "x.bad.example.com", "name_constraints")
        case2("nc_ip", "leaf_nc_ip", ["int_nc"], ["root_rsa"], [], [], "www.example.com", "name_constraints")
        case2("nc_dn", "leaf_nc_dn", ["int_nc"], ["root_rsa"], [], [], "www.example.com", "name_constraints")
        case2("nc_email", "leaf_nc_email", ["int_nc"], ["root_rsa"], [], [], "www.example.com", "name_constraints")
        case2("pol_default", "leaf_pol1", ["int_pol"], ["root_rsa"], [], [], "example.com", "ok")
        case2("pol_explicit_any", "leaf_pol1", ["int_pol"], ["root_rsa"], [], ["explicit"], "example.com", "ok")
        case2("pol_explicit_match", "leaf_pol1", ["int_pol"], ["root_rsa"], [], ["explicit", f"policy={POL}1"], "example.com", "ok")
        case2("pol_explicit_other", "leaf_pol1", ["int_pol"], ["root_rsa"], [], ["explicit", f"policy={POL}2"], "example.com", "policy")
        case2("pol_other_not_required", "leaf_pol1", ["int_pol"], ["root_rsa"], [], [f"policy={POL}2"], "example.com", "ok")
        case2("pol_leaf_none", "leaf_nopol", ["int_pol"], ["root_rsa"], [], [], "example.com", "ok")
        case2("pol_leaf_none_explicit", "leaf_nopol", ["int_pol"], ["root_rsa"], [], ["explicit"], "example.com", "policy")
        case2("pol_required_by_ca", "leaf_req_none", ["int_req"], ["root_rsa"], [], [], "example.com", "policy")
        case2("pol_required_met", "leaf_req_pol", ["int_req"], ["root_rsa"], [], [], "example.com", "ok")
        case2("pol_mapped", "leaf_map", ["int_map"], ["root_rsa"], [], ["explicit", f"policy={POL}1"], "example.com", "ok")
        case2("pol_mapped_subject_side", "leaf_map", ["int_map"], ["root_rsa"], [], ["explicit", f"policy={POL}7"], "example.com", "policy")
        case2("pol_mapping_inhibited", "leaf_map", ["int_map"], ["root_rsa"], [], ["explicit", f"policy={POL}1", "inhibit_map"], "example.com", "policy")
        case2("pol_any", "leaf_any", ["int_any"], ["root_rsa"], [], ["explicit"], "example.com", "ok")
        case2("pol_any_inhibited_option", "leaf_any", ["int_any"], ["root_rsa"], [], ["explicit", "inhibit_any"], "example.com", "policy")
        case2("pol_any_inhibited_by_ca", "leaf_any_inh", ["int_anyinh"], ["root_rsa"], [], ["explicit"], "example.com", "policy")
        case2("crl_good", "leaf_ec", ["int_ec"], ["root_rsa"], ["crl_int"], ["crl_leaf"], "example.com", "ok")
        case2("crl_revoked", "leaf_revoked", ["int_ec"], ["root_rsa"], ["crl_int"], ["crl_leaf"], "example.com", "revoked")
        case2("crl_revoked_unchecked", "leaf_revoked", ["int_ec"], ["root_rsa"], ["crl_int"], [], "example.com", "ok")
        case2("crl_missing", "leaf_ec", ["int_ec"], ["root_rsa"], [], ["crl_leaf"], "example.com", "revocation_unknown")
        case2("crl_expired", "leaf_ec", ["int_ec"], ["root_rsa"], ["crl_int_expired"], ["crl_leaf"], "example.com", "revocation_unknown")
        case2("crl_wrong_signer", "leaf_ec", ["int_ec"], ["root_rsa"], ["crl_int_fake"], ["crl_leaf"], "example.com", "revocation_unknown")
        case2("crl_all_good", "leaf_ec", ["int_ec"], ["root_rsa"], ["crl_int", "crl_root"], ["crl_all"], "example.com", "ok")
        case2("crl_all_missing_root", "leaf_ec", ["int_ec"], ["root_rsa"], ["crl_int"], ["crl_all"], "example.com", "revocation_unknown")
        case2("crl_all_int_revoked", "leaf_ec", ["int_ec"], ["root_rsa"], ["crl_int", "crl_root_revokes_int"], ["crl_all"], "example.com", "revoked")
        case2("crl_leaf_ignores_int", "leaf_ec", ["int_ec"], ["root_rsa"], ["crl_int", "crl_root_revokes_int"], ["crl_leaf"], "example.com", "ok")
        case("root_as_leaf", "root_rsa", [], ["root_rsa"], "-", "key_usage")   # keyCertSign only

        # The RFC 8448 server certificate and its CertificateVerify, from
        # the tls package's vectors when they are beside this repository.
        rfc = os.path.join(ROOT, "..", "tlsgoose.git", "test", "vectors", "rfc8448.txt")
        if os.path.exists(rfc):
            v = dict(l.split() for l in open(rfc).read().splitlines())
            cert_msg = bytes.fromhex(v["server.construct_a_certificate_handshake_message.certificate"])
            cert = cert_msg[11:11 + int.from_bytes(cert_msg[8:11], "big")]
            cv = bytes.fromhex(v["server.construct_a_certificateverify_handshake_message.certificateverify"])
            import hashlib
            th = hashlib.sha256(b"".join(bytes.fromhex(v[x]) for x in (
                "client.construct_a_clienthello_handshake_message.clienthello",
                "server.construct_a_serverhello_handshake_message.serverhello",
                "server.construct_an_encryptedextensions_handshake_message.encryptedextensions",
                "server.construct_a_certificate_handshake_message.certificate"))).digest()
            content = b" " * 64 + b"TLS 1.3, server CertificateVerify\0" + th
            lines.append(f"rfc8448 {cert.hex()} {cv[4:6].hex()} {content.hex()} {cv[8:].hex()}")

    vec = os.path.join(ROOT, "test", "vectors")
    # Keys in each DER form, made by openssl.
    keys = []
    with tempfile.TemporaryDirectory() as tmp:
        for kind, args in [("rsa", ["-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"]),
                           ("p256", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256"]),
                           ("p384", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384"]),
                           ("p521", ["-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-521"]),
                           ("ed25519", ["-algorithm", "ED25519"])]:
            kp = os.path.join(tmp, kind + ".pem")
            ossl("genpkey", *args, "-out", kp)
            pkcs8 = ossl("pkey", "-in", kp, "-outform", "DER").stdout
            spki = ossl("pkey", "-in", kp, "-pubout", "-outform", "DER").stdout
            native = "-"
            if kind == "rsa":
                native = ossl("rsa", "-in", kp, "-outform", "DER", "-traditional").stdout.hex()
            elif kind.startswith("p"):
                native = ossl("ec", "-in", kp, "-outform", "DER").stdout.hex()
            keys.append(f"key {kind} {pkcs8.hex()} {native} {spki.hex()}")
    with open(os.path.join(vec, "keys.txt"), "w") as f:
        f.write("\n".join(keys) + "\n")
    with open(os.path.join(vec, "certs.txt"), "w") as f:
        f.write("\n".join(lines + cases) + "\n")

    # The system root store.
    src = "/etc/ssl/cert.pem"
    if os.path.exists(src):
        shutil.copy(src, os.path.join(vec, "roots.pem"))
    pems = re.findall(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                      open(os.path.join(vec, "roots.pem")).read(), re.S)
    out = []
    for i, pem in enumerate(pems):
        p = ossl("x509", "-noout", "-subject", "-nameopt", "RFC2253,-esc_msb", "-text",
                 input=pem.encode()).stdout.decode("utf-8")
        subject = p.splitlines()[0][len("subject="):]
        alg = re.search(r"Signature Algorithm: (\S+)", p).group(1)
        checkable = alg in ("sha256WithRSAEncryption", "sha384WithRSAEncryption",
                            "sha512WithRSAEncryption", "ecdsa-with-SHA256", "ecdsa-with-SHA384",
                            "ecdsa-with-SHA512", "ED25519", "rsassaPss")
        out.append(f"root {i} {int(checkable)} {subject.replace(' ', '%20') or '-'}")
    with open(os.path.join(vec, "roots.txt"), "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {len([l for l in lines if l.startswith('cert ')])} certificates, {len(cases)} path cases, "
          f"{len(out)} roots")


if __name__ == "__main__":
    main()
