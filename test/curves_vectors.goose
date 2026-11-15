// brainpool (RFC 5639), Ed448 and X448 (RFC 8410) keys, certificates and
// CMS against vectors/curves.txt (scripts/curves_vectors.py): openssl's
// keys must parse from PKCS #8 (and SEC 1 for brainpool; a OneAsymmetricKey
// v2 with its public key for Ed448 and X448) and marshal back to its bytes
// and SubjectPublicKeyInfo; its certificates must parse and its path cases
// give the result openssl gave; its requests and CRLs must check (each
// CRL revoking the leaf it names); its PKCS #12 files must give the key;
// its SignedData by brainpool and Ed448 signers, and an Ed448 one with
// signed attributes built from openssl's primitives, must verify; its
// EnvelopedData to brainpool recipients, and X448 ones built from its
// primitives (X9.63 KDF, HKDF with a ukm), must decrypt. Then keys made
// here: each signs a certificate that checks (X448 signs nothing), sign
// and encrypt CMS that reads back here, and changed bytes or the wrong
// key are refused. scripts/check_curves.py has openssl check what is
// made here.
import std;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.verify;
import x509.crl;
import x509.ocsp;
import x509.pkcs12;
import x509.cms;
import x509.cms_env;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 20 { print("FAIL ", what); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i + 1 < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn vectors() -> const u8[:] { embed_file("vectors/curves.txt") }

let NOW:     i64         = 1793000000;
let CONTENT: const u8[:] = "Hello from the new curves.\r\n";

// The hex field `field` of the first line starting `tag name`.
fn field(tag: const u8[:], name: const u8[:], field: i64) -> u8[>..] {
    for line in split(vectors(), '\n') {
        let w = words(line);
        if w.len > field && w[0] == tag && w[1] == name { return unhex(w[field]); }
    }
    print("no ", tag, " ", name);
    assert(false);
    var none: u8[>..] = [];
    return none;
}

fn cert_der(name: const u8[:]) -> u8[>..] { field("cert", name, 2) }

fn cert_of(name: const u8[:]) -> x509::Cert {
    let c, e = x509::parse(cert_der(name));
    assert(e == x509::OK);
    return c;
}

fn key_of(name: const u8[:]) -> x509::PrivateKey {
    let k, ok = x509::parse_private_key(field("key", name, 2));
    assert(ok);
    return k;
}

fn bundle(names: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if names == "-" { return out; }
    for n in split(names, ',') { out.append(cert_der(n)); }
    return out;
}

fn kind_of(name: const u8[:]) -> i64 {
    if name == "bp256" { return x509::KEY_EC_BP256; }
    if name == "bp384" { return x509::KEY_EC_BP384; }
    if name == "bp512" { return x509::KEY_EC_BP512; }
    if name == "ed448" { return x509::KEY_ED448; }
    return x509::KEY_X448;
}

// A certificate the key signs for itself, which must check, and changed
// must not; a signature by its default algorithm, which must verify, and
// not over another message.
fn sign_checks(label: const u8[:], k: const x509::PrivateKey&) {
    var t, okt = x509::template("CN=Goose Curves Self,O=Goose", NOW - 3600, NOW + 86400);
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_DIGITAL_SIGNATURE;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    check(str(label, " self-signed made"), e == x509::OK);
    let c, ep = x509::parse(der);
    check(str(label, " self-signed parses"), ep == x509::OK && c.key_type == k.kind);
    check(str(label, " self-signed checks"), x509::check_signature(c, c) == x509::OK);
    var bad: u8[>..] = [];
    bad.append(der);
    bad[c.tbs.end - 5] ^= 1;
    let cb, eb = x509::parse(bad);
    check(str(label, " altered certificate refused"), eb != x509::OK || x509::check_signature(cb, c) == x509::ERR_BAD_SIGNATURE);
    let a, h = x509::default_sig(k.kind);
    let msg = "a message to sign";
    let sig, oksig = x509::sign(k, a, h, msg);
    check(str(label, " signs"), oksig);
    check(str(label, " signature verifies"), x509::verify_with(c, a, h, 0, msg, sig) == x509::OK);
    check(str(label, " other message refused"), x509::verify_with(c, a, h, 0, "another", sig) != x509::OK);
    if a == x509::SIG_ECDSA {
        // TLS 1.3's ECDSA schemes name the NIST curve: a brainpool key is none of them.
        check(str(label, " NIST scheme refused"), x509::verify_scheme(c, x509::ECDSA_SECP256R1_SHA256, msg, sig) != x509::OK &&
              x509::verify_scheme(c, x509::ECDSA_SECP384R1_SHA384, msg, sig) != x509::OK &&
              x509::verify_scheme(c, x509::ECDSA_SECP521R1_SHA512, msg, sig) != x509::OK);
        // RFC 8734's scheme of its own curve verifies; another curve's does not.
        let mine = if k.kind == x509::KEY_EC_BP256 { x509::ECDSA_BRAINPOOLP256R1TLS13_SHA256 }
                   else if k.kind == x509::KEY_EC_BP384 { x509::ECDSA_BRAINPOOLP384R1TLS13_SHA384 }
                   else { x509::ECDSA_BRAINPOOLP512R1TLS13_SHA512 };
        let other = if k.kind == x509::KEY_EC_BP256 { x509::ECDSA_BRAINPOOLP384R1TLS13_SHA384 }
                    else { x509::ECDSA_BRAINPOOLP256R1TLS13_SHA256 };
        check(str(label, " brainpool scheme"), x509::verify_scheme(c, mine, msg, sig) == x509::OK);
        check(str(label, " other brainpool scheme refused"), x509::verify_scheme(c, other, msg, sig) != x509::OK);
    }
    if a == x509::SIG_ED448 {
        check(str(label, " ed448 scheme"), x509::verify_scheme(c, x509::ED448, msg, sig) == x509::OK);
        check(str(label, " ed448 scheme, other message"), x509::verify_scheme(c, x509::ED448, "another", sig) != x509::OK);
        check(str(label, " ed25519 scheme refused"), x509::verify_scheme(c, x509::ED25519, msg, sig) != x509::OK);
    }
}

fn key_lines() {
    for line in split(vectors(), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let label = line[.. ::min(line.len, 24)];
        if w[0] == "eckey" {
            let pkcs8 = unhex(w[2]);
            let sec1 = unhex(w[3]);
            let k, ok = x509::parse_private_key(pkcs8);
            check(str(label, " PKCS #8 parses"), ok && k.kind == kind_of(w[1]) && x509::is_ec(k.kind) && x509::is_brainpool(k.kind));
            check(str(label, " PKCS #8 back"), x509::marshal_pkcs8(k) == pkcs8);
            check(str(label, " SPKI"), x509::marshal_public_key(k) == unhex(w[4]));
            let ks, oks = x509::parse_private_key(sec1);
            check(str(label, " SEC 1 parses"), oks && ks.kind == k.kind && ks.ec_sk == k.ec_sk);
            check(str(label, " SEC 1 back"), x509::marshal_sec1(k) == sec1);
            let spki_der = unhex(w[4]);
            let st, okt = asn1::parse(spki_der);
            let kind, kb, okspki = x509::spki_of(spki_der, st);
            check(str(label, " SPKI kind"), okspki && kind == k.kind);
            sign_checks(label, k);
        } else if w[0] == "okpkey" {
            let pkcs8 = unhex(w[2]);
            let k, ok = x509::parse_private_key(pkcs8);
            let kind = kind_of(w[1]);
            check(str(label, " PKCS #8 parses"), ok && k.kind == kind && k.key448.len == (if kind == x509::KEY_ED448 { 57 } else { 56 }));
            check(str(label, " PKCS #8 back"), x509::marshal_pkcs8(k) == pkcs8);
            check(str(label, " SPKI"), x509::marshal_public_key(k) == unhex(w[3]));
            let kv, okv = x509::parse_private_key(unhex(w[4]));
            check(str(label, " v2 with public key parses"), okv && kv.kind == kind && kv.key448 == k.key448);
            // A key a byte short, and one under the other curve's OID, are refused.
            var short: u8[>..] = [];
            short.append(pkcs8);
            short[1] -= 1;
            short[short.len - k.key448.len - 3] -= 1;      // the outer OCTET STRING
            short[short.len - k.key448.len - 1] -= 1;      // the inner one
            short.pop();
            let ks, okshort = x509::parse_private_key(short);
            check(str(label, " short key refused"), !okshort);
            var other: u8[>..] = [];
            other.append(pkcs8);
            other[11] = if kind == x509::KEY_ED448 { 0x6f } else { 0x71 };   // 1.3.101.113 <-> .111
            let ko, okother = x509::parse_private_key(other);
            check(str(label, " other curve's OID refused"), !okother);
            if kind == x509::KEY_ED448 { sign_checks(label, k); }
        }
    }
}

fn pki_lines() -> i64, i64 {
    var certs = 0;
    var cases = 0;
    for line in split(vectors(), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let label = line[.. ::min(line.len, 30)];
        if w[0] == "cert" {
            let c, e = x509::parse(unhex(w[2]));
            check(str(label, " parses"), e == x509::OK && c.key_type != x509::KEY_UNKNOWN && c.sig_alg != x509::SIG_UNKNOWN);
            certs++;
        } else if w[0] == "case" {
            let now, okn = parse_int(w[5], 10);
            let want, okw = parse_int(w[7], 10);
            let host = if w[6] == "-" { "" } else { w[6] };
            let got = x509::verify_chain(cert_der(w[2]), bundle(w[3]), bundle(w[4]), now, host);
            check(line, got == want);
            if got != want { print("    got ", got, " (", x509::error_text(got), ")"); }
            cases++;
        } else if w[0] == "csr" {
            let r, e = x509::parse_csr(unhex(w[2]));
            check(str(label, " parses"), e == x509::OK);
            check(str(label, " checks"), x509::check_csr(r) == x509::OK);
            check(str(label, " key"), r.key_type == (if w[1] == "csr_bp384" { x509::KEY_EC_BP384 } else { x509::KEY_ED448 }));
            var bad = unhex(w[2]);
            bad[bad.len - 4] ^= 1;
            let rb, eb = x509::parse_csr(bad);
            check(str(label, " changed refused"), eb != x509::OK || x509::check_csr(rb) != x509::OK);
        } else if w[0] == "crl" {
            let crl, e = x509::parse_crl(unhex(w[4]));
            check(str(label, " parses"), e == x509::OK);
            let issuer = cert_of(w[2]);
            check(str(label, " checks"), x509::check_crl(crl, issuer, NOW) == x509::OK);
            let rc = cert_of(w[3]);
            let revoked, reason = x509::crl_lookup(crl, rc);
            check(str(label, " revokes ", w[3]), revoked);
            let other = cert_of(if w[2] == "bp_int" { "leaf_ed448" } else { "ed_other_root" });
            let r2, reason2 = x509::crl_lookup(crl, other);
            check(str(label, " not another"), !r2);
            let wrong = cert_of("ed_other_root");
            check(str(label, " not by another issuer"), x509::check_crl(crl, wrong, NOW) != x509::OK);
        } else if w[0] == "p12" {
            let key, certs_der, e = x509::pkcs12_decode(unhex(w[3]), w[2]);
            check(str(label, " decodes"), e == x509::OK && key[..] == unhex(w[4])[..] && certs_der[..] == cert_der(w[1])[..]);
            let k, okk = x509::parse_private_key(key);
            check(str(label, " key parses"), okk && k.kind == cert_of(w[1]).key_type);
            let k2, c2, e2 = x509::pkcs12_decode(unhex(w[3]), "wrong");
            check(str(label, " wrong password refused"), e2 != x509::OK);
        }
    }
    return certs, cases;
}

fn cms_lines() -> i64 {
    var n = 0;
    for line in split(vectors(), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let label = str(w[0], " ", if w.len > 1 { w[1] } else { "" });
        if w[0] == "signed" {
            let der = unhex(w[3]);
            let sd, e = x509::cms_parse_signed(der);
            check(str(label, " parses"), e == x509::OK);
            let c, ev = x509::cms_verify(sd);
            check(str(label, " verifies"), ev == x509::OK && c.der[..] == cert_der(w[2])[..]);
            if ev != x509::OK { print("    got ", ev, " (", x509::error_text(ev), ")"); }
            check(str(label, " content"), x509::cms_content(sd) == CONTENT);
            // The content changed: the digest (or, without attributes, the signature) no longer checks.
            var bad: u8[>..] = [];
            bad.append(der);
            let at = find(bad[..], CONTENT);
            bad[at] ^= 1;
            let sdb, eb = x509::cms_parse_signed(bad);
            let cb, evb = x509::cms_verify(sdb);
            check(str(label, " changed refused"), evb == x509::ERR_BAD_SIGNATURE);
            n++;
        } else if w[0] == "enveloped" {
            let der = unhex(w[3]);
            let c = cert_of(w[2]);
            let k = key_of(w[2]);
            let pt, ct, e = x509::cms_decrypt(der, k, c);
            check(str(label, " decrypts"), e == x509::OK && pt[..] == CONTENT && ct[..] == x509::OID_CMS_DATA);
            if e != x509::OK { print("    got ", e, " (", x509::error_text(e), ")"); }
            // Another recipient's certificate and key: not a recipient.
            let other = if w[2] == "leaf_x448" { "sm_bp256" } else { "leaf_x448" };
            let ok_key = key_of(other);
            let ok_cert = cert_of(other);
            let p2, c2, e2 = x509::cms_decrypt(der, ok_key, ok_cert);
            check(str(label, " not for another"), e2 == x509::ERR_CMS_NOT_RECIPIENT);
            // The right certificate with the wrong key of its type.
            let wrong = x509::generate_key(k.kind);
            let p3, c3, e3 = x509::cms_decrypt(der, wrong, c);
            check(str(label, " wrong key refused"), e3 == x509::ERR_CMS_DECRYPT);
            n++;
        }
    }
    return n;
}

// What is made here: certificates by each signing kind, CMS signed by
// each and encrypted to brainpool and X448 recipients together.
fn made_here() {
    let ca = x509::generate_key(x509::KEY_EC_BP512);
    var rt, okr = x509::template("CN=Goose Curves Root,O=Goose", NOW - 3600, NOW + 86400);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(ca), "", ca);
    check("brainpool root made", er == x509::OK);
    let kinds: i64[5] = [x509::KEY_EC_BP256, x509::KEY_EC_BP384, x509::KEY_EC_BP512, x509::KEY_ED448, x509::KEY_X448];
    var keys:  x509::PrivateKey[>..] = [];
    var certs: u8[>..]               = [];
    var offs:  i64[>..]              = [0]; // leaf i is certs[offs[i]..offs[i + 1]]
    for kind in kinds {
        let k = x509::generate_key(kind);
        let back, okb = x509::parse_private_key(x509::marshal_pkcs8(k));
        check("generated key round trip", okb && back.kind == kind && x509::marshal_public_key(back) == x509::marshal_public_key(k));
        var t, okt = x509::template("CN=Goose Curves Leaf,O=Goose", NOW - 3600, NOW + 86400);
        t.key_usage = if kind == x509::KEY_X448 { x509::KU_KEY_AGREEMENT }
                      else if kind == x509::KEY_ED448 { x509::KU_DIGITAL_SIGNATURE }
                      else { x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_AGREEMENT };
        t.ext_key_usage = x509::EKU_SERVER_AUTH;
        x509::add_dns(t.san, "www.example.com");
        let leaf, el = x509::create_certificate(t, x509::marshal_public_key(k), root, ca);
        check("leaf made", el == x509::OK);
        check("leaf verifies", x509::verify_chain(leaf, "", root, NOW, "www.example.com") == x509::OK);
        if kind == x509::KEY_X448 {
            // X448 signs nothing.
            let subj, oks = x509::name_der("CN=x448.example.com");
            let csr, ecsr = x509::create_csr(subj, "", k);
            check("X448 request refused", ecsr == x509::ERR_UNSUPPORTED_ALGORITHM);
            var st, okst = x509::template("CN=X448", NOW - 3600, NOW + 86400);
            let selfsigned, es = x509::create_certificate(st, x509::marshal_public_key(k), "", k);
            check("X448 self-signed refused", es == x509::ERR_UNSUPPORTED_ALGORITHM);
        } else {
            sign_checks("generated", k);
            let subj, oks = x509::name_der("CN=csr.example.com");
            let csr, ecsr = x509::create_csr(subj, "", k);
            let r, epr = x509::parse_csr(csr);
            check("request made", ecsr == x509::OK && epr == x509::OK && x509::check_csr(r) == x509::OK && r.key_type == kind);
        }
        if kind == x509::KEY_ED448 {
            // An Ed448 CA's CRL.
            var ct, okct = x509::template("CN=Goose Ed448 CA", NOW - 3600, NOW + 86400);
            ct.is_ca = true;
            ct.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
            let edca, eca = x509::create_certificate(ct, x509::marshal_public_key(k), "", k);
            let empty: x509::Revoked[0] = [];
            let crl, ecrl = x509::create_crl(edca, k, empty, NOW - 60, NOW + 86400, 1);
            let pc, epc = x509::parse_crl(crl);
            let edcert = cert_of_der(edca);
            check("Ed448 CRL", eca == x509::OK && ecrl == x509::OK && epc == x509::OK && pc.sig_alg == x509::SIG_ED448 &&
                  x509::check_crl(pc, edcert, NOW) == x509::OK);
            // And its OCSP response for a certificate it issued.
            var lt, oklt = x509::template("CN=ocsp.example.com", NOW - 3600, NOW + 86400);
            let ol, eol = x509::create_certificate(lt, x509::marshal_public_key(ca), edca, k);
            let olc = cert_of_der(ol);
            ocsp_checks("Ed448 OCSP", olc, edcert, k);
        }
        keys.push(k);
        certs.append(leaf);
        offs.push(certs.len);
    }

    let rootc = cert_of_der(root);
    let leaf0 = cert_of_der(certs[offs[0]..offs[1]]);
    ocsp_checks("brainpoolP512r1 OCSP", leaf0, rootc, ca);

    // SignedData by each signer, read back; changed, refused.
    for i in 4 {
        let c = cert_of_der(certs[offs[i]..offs[i + 1]]);
        let a, h = x509::default_sig(kinds[i]);
        let o = x509::CmsSignOptions { detached: false, signing_time: NOW, capabilities: true, by_key_id: i == 1 };
        let sd, oks = x509::cms_sign_with(x509::OID_CMS_DATA, CONTENT, keys[i], c, root, a, h, o);
        check("signed made", oks);
        let p, e = x509::cms_parse_signed(sd);
        let sc, ev = x509::cms_verify(p);
        check("signed made here verifies", e == x509::OK && ev == x509::OK && sc.der == c.der);
        let t, okt = x509::cms_signing_time(p);
        check("signing time", okt && t == NOW);
        var bad: u8[>..] = [];
        bad.append(sd);
        bad[bad.len - 2] ^= 1;
        let pb, eb = x509::cms_parse_signed(bad);
        let cb, evb = x509::cms_verify(pb);
        check("signed made here, changed, refused", evb == x509::ERR_BAD_SIGNATURE);
    }
    // Ed448's digest: id-shake256-len with 512 (RFC 8419 §3.1).
    let edc = cert_of_der(certs[offs[3]..offs[4]]);
    let o = x509::CmsSignOptions { .. };
    let edsd, okes = x509::cms_sign_with(x509::OID_CMS_DATA, CONTENT, keys[3], edc, "", x509::SIG_ED448, 0, o);
    var want: u8[>..] = [];
    var walg: u8[>..] = [];
    asn1::put_oid(walg, "2.16.840.1.101.3.4.2.18");
    asn1::put_i64(walg, 512);
    asn1::put(want, asn1::SEQUENCE, walg);
    check("Ed448 digest is id-shake256-len", okes && find(edsd[..], want[..]) >= 0);
    // The wrong algorithm for a key is refused, not signed.
    let wr, okw = x509::cms_sign_with(x509::OID_CMS_DATA, CONTENT, keys[3], edc, "", x509::SIG_ED25519, 0, o);
    check("Ed448 key as Ed25519 refused", !okw);

    // EnvelopedData to every agreeing recipient (brainpool and X448), and
    // to X448 by HKDF: each decrypts its own.
    var rcpts: u8[>..] = [];
    for i in 5 { if i != 3 { rcpts.append(certs[offs[i]..offs[i + 1]]); } }
    for hkdf in [false, true] {
        for cipher in [x509::CMS_AES256_CBC, x509::CMS_AES128_GCM] {
            let eo = x509::CmsEncryptOptions { cipher: cipher, x448_hkdf: hkdf, by_key_id: hkdf };
            let env, ee = x509::cms_encrypt(x509::OID_CMS_DATA, CONTENT, rcpts, eo);
            check("enveloped made", ee == x509::OK);
            var hk: u8[>..] = [];
            asn1::put_oid(hk, "1.2.840.113549.1.9.16.3.21");
            check("X448 KDF as asked", (find(env[..], hk[..]) >= 0) == hkdf);
            for i in 5 {
                if i == 3 { continue; }
                let rc = cert_of_der(certs[offs[i]..offs[i + 1]]);
                let pt, ct, e = x509::cms_decrypt(env, keys[i], rc);
                check("enveloped made here decrypts", e == x509::OK && pt[..] == CONTENT);
            }
            let p2, c2, e2 = x509::cms_decrypt(env, keys[3], edc);
            check("Ed448 not a recipient", e2 == x509::ERR_CMS_NOT_RECIPIENT);
        }
    }
    let deo = x509::CmsEncryptOptions { .. };
    let ee448, e448 = x509::cms_encrypt(x509::OID_CMS_DATA, CONTENT, certs[offs[3]..offs[4]], deo);
    check("Ed448 recipient refused", e448 == x509::ERR_UNSUPPORTED_ALGORITHM);
}

// An OCSP response for c signed by its issuer's key, which must check,
// and changed must not.
fn ocsp_checks(label: const u8[:], c: const x509::Cert&, issuer: const x509::Cert&, key: const x509::PrivateKey&) {
    let serial = c.der[c.serial.off..c.serial.end];
    let t = x509::ocsp_template(x509::OCSP_GOOD, serial, NOW - 60);
    let der, e = x509::ocsp_create_response(issuer, issuer, key, t, NOW, false);
    check(str(label, " made"), e == x509::OK);
    let r, er = x509::ocsp_parse_response(der);
    check(str(label, " checks"), er == x509::OK && x509::ocsp_check_response(r, c, issuer, NOW) == x509::OK);
    var bad = copy(der);
    bad[bad.len - 3] ^= 1;
    let rb, erb = x509::ocsp_parse_response(bad);
    check(str(label, " changed refused"), erb != x509::OK || x509::ocsp_check_response(rb, c, issuer, NOW) != x509::OK);
}

fn cert_of_der(der: const u8[:]) -> x509::Cert {
    let c, e = x509::parse(der);
    assert(e == x509::OK);
    return c;
}

fn main() {
    key_lines();
    let certs, cases = pki_lines();
    let cms = cms_lines();
    made_here();
    print(certs, " certificates, ", cases, " path cases, ", cms, " CMS");
    print("curves keys, certificates and CMS: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
