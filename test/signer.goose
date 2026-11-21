// Keys held elsewhere in x509: a CA whose key is only an external_key
// (its SubjectPublicKeyInfo), signing through a signer as a TPM or an HSM
// would: a self-signed root, a certificate under it, a CSR, a CRL, an OCSP
// response and a CMS SignedData, each checked by x509's own verifiers. The
// signer holds the private key x509 never sees, and counts its calls. Then
// what an external key refuses: being signed with directly, a signer that
// fails, and a signer for the wrong key.
import std;
import x509 from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509.keys;
import x509.create;
import x509.verify;
import x509.crl;
import x509.ocsp;
import x509.cms;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

let NOW: i64 = 1800000000;
let YEAR: i64 = 31536000;

// The CA's key held elsewhere, for each kind: everything signed through
// the signer and checked.
fn ca_held_elsewhere(kind: i64) {
    let real = x509::generate_key(kind);
    let ext, oke = x509::external_key(x509::marshal_public_key(real));
    check(str(kind, ": external_key"), oke && x509::is_external(ext) && ext.kind == kind);
    check(str(kind, ": its public key as the real one's"),
          x509::marshal_public_key(ext) == x509::marshal_public_key(real) && x509::public_key_bytes(ext) == x509::public_key_bytes(real));
    var calls = 0;
    var wrong_key = false;
    fn tpm(k: const x509::PrivateKey&, alg: i64, h: i64, data: const u8[:]) -> u8[>..] {
        calls++;
        if !x509::is_external(k) { wrong_key = true; }
        return x509::sign_data(real, alg, h, data);
    }

    // A self-signed root.
    var rt, okt = x509::template("CN=Root Held Elsewhere,O=Goose", NOW - YEAR, NOW + YEAR);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN | x509::KU_DIGITAL_SIGNATURE;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(ext), "", ext, tpm);
    let rc, epr = x509::parse(root);
    check(str(kind, ": root signed through the signer"), okt && er == x509::OK && epr == x509::OK
          && x509::check_signature(rc, rc) == x509::OK && calls == 1 && !wrong_key);
    let ext_c, okc = x509::external_key(rc);
    check(str(kind, ": external_key of the certificate"), okc && x509::marshal_public_key(ext_c) == x509::marshal_public_key(real));

    // A leaf under it, from a CSR whose key is held elsewhere too.
    let leaf_real = x509::generate_key(x509::KEY_EC_P256);
    let leaf_ext, okl = x509::external_key(x509::marshal_public_key(leaf_real));
    fn leaf_tpm(k: const x509::PrivateKey&, alg: i64, h: i64, data: const u8[:]) -> u8[>..] {
        return x509::sign_data(leaf_real, alg, h, data);
    }
    let subj, oks = x509::name_der("CN=device.example.com");
    var san: u8[..4096] = [];
    x509::add_dns(san, "device.example.com");
    let csr, ecsr = x509::create_csr(subj, san, leaf_ext, leaf_tpm);
    let cr, ecr = x509::parse_csr(csr);
    check(str(kind, ": a CSR signed through the signer"), okl && oks && ecsr == x509::OK && ecr == x509::OK
          && x509::check_csr(cr) == x509::OK);
    var lt, oklt = x509::template("CN=device.example.com", NOW - 10, NOW + YEAR);
    lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    x509::add_dns(lt.san, "device.example.com");
    let leaf, el = x509::create_certificate(lt, cr.der[cr.spki.start..cr.spki.end], root, ext, tpm);
    let lc, epl = x509::parse(leaf);
    check(str(kind, ": a certificate issued through the signer"), oklt && el == x509::OK && epl == x509::OK
          && x509::check_signature(lc, rc) == x509::OK && calls == 2);

    // A CRL revoking it.
    var entries: x509::Revoked[>..] = [];
    var serial: u8[..20] = [];
    serial.append(lc.der[lc.serial.off..lc.serial.end]);
    entries.push(x509::Revoked { serial: serial, time: NOW - 100, reason: x509::REASON_KEY_COMPROMISE });
    let crl, ecrl = x509::create_crl(root, ext, entries, NOW - 3600, NOW + 86400, 3, tpm);
    let pc, epc = x509::parse_crl(crl);
    let listed, reason = x509::crl_lookup(pc, lc);
    check(str(kind, ": a CRL signed through the signer"), ecrl == x509::OK && epc == x509::OK && listed
          && x509::check_crl(pc, rc, NOW) == x509::OK && calls == 3);

    // An OCSP response by the CA itself.
    var t = x509::ocsp_template(x509::OCSP_GOOD, lc.der[lc.serial.off..lc.serial.end], NOW);
    t.next_update = NOW + 86400;
    let ocsp, eo = x509::ocsp_create_response(rc, rc, ext, t, NOW, false, tpm);
    let resp, ero = x509::ocsp_parse_response(ocsp);
    check(str(kind, ": an OCSP response signed through the signer"), eo == x509::OK && ero == x509::OK
          && x509::ocsp_check_response(resp, lc, rc, NOW) == x509::OK && calls == 4);

    // A CMS SignedData by the CA.
    let alg, h = x509::default_sig(kind);
    if alg == x509::SIG_RSA_PKCS1 || alg == x509::SIG_RSA_PSS || alg == x509::SIG_ECDSA {
        let signed, okcms = x509::cms_sign("1.2.840.113549.1.7.1", "hello", ext, rc, "", alg, h, tpm);
        let sd, ep = x509::cms_parse_signed(signed);
        let signer, ev = x509::cms_verify(sd);
        check(str(kind, ": CMS signed through the signer"), okcms && ep == x509::OK && ev == x509::OK && calls == 5);
    }
    check(str(kind, ": the signer always given the key held elsewhere"), !wrong_key);
}

fn main() {
    let kinds: i64[5] = [x509::KEY_EC_P256, x509::KEY_EC_P384, x509::KEY_RSA, x509::KEY_ED25519, x509::KEY_MLDSA44];
    for kind in kinds { ca_held_elsewhere(kind); }

    // What a key held elsewhere refuses.
    let real = x509::generate_key(x509::KEY_EC_P256);
    let ext, oke = x509::external_key(x509::marshal_public_key(real));
    let s1, ok1 = x509::sign(ext, x509::SIG_ECDSA, 256, "message");
    let s2, ok2 = x509::sign_digest(ext, x509::SIG_ECDSA, 256, bignum::hash_bits(256, "message"));
    check("sign and sign_digest refuse a key held elsewhere", !ok1 && !ok2 && s1.len == 0 && s2.len == 0);
    check("sign_data too", x509::sign_data(ext, x509::SIG_ECDSA, 256, bignum::hash_bits(256, "message")).len == 0);
    var rt, okt = x509::template("CN=No Signer", NOW - YEAR, NOW + YEAR);
    rt.is_ca = true;
    let none, en = x509::create_certificate(rt, x509::marshal_public_key(ext), "", ext);
    check("no signer: a certificate cannot be made", en == x509::ERR_SIGNING && none.len == 0);
    let failed, ef = x509::create_certificate(rt, x509::marshal_public_key(ext), "", ext) { k, alg, h, data => let e: u8[>..] = []; e };
    check("a signer that fails: ERR_SIGNING", ef == x509::ERR_SIGNING && failed.len == 0);
    // A signer with another key's signature is caught, as Go checks a
    // crypto.Signer's: no certificate, and no CSR.
    let other = x509::generate_key(x509::KEY_EC_P256);
    let wrong, ew = x509::create_certificate(rt, x509::marshal_public_key(ext), "", ext) { k, alg, h, data => x509::sign_data(other, alg, h, data) };
    check("a signer with the wrong key: ERR_BAD_SIGNATURE", ew == x509::ERR_BAD_SIGNATURE && wrong.len == 0);
    let subj, oks = x509::name_der("CN=wrong.example.com");
    let wcsr, ewc = x509::create_csr(subj, "", ext) { k, alg, h, data => x509::sign_data(other, alg, h, data) };
    check("a CSR by a signer with the wrong key: ERR_BAD_SIGNATURE", oks && ewc == x509::ERR_BAD_SIGNATURE && wcsr.len == 0);
    let bad, okb = x509::external_key("not a key");
    check("external_key: not a SubjectPublicKeyInfo", !okb);

    print("signer: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
