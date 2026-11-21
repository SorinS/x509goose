// CMS SignedData (RFC 5652): sign a document with a key and its
// certificate (ECDSA, then RSA-PSS), carrying the CA certificate along;
// parse and verify it on the receiving side, read the content out, and
// check the signer's certificate against a trusted CA, which CMS leaves
// to the caller. A changed byte is refused. Also the unsigned form that
// anonymous PKINIT sends.
//
//   goose examples/cms_signed.goose
import std;
import os;
import x509 from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509.keys;
import x509.create;
import x509.verify;
import x509.cms;

let DAY:          i64         = 86400;
let CONTENT_TYPE: const u8[:] = "1.3.6.1.4.1.55555.7";    // an example OID (x509.cms never uses id-data)

fn fail(what: const u8[:], e: i64) { print("cms_signed: ", what, ": ", x509::error_text(e)); exit(1); }

fn signer_cert(kind: i64, ca: const u8[:], ca_key: const x509::PrivateKey&, now: i64) -> u8[>..], x509::PrivateKey {
    let k = x509::generate_key(kind);
    var t, ok = x509::template("CN=Release Signing,O=Example", now - DAY, now + 365 * DAY);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = x509::EKU_CODE_SIGNING;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), ca, ca_key);
    guard ok && e == x509::OK else { fail("signer certificate", e); }
    return der, k;
}

// The receiver: parse, verify the signature, then the signer's path.
fn receive(signed: const u8[:], ca: const u8[:], now: i64) -> i64 {
    let sd, ep = x509::cms_parse_signed(signed);
    if ep != x509::OK { return ep; }
    let signer, ev = x509::cms_verify(sd);
    if ev != x509::OK { return ev; }
    var opts = x509::options();
    opts.key_usages = x509::EKU_CODE_SIGNING;
    // The other certificates sent (here the CA) can serve as intermediates.
    let path = x509::verify_chain_with(signer.der, x509::cms_certs(sd), ca, "", now, "", opts);
    if path != x509::OK { return path; }
    print("  signed by ", x509::subject_text(signer), "; content: \"", x509::cms_content(sd), "\"");
    return x509::OK;
}

fn main() {
    let now = time() as i64;
    let ca_key = x509::generate_key(x509::KEY_EC_P256);
    var ct, okc = x509::template("CN=Example Code Signing CA,O=Example", now - DAY, now + 5 * 365 * DAY);
    ct.is_ca = true;
    ct.key_usage = x509::KU_KEY_CERT_SIGN;
    let ca, eca = x509::create_certificate(ct, x509::marshal_public_key(ca_key), "", ca_key);
    guard okc && eca == x509::OK else { fail("CA", eca); }
    let doc = "release v2.1.0: sha256 of the tarball is 9f86d081884c7d65...";

    // ECDSA P-256 over SHA-256.
    let ec_der, ec_key = signer_cert(x509::KEY_EC_P256, ca, ca_key, now);
    let ec_signer, e1 = x509::parse(ec_der);
    let s1, ok1 = x509::cms_sign(CONTENT_TYPE, doc, ec_key, ec_signer, ca, x509::SIG_ECDSA, 256);
    guard ok1 else { print("cms_signed: ECDSA signing failed"); exit(1); }
    print("ECDSA SignedData: ", s1.len, " bytes");
    let r1 = receive(s1, ca, now);
    guard r1 == x509::OK else { fail("ECDSA", r1); }

    // RSA-PSS over SHA-384, without the CA certificate in the message.
    let rsa_der, rsa_key = signer_cert(x509::KEY_RSA, ca, ca_key, now);
    let rsa_signer, e2 = x509::parse(rsa_der);
    let s2, ok2 = x509::cms_sign(CONTENT_TYPE, doc, rsa_key, rsa_signer, "", x509::SIG_RSA_PSS, 384);
    guard ok2 else { print("cms_signed: RSA-PSS signing failed"); exit(1); }
    print("RSA-PSS SignedData: ", s2.len, " bytes");
    let r2 = receive(s2, ca, now);
    guard r2 == x509::OK else { fail("RSA-PSS", r2); }

    // Tampering: a byte of the content changed.
    var bad = copy(s1);
    var at = 0;
    for i in bad.len - 6 { if bad[i..i + 7] == "release" { at = i; } }
    bad[at] = 'R';
    let rb = receive(bad, ca, now);
    print("changed content: ", x509::error_text(rb));
    guard rb != x509::OK else { print("cms_signed: changed content verified"); exit(1); }

    // Signed, but by a key no trusted CA certified.
    let other_key = x509::generate_key(x509::KEY_EC_P256);
    var ot, okot = x509::template("CN=Some Other CA", now - DAY, now + 365 * DAY);
    ot.is_ca = true;
    ot.key_usage = x509::KU_KEY_CERT_SIGN;
    let other_ca, eo = x509::create_certificate(ot, x509::marshal_public_key(other_key), "", other_key);
    let ro = receive(s1, other_ca, now);
    print("trusting another CA: ", x509::error_text(ro));
    guard ro == x509::ERR_UNKNOWN_ISSUER else { fail("untrusted signer", ro); }

    // No signer at all: anonymous PKINIT's form; it parses, does not verify.
    let u = x509::cms_unsigned(CONTENT_TYPE, "anonymous");
    let sd, ep = x509::cms_parse_signed(u);
    guard ep == x509::OK && !x509::cms_signed(sd) && x509::cms_content(sd) == "anonymous" else {
        print("cms_signed: unsigned form");
        exit(1);
    }
    print("unsigned SignedData parses, with no signer");
}
