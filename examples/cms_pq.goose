// CMS with post-quantum keys: a SignedData by ML-DSA-65 (RFC 9882) and an
// EnvelopedData to an ML-KEM-768 certificate (KEMRecipientInfo, RFC 9629
// and RFC 9936). A CA (ML-DSA-65 itself) certifies a signing key and an
// encryption key, all made here; the document is signed, parsed, verified
// and its signer's path checked; then encrypted to the ML-KEM certificate
// and decrypted with its key. A changed byte and a wrong key are refused.
// No network, no files.
//
//   goose examples/cms_pq.goose
import std;
import x509 from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509.keys;
import x509.create;
import x509.verify;
import x509.cms;
import x509.cms_env;

let DAY: i64 = 86400;

fn fail(what: const u8[:], e: i64) { print("cms_pq: ", what, ": ", x509::error_text(e)); exit(1); }

// A certificate for key k, issued by the CA, with the key usage given.
fn issue(subject: const u8[:], k: const x509::PrivateKey&, usage: u32, ca: const u8[:], ca_key: const x509::PrivateKey&,
         now: i64) -> x509::Cert {
    var t, ok = x509::template(subject, now - DAY, now + 365 * DAY);
    t.key_usage = usage;
    t.ext_key_usage = x509::EKU_EMAIL_PROTECTION;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), ca, ca_key);
    guard ok && e == x509::OK else { fail(subject, e); }
    let c, ep = x509::parse(der);
    guard ep == x509::OK else { fail(subject, ep); }
    return c;
}

fn main() {
    let now = time() as i64;
    let ca_key = x509::generate_key(x509::KEY_MLDSA65);
    var ct, okc = x509::template("CN=Example PQ CA,O=Example", now - DAY, now + 5 * 365 * DAY);
    ct.is_ca = true;
    ct.key_usage = x509::KU_KEY_CERT_SIGN;
    let ca, eca = x509::create_certificate(ct, x509::marshal_public_key(ca_key), "", ca_key);
    guard okc && eca == x509::OK else { fail("CA", eca); }

    let sign_key = x509::generate_key(x509::KEY_MLDSA65);
    let signer = issue("CN=Records Office (signing),O=Example", sign_key, x509::KU_DIGITAL_SIGNATURE, ca, ca_key, now);
    let kem_key = x509::generate_key(x509::KEY_MLKEM768);
    let recipient = issue("CN=Records Office (encryption),O=Example", kem_key, x509::KU_KEY_ENCIPHERMENT, ca, ca_key, now);
    let doc = "Minutes, 14 November: the archive moves to post-quantum keys.\n";

    // Signed: pure ML-DSA-65 over the signed attributes, the digest SHA-512.
    let so = x509::CmsSignOptions { signing_time: now, .. };
    let signed, oks = x509::cms_sign_with(x509::OID_CMS_DATA, doc, sign_key, signer, ca, x509::SIG_MLDSA, 0, so);
    guard oks else { print("cms_pq: ML-DSA signing failed"); exit(1); }
    print("ML-DSA-65 SignedData: ", signed.len, " bytes");
    let sd, ep = x509::cms_parse_signed(signed);
    guard ep == x509::OK else { fail("parse", ep); }
    let who, ev = x509::cms_verify(sd);
    guard ev == x509::OK && x509::cms_content(sd) == doc else { fail("verify", ev); }
    var opts = x509::options();
    opts.key_usages = x509::EKU_EMAIL_PROTECTION;
    let path = x509::verify_chain_with(who.der, x509::cms_certs(sd), ca, "", now, "", opts);
    guard path == x509::OK else { fail("signer's path", path); }
    print("  signed by ", x509::subject_text(who), ", certified by the CA");

    var bad = copy(signed);
    bad[bad.len - 100] ^= 1;
    let sd2, ep2 = x509::cms_parse_signed(bad);
    let who2, ev2 = x509::cms_verify(sd2);
    print("  a byte of the signature changed: ", x509::error_text(ev2));
    guard ev2 == x509::ERR_BAD_SIGNATURE else { print("cms_pq: a changed signature verified"); exit(1); }

    // Encrypted to the ML-KEM certificate (AES-256-GCM: AuthEnvelopedData).
    let eo = x509::CmsEncryptOptions { cipher: x509::CMS_AES256_GCM, .. };
    let sealed, ee = x509::cms_encrypt(x509::OID_CMS_DATA, doc, recipient.der, eo);
    guard ee == x509::OK else { fail("encrypt", ee); }
    print("ML-KEM-768 AuthEnvelopedData: ", sealed.len, " bytes");
    let pt, ctype, ed = x509::cms_decrypt(sealed, kem_key, recipient);
    guard ed == x509::OK && pt == doc else { fail("decrypt", ed); }
    print("  decrypted: \"", pt[..pt.len - 1], "\"");

    // Another ML-KEM-768 key for the same certificate: ML-KEM's implicit
    // rejection gives it a wrong shared secret, and the key does not unwrap.
    let other = x509::generate_key(x509::KEY_MLKEM768);
    let p2, c2, e2 = x509::cms_decrypt(sealed, other, recipient);
    print("  with another key: ", x509::error_text(e2));
    guard e2 == x509::ERR_CMS_DECRYPT else { print("cms_pq: decrypted with the wrong key"); exit(1); }
}
