// brainpool (RFC 5639), Ed448 and X448 (RFC 8410) in X.509 and CMS: a CA
// on a brainpoolP384r1 key issues a server certificate for an Ed448 key
// and a mail certificate for an X448 key; the keys go out as PKCS #8 PEM
// and come back, and the chain verifies for its host name. The Ed448 key
// signs a CMS SignedData (RFC 8419: SHAKE256 digest, pure Ed448), which
// verifies, and a message encrypted to the X448 certificate (RFC 8418
// key agreement) decrypts with its key. A changed certificate, a wrong
// host and a changed signature are refused. If a directory is given, the
// PEM files go there, for `openssl verify -CAfile bp_ca.pem ed448_server.pem`.
//
//   goose examples/new_curves.goose -- [DIR]
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
import x509.cms_env;

let DAY: i64 = 86400;

fn fail(what: const u8[:]) { print("new_curves: ", what); exit(1); }

fn pem(label: const u8[:], der: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    asn1::pem_encode(out, label, der);
    return out;
}

fn main() {
    let a = args();
    let now = time() as i64;

    // The CA: brainpoolP384r1, self-signed (ECDSA with SHA-384).
    let ca_key = x509::generate_key(x509::KEY_EC_BP384);
    var ct, okc = x509::template("CN=Example Brainpool CA,O=Example", now - DAY, now + 10 * 365 * DAY);
    ct.is_ca = true;
    ct.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let ca_der, ec = x509::create_certificate(ct, x509::marshal_public_key(ca_key), "", ca_key);
    guard okc && ec == x509::OK else { fail("CA certificate"); }
    print("CA: brainpoolP384r1, certificate ", ca_der.len, " bytes");

    // An Ed448 server key and its certificate from the CA.
    let srv_key = x509::generate_key(x509::KEY_ED448);
    var st, oks = x509::template("CN=www.example.com,O=Example", now - DAY, now + 90 * DAY);
    st.key_usage = x509::KU_DIGITAL_SIGNATURE;
    st.ext_key_usage = x509::EKU_SERVER_AUTH | x509::EKU_EMAIL_PROTECTION;
    x509::add_dns(st.san, "www.example.com");
    let srv_der, es = x509::create_certificate(st, x509::marshal_public_key(srv_key), ca_der, ca_key);
    guard oks && es == x509::OK else { fail("server certificate"); }

    // An X448 key, which only agrees keys, and its certificate.
    let mail_key = x509::generate_key(x509::KEY_X448);
    var mt, okm = x509::template("CN=Example Mail,O=Example", now - DAY, now + 90 * DAY);
    mt.key_usage = x509::KU_KEY_AGREEMENT;
    let mail_der, em = x509::create_certificate(mt, x509::marshal_public_key(mail_key), ca_der, ca_key);
    guard okm && em == x509::OK else { fail("X448 certificate"); }
    print("issued: an Ed448 server certificate (", srv_der.len, " bytes) and an X448 one (", mail_der.len, " bytes)");

    // PEM out, and back in.
    let key_pem = pem("PRIVATE KEY", x509::marshal_pkcs8(srv_key));
    if a.len > 1 {
        let files = ["bp_ca.pem", "ed448_server.pem", "ed448_server.key"];
        for i in 3 {
            let body = if i == 0 { pem("CERTIFICATE", ca_der) } else if i == 1 { pem("CERTIFICATE", srv_der) } else { copy(key_pem) };
            guard write_file(str(a[1], "/", files[i]), body) else { fail(str("cannot write ", a[1], "/", files[i])); }
            print("wrote ", a[1], "/", files[i]);
        }
    }
    let k2, okk = x509::parse_private_key_pem(key_pem);
    guard okk && k2.kind == x509::KEY_ED448 && k2.key448 == srv_key.key448 else { fail("PKCS #8 read back"); }
    let srv, ep = x509::parse(srv_der);
    guard ep == x509::OK && srv.sig_alg == x509::SIG_ECDSA && srv.sig_hash == 384 && srv.key_type == x509::KEY_ED448 else {
        fail("certificate read back");
    }
    print("the Ed448 key read back from PEM");

    // The chain, for its host name; a wrong host and a changed certificate fail.
    let e = x509::verify_chain(srv_der, "", ca_der, now, "www.example.com");
    guard e == x509::OK else { fail(str("chain: ", x509::error_text(e))); }
    guard x509::verify_chain(srv_der, "", ca_der, now, "www.example.org") == x509::ERR_HOSTNAME else { fail("wrong host accepted"); }
    var bad = copy(srv_der);
    bad[srv.tbs.end - 40] ^= 1;
    guard x509::verify_chain(bad, "", ca_der, now, "www.example.com") != x509::OK else { fail("changed certificate accepted"); }
    print("chain verified for www.example.com; wrong host and changed certificate refused");

    // CMS: signed by the Ed448 key, and checked.
    let content = "Signed with Ed448, sealed with X448.";
    let so = x509::CmsSignOptions { signing_time: now };
    let signed, okd = x509::cms_sign_with(x509::OID_CMS_DATA, content, srv_key, srv, ca_der, x509::SIG_ED448, 0, so);
    guard okd else { fail("signing"); }
    let sd, epsd = x509::cms_parse_signed(signed);
    let signer, ev = x509::cms_verify(sd);
    guard epsd == x509::OK && ev == x509::OK && signer.der == srv.der && x509::cms_content(sd) == content else {
        fail(str("SignedData: ", x509::error_text(ev)));
    }
    var forged = copy(signed);
    forged[forged.len - 3] ^= 1;
    let fsd, efs = x509::cms_parse_signed(forged);
    let fc, efv = x509::cms_verify(fsd);
    guard efv == x509::ERR_BAD_SIGNATURE else { fail("changed signature accepted"); }
    print("SignedData by Ed448: ", signed.len, " bytes, verified; changed, refused");

    // CMS: encrypted to the X448 certificate, and decrypted with its key.
    let eo = x509::CmsEncryptOptions { cipher: x509::CMS_AES256_GCM };
    let env, ee = x509::cms_encrypt(x509::OID_CMS_DATA, content, mail_der, eo);
    guard ee == x509::OK else { fail(str("encrypting: ", x509::error_text(ee))); }
    let mc, emc = x509::parse(mail_der);
    let pt, ctype, ed = x509::cms_decrypt(env, mail_key, mc);
    guard emc == x509::OK && ed == x509::OK && pt[..] == content else { fail(str("decrypting: ", x509::error_text(ed))); }
    print("AuthEnvelopedData to X448: ", env.len, " bytes, decrypted: \"", pt, "\"");
}
