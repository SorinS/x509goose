// Makes certificates, requests, CRLs, keys and CMS on the brainpool
// curves, Ed448 and X448 with x509.create and x509.cms into a directory,
// for scripts/check_curves.py to check with openssl: a brainpoolP512r1
// root, a brainpoolP384r1 intermediate, leaves on Ed448, brainpoolP256r1
// and X448 keys (each one's key in PKCS #8, the brainpool one in SEC 1
// too), an Ed448 root with a brainpoolP384r1 leaf, requests on
// brainpoolP256r1 and Ed448 keys, a CRL from the intermediate revoking
// the brainpoolP256r1 leaf and one from the Ed448 root revoking its leaf;
// SignedData over content.txt by brainpoolP256r1 (SHA-256),
// brainpoolP384r1 (SHA-384, by key identifier), brainpoolP512r1
// (SHA-512) and Ed448 signers (sig_*.der); and EnvelopedData of it to
// the three brainpool recipients and the X448 one (env_all.der, AES-256-CBC,
// X9.63 KDFs), to the brainpoolP512r1 one by AES-128-GCM (env_gcm.der)
// and to the X448 one by HKDF-SHA512 (env_x448_hkdf.der).
//
//   goose tools/make_curves.goose -- <dir>
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.cms;
import x509.cms_env;

let CONTENT: const u8[:] = "Hello from the new curves, made here.\r\n";

fn save(dir: const u8[:], name: const u8[:], label: const u8[:], der: const u8[:]) {
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, label, der);
    assert(write_file(str(dir, "/", name), pem));
}

fn save_der(dir: const u8[:], name: const u8[:], der: const u8[:]) { assert(write_file(str(dir, "/", name), der)); }

fn ca_template(subject: const u8[:], now: i64) -> x509::Template {
    var t, ok = x509::template(subject, now - 3600, now + 10 * 31536000);
    assert(ok);
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    return t;
}

// A leaf for www.example.com with `usage`, issued by issuer with its key.
fn leaf(dir: const u8[:], name: const u8[:], k: const x509::PrivateKey&, usage: u32, issuer: const u8[:],
        issuer_key: const x509::PrivateKey&, now: i64) -> u8[>..] {
    var t, ok = x509::template("CN=www.example.com,O=Goose", now - 3600, now + 31536000);
    t.basic_constraints = true;
    t.key_usage = usage;
    t.ext_key_usage = x509::EKU_SERVER_AUTH | x509::EKU_EMAIL_PROTECTION;
    x509::add_dns(t.san, "www.example.com");
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), issuer, issuer_key);
    assert(e == x509::OK);
    save(dir, str(name, ".pem"), "CERTIFICATE", der);
    save(dir, str(name, ".key"), "PRIVATE KEY", x509::marshal_pkcs8(k));
    return der;
}

fn serial_of(der: const u8[:]) -> u8[>..] {
    let c, e = x509::parse(der);
    assert(e == x509::OK);
    var s: u8[>..] = [];
    s.append(c.der[c.serial.off..c.serial.end]);
    return s;
}

// sig_<name>.der: content.txt signed by key (cert's) with its default
// algorithm, the intermediate sent along.
fn sign_to(dir: const u8[:], name: const u8[:], key: const x509::PrivateKey&, cert: const u8[:], inter: const u8[:],
           now: i64, by_key_id: bool) {
    let c, e = x509::parse(cert);
    assert(e == x509::OK);
    let o = x509::CmsSignOptions { detached: false, signing_time: now, capabilities: true, by_key_id: by_key_id };
    let a, h = x509::default_sig(c.key_type);
    let sd, ok = x509::cms_sign_with(x509::OID_CMS_DATA, CONTENT, key, c, inter, a, h, o);
    assert(ok);
    save_der(dir, str("sig_", name, ".der"), sd);
}

fn main() {
    let dir = args()[1];
    let now = time() as i64;
    let sign_agree = x509::KU_DIGITAL_SIGNATURE | x509::KU_KEY_AGREEMENT;

    let root_key = x509::generate_key(x509::KEY_EC_BP512);
    let rt = ca_template("CN=Goose Made Brainpool Root,O=Goose", now);
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    assert(er == x509::OK);
    save(dir, "bp_root.pem", "CERTIFICATE", root);
    let int_key = x509::generate_key(x509::KEY_EC_BP384);
    let it = ca_template("CN=Goose Made Brainpool Issuing,O=Goose", now);
    let inter, ei = x509::create_certificate(it, x509::marshal_public_key(int_key), root, root_key);
    assert(ei == x509::OK);
    save(dir, "bp_int.pem", "CERTIFICATE", inter);

    let ed_key = x509::generate_key(x509::KEY_ED448);
    let bp256_key = x509::generate_key(x509::KEY_EC_BP256);
    let x448_key = x509::generate_key(x509::KEY_X448);
    let leaf_ed = leaf(dir, "leaf_ed448", ed_key, x509::KU_DIGITAL_SIGNATURE, inter, int_key, now);
    let leaf_bp = leaf(dir, "leaf_bp256", bp256_key, sign_agree, inter, int_key, now);
    save(dir, "leaf_bp256.sec1", "EC PRIVATE KEY", x509::marshal_sec1(bp256_key));
    let leaf_x = leaf(dir, "leaf_x448", x448_key, x509::KU_KEY_AGREEMENT, inter, int_key, now);
    let bp384_key = x509::generate_key(x509::KEY_EC_BP384);
    let leaf_384 = leaf(dir, "sm_bp384", bp384_key, sign_agree, inter, int_key, now);
    let bp512_key = x509::generate_key(x509::KEY_EC_BP512);
    let leaf_512 = leaf(dir, "sm_bp512", bp512_key, sign_agree, inter, int_key, now);

    let edroot_key = x509::generate_key(x509::KEY_ED448);
    let et = ca_template("CN=Goose Made Ed448 Root,O=Goose", now);
    let edroot, eer = x509::create_certificate(et, x509::marshal_public_key(edroot_key), "", edroot_key);
    assert(eer == x509::OK);
    save(dir, "ed_root.pem", "CERTIFICATE", edroot);
    let by_ed_key = x509::generate_key(x509::KEY_EC_BP384);
    let leaf_by_ed = leaf(dir, "leaf_by_ed448", by_ed_key, x509::KU_DIGITAL_SIGNATURE, edroot, edroot_key, now);

    let subj, oks = x509::name_der("CN=csr.example.com,O=Goose");
    var san: u8[..4096] = [];
    x509::add_dns(san, "csr.example.com");
    for kind in [x509::KEY_EC_BP256, x509::KEY_ED448] {
        let k = x509::generate_key(kind);
        let csr, ecsr = x509::create_csr(subj, san, k);
        assert(ecsr == x509::OK);
        save(dir, if kind == x509::KEY_ED448 { "csr_ed448.pem" } else { "csr_bp256.pem" }, "CERTIFICATE REQUEST", csr);
    }

    var entries: x509::Revoked[>..] = [];
    entries.push(x509::Revoked { serial: serial_of(leaf_bp), time: now - 600, reason: 1 });
    let crl, ec = x509::create_crl(inter, int_key, entries, now - 600, now + 86400, 1);
    assert(ec == x509::OK);
    save(dir, "crl_bp.pem", "X509 CRL", crl);
    var ed_entries: x509::Revoked[>..] = [];
    ed_entries.push(x509::Revoked { serial: serial_of(leaf_by_ed), time: now - 600, reason: 4 });
    let edcrl, eec = x509::create_crl(edroot, edroot_key, ed_entries, now - 600, now + 86400, 7);
    assert(eec == x509::OK);
    save(dir, "crl_ed.pem", "X509 CRL", edcrl);

    // CMS: signed by each, the intermediate sent along.
    assert(write_file(str(dir, "/content.txt"), CONTENT));
    sign_to(dir, "leaf_bp256", bp256_key, leaf_bp, inter, now, false);
    sign_to(dir, "sm_bp384", bp384_key, leaf_384, inter, now, true);
    sign_to(dir, "sm_bp512", bp512_key, leaf_512, inter, now, false);
    sign_to(dir, "leaf_ed448", ed_key, leaf_ed, inter, now, false);

    // Enveloped to every agreeing recipient; by GCM; to X448 by HKDF.
    var all: u8[>..] = [];
    all.append(leaf_bp);
    all.append(leaf_384);
    all.append(leaf_512);
    all.append(leaf_x);
    let o1 = x509::CmsEncryptOptions { .. };
    let env, e1 = x509::cms_encrypt(x509::OID_CMS_DATA, CONTENT, all, o1);
    assert(e1 == x509::OK);
    save_der(dir, "env_all.der", env);
    let o2 = x509::CmsEncryptOptions { cipher: x509::CMS_AES128_GCM, by_key_id: true };
    let gcm, e2 = x509::cms_encrypt(x509::OID_CMS_DATA, CONTENT, leaf_512, o2);
    assert(e2 == x509::OK);
    save_der(dir, "env_gcm.der", gcm);
    let o3 = x509::CmsEncryptOptions { cipher: x509::CMS_AES128_CBC, x448_hkdf: true };
    let hk, e3 = x509::cms_encrypt(x509::OID_CMS_DATA, CONTENT, leaf_x, o3);
    assert(e3 == x509::OK);
    save_der(dir, "env_x448_hkdf.der", hk);
    print("ok");
}
