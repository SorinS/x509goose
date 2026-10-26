// Makes a small PKI with x509.create into a directory, for
// scripts/check_created.py to check with openssl: a P-384 root, an RSA
// intermediate (name constraints, a policy, a CRL URL), leaves on
// Ed25519, P-256 (signed RSA PKCS #1 v1.5 SHA-384), P-521 (RSA-PSS
// SHA-512) and P-224 keys, a P-224 intermediate and a leaf it signs, a
// leaf outside the name constraints, a CSR, a CRL from
// each CA (the intermediate's revokes the Ed25519 leaf), and every
// private key in PKCS #8.
//
//   goose tools/make_pki.goose -- <dir> <intermediate-key.der>
import std;
import os;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.keys;
import x509.create;

fn save(dir: const u8[:], name: const u8[:], label: const u8[:], der: const u8[:]) {
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, label, der);
    assert(write_file(str(dir, "/", name), pem));
}

fn main() {
    let a = args();
    let dir = a[1];
    var kder: u8[>..] = [];
    assert(read_file(a[2], kder));
    let now = time() as i64;
    let year: i64 = 31536000;
    let root_key = x509::generate_key(x509::KEY_EC_P384);
    var rt, okr = x509::template("CN=Goose Made Root,O=Goose,C=US", now - 3600, now + 10 * year);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    assert(er == x509::OK);
    save(dir, "root.pem", "CERTIFICATE", root);
    save(dir, "root.key", "PRIVATE KEY", x509::marshal_pkcs8(root_key));
    let int_key, oki = x509::parse_private_key(kder);
    assert(oki);
    var it, okit = x509::template("CN=Goose Made Issuing,O=Goose,C=US", now - 3600, now + 5 * year);
    it.is_ca = true;
    it.path_len = 0;
    it.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    x509::add_dns(it.permitted, "example.com");
    x509::add_dns(it.excluded, "bad.example.com");
    it.policies.append("1.3.6.1.4.1.55555.1");
    it.crl_urls.append("http://crl.example.com/issuing.crl");
    let inter, ei = x509::create_certificate(it, x509::marshal_public_key(int_key), root, root_key);
    assert(ei == x509::OK);
    save(dir, "int.pem", "CERTIFICATE", inter);
    let kinds: i64[4] = [x509::KEY_ED25519, x509::KEY_EC_P256, x509::KEY_EC_P521, x509::KEY_EC_P224];
    let names = ["leaf_ed25519", "leaf_p256", "leaf_p521", "leaf_p224"];
    var revoked_serial: u8[..20] = [];
    for i in 4 {
        let lk = x509::generate_key(kinds[i]);
        var lt, oklt = x509::template("CN=www.example.com,O=Goose", now - 3600, now + year);
        lt.basic_constraints = true;
        lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
        lt.ext_key_usage = x509::EKU_SERVER_AUTH;
        x509::add_dns(lt.san, "www.example.com");
        x509::add_dns(lt.san, "api.example.com");
        lt.policies.append("1.3.6.1.4.1.55555.1");
        if i == 1 { lt.sig_alg = x509::SIG_RSA_PKCS1; lt.sig_hash = 384; }
        if i == 2 { lt.sig_alg = x509::SIG_RSA_PSS; lt.sig_hash = 512; }
        let leaf, el = x509::create_certificate(lt, x509::marshal_public_key(lk), inter, int_key);
        assert(el == x509::OK);
        save(dir, str(names[i], ".pem"), "CERTIFICATE", leaf);
        save(dir, str(names[i], ".key"), "PRIVATE KEY", x509::marshal_pkcs8(lk));
        if i == 0 {
            let c, e = x509::parse(leaf);
            revoked_serial.append(c.der[c.serial.off..c.serial.end]);
        }
    }
    // A P-224 intermediate, and a leaf it signs.
    let k224 = x509::generate_key(x509::KEY_EC_P224);
    var t224, ok224 = x509::template("CN=Goose P-224 Issuing,O=Goose", now - 3600, now + 5 * year);
    t224.is_ca = true;
    t224.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let int224, e224 = x509::create_certificate(t224, x509::marshal_public_key(k224), root, root_key);
    assert(e224 == x509::OK);
    save(dir, "int_p224.pem", "CERTIFICATE", int224);
    let lk224 = x509::generate_key(x509::KEY_EC_P256);
    var lt224, oklt224 = x509::template("CN=www.example.com", now - 3600, now + year);
    lt224.key_usage = x509::KU_DIGITAL_SIGNATURE;
    lt224.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(lt224.san, "www.example.com");
    let leaf224, el224 = x509::create_certificate(lt224, x509::marshal_public_key(lk224), int224, k224);
    assert(el224 == x509::OK);
    save(dir, "leaf_by_p224.pem", "CERTIFICATE", leaf224);
    let bk = x509::generate_key(x509::KEY_EC_P256);
    var bt, okbt = x509::template("CN=x.bad.example.com", now - 3600, now + year);
    bt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    x509::add_dns(bt.san, "x.bad.example.com");
    let bleaf, eb = x509::create_certificate(bt, x509::marshal_public_key(bk), inter, int_key);
    assert(eb == x509::OK);
    save(dir, "leaf_excluded.pem", "CERTIFICATE", bleaf);
    let ck = x509::generate_key(x509::KEY_EC_P256);
    let subj, oks = x509::name_der("CN=csr.example.com,O=Requester\\, Inc.,C=US");
    var san: u8[..4096] = [];
    x509::add_dns(san, "csr.example.com");
    save(dir, "csr.pem", "CERTIFICATE REQUEST", x509::create_csr(subj, san, ck));
    var entries: x509::Revoked[>..] = [];
    entries.push(x509::Revoked { serial: revoked_serial, time: now - 600, reason: 1 });
    let crl, ec = x509::create_crl(inter, int_key, entries, now - 600, now + 86400, 2);
    assert(ec == x509::OK);
    save(dir, "crl_int.pem", "X509 CRL", crl);
    let empty: x509::Revoked[0] = [];
    let rcrl, erc = x509::create_crl(root, root_key, empty, now - 600, now + 86400, 1);
    assert(erc == x509::OK);
    save(dir, "crl_root.pem", "X509 CRL", rcrl);
    print("ok");
}
