// Makes a small PKI with x509.create into a directory, for
// scripts/check_created.py to check with openssl: a P-384 root, an RSA
// intermediate (name constraints, a policy, a CRL URL), leaves on
// Ed25519, P-256 (signed RSA PKCS #1 v1.5 SHA-384), P-521 (RSA-PSS
// SHA-512) and P-224 keys, a P-224 intermediate and a leaf it signs, a
// leaf outside the name constraints, a CSR, a CRL from
// each CA (the intermediate's revokes the Ed25519 leaf), an ML-DSA-65
// root with ML-DSA-44, ML-DSA-87 and DSA leaves, an ML-DSA CSR and CRL, a
// DSA root with a leaf, an SLH-DSA-SHAKE-128f root with an
// SLH-DSA-SHA2-128f leaf, an SLH-DSA CSR and CRL, every leaf's private
// key in PKCS #8, and paths for the rules over a whole path (as
// test/path_rules.goose): a CA's key rollover under path length 0 and
// another CA there, and leaves under CAs restricted to server or client
// authentication.
//
//   goose tools/make_pki.goose -- <dir> <intermediate-key.der>
import std;
import os;
import x509 from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509.keys;
import x509.create;

fn save(dir: const u8[:], name: const u8[:], label: const u8[:], der: const u8[:]) {
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, label, der);
    assert(write_file(str(dir, "/", name), pem));
}

// An Ed25519 CA certificate for `key` under `issuer`, with a path length
// constraint unless `path_len` is -1, and these extended key usages unless 0.
fn path_ca(subject: const u8[:], key: const x509::PrivateKey&, issuer: const u8[:],
           issuer_key: const x509::PrivateKey&, path_len: i64, eku: u32, now: i64) -> u8[>..] {
    var t, ok = x509::template(subject, now - 3600, now + 31536000);
    t.is_ca = true;
    t.path_len = path_len;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    t.ext_key_usage = eku;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), issuer, issuer_key);
    assert(ok && e == x509::OK);
    return der;
}

fn path_leaf(issuer: const u8[:], issuer_key: const x509::PrivateKey&, eku: u32, now: i64) -> u8[>..] {
    let key = x509::generate_key(x509::KEY_ED25519);
    var t, ok = x509::template("CN=www.example.com", now - 3600, now + 31536000);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = eku;
    x509::add_dns(t.san, "www.example.com");
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), issuer, issuer_key);
    assert(ok && e == x509::OK);
    return der;
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
    // Path length 0 and a rollover: the new key's certificate is
    // self-issued, signed by the old key; a second CA is not.
    let old_key = x509::generate_key(x509::KEY_ED25519);
    let new_key = x509::generate_key(x509::KEY_ED25519);
    let old = path_ca("CN=Goose Rollover,O=Goose", old_key, root, root_key, 0, 0, now);
    let rolled = path_ca("CN=Goose Rollover,O=Goose", new_key, old, old_key, -1, 0, now);
    save(dir, "rollover_old.pem", "CERTIFICATE", old);
    save(dir, "rollover_new.pem", "CERTIFICATE", rolled);
    save(dir, "leaf_rollover.pem", "CERTIFICATE", path_leaf(rolled, new_key, x509::EKU_SERVER_AUTH, now));
    let second_key = x509::generate_key(x509::KEY_ED25519);
    let second = path_ca("CN=Goose Second,O=Goose", second_key, old, old_key, -1, 0, now);
    save(dir, "second.pem", "CERTIFICATE", second);
    save(dir, "leaf_second.pem", "CERTIFICATE", path_leaf(second, second_key, x509::EKU_SERVER_AUTH, now));
    // Server-only leaves under a client-only CA and a server-only one.
    let cck = x509::generate_key(x509::KEY_ED25519);
    let client_ca = path_ca("CN=Goose Client CA,O=Goose", cck, root, root_key, -1, x509::EKU_CLIENT_AUTH, now);
    save(dir, "client_ca.pem", "CERTIFICATE", client_ca);
    save(dir, "leaf_disjoint.pem", "CERTIFICATE", path_leaf(client_ca, cck, x509::EKU_SERVER_AUTH, now));
    let sck = x509::generate_key(x509::KEY_ED25519);
    let server_ca = path_ca("CN=Goose Server CA,O=Goose", sck, root, root_key, -1, x509::EKU_SERVER_AUTH, now);
    save(dir, "server_ca.pem", "CERTIFICATE", server_ca);
    save(dir, "leaf_server_ca.pem", "CERTIFICATE", path_leaf(server_ca, sck, x509::EKU_SERVER_AUTH, now));
    let ck = x509::generate_key(x509::KEY_EC_P256);
    let subj, oks = x509::name_der("CN=csr.example.com,O=Requester\\, Inc.,C=US");
    var san: u8[..4096] = [];
    x509::add_dns(san, "csr.example.com");
    let csr, ecsr = x509::create_csr(subj, san, ck);
    assert(ecsr == x509::OK);
    save(dir, "csr.pem", "CERTIFICATE REQUEST", csr);
    var entries: x509::Revoked[>..] = [];
    entries.push(x509::Revoked { serial: revoked_serial, time: now - 600, reason: 1 });
    let crl, ec = x509::create_crl(inter, int_key, entries, now - 600, now + 86400, 2);
    assert(ec == x509::OK);
    save(dir, "crl_int.pem", "X509 CRL", crl);
    let empty: x509::Revoked[0] = [];
    let rcrl, erc = x509::create_crl(root, root_key, empty, now - 600, now + 86400, 1);
    assert(erc == x509::OK);
    save(dir, "crl_root.pem", "X509 CRL", rcrl);
    // A post-quantum hierarchy: an ML-DSA-65 root, leaves on ML-DSA-44,
    // ML-DSA-87 and DSA keys, a CSR and a CRL signed with ML-DSA; and a
    // DSA root with a leaf it signs.
    let pq_key = x509::generate_key(x509::KEY_MLDSA65);
    var pt, okpt = x509::template("CN=Goose Made ML-DSA Root,O=Goose", now - 3600, now + 10 * year);
    pt.is_ca = true;
    pt.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let pq_root, epq = x509::create_certificate(pt, x509::marshal_public_key(pq_key), "", pq_key);
    assert(epq == x509::OK);
    save(dir, "pq_root.pem", "CERTIFICATE", pq_root);
    let dsa_key = x509::generate_key(x509::KEY_DSA);
    var dt, okdt = x509::template("CN=Goose Made DSA Root,O=Goose", now - 3600, now + 10 * year);
    dt.is_ca = true;
    dt.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let dsa_root, edr = x509::create_certificate(dt, x509::marshal_public_key(dsa_key), "", dsa_key);
    assert(edr == x509::OK);
    save(dir, "dsa_root.pem", "CERTIFICATE", dsa_root);
    let pq_kinds: i64[4] = [x509::KEY_MLDSA44, x509::KEY_MLDSA87, x509::KEY_DSA, x509::KEY_EC_P256];
    let pq_names = ["leaf_mldsa44", "leaf_mldsa87", "leaf_dsa", "leaf_by_dsa"];
    for i in 4 {
        let lk = x509::generate_key(pq_kinds[i]);
        var lt, oklt = x509::template("CN=www.example.com,O=Goose", now - 3600, now + year);
        lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
        lt.ext_key_usage = x509::EKU_SERVER_AUTH;
        x509::add_dns(lt.san, "www.example.com");
        let by_dsa = i == 3;
        let leaf, el = x509::create_certificate(lt, x509::marshal_public_key(lk), if by_dsa { dsa_root } else { pq_root },
                                                if by_dsa { dsa_key } else { pq_key });
        assert(el == x509::OK);
        save(dir, str(pq_names[i], ".pem"), "CERTIFICATE", leaf);
        save(dir, str(pq_names[i], ".key"), "PRIVATE KEY", x509::marshal_pkcs8(lk));
    }
    let pq_csr_key = x509::generate_key(x509::KEY_MLDSA44);
    let csr_mldsa, ecsr_mldsa = x509::create_csr(subj, san, pq_csr_key);
    assert(ecsr_mldsa == x509::OK);
    save(dir, "csr_mldsa.pem", "CERTIFICATE REQUEST", csr_mldsa);
    let pq_crl, epc = x509::create_crl(pq_root, pq_key, empty, now - 600, now + 86400, 1);
    assert(epc == x509::OK);
    save(dir, "crl_pq.pem", "X509 CRL", pq_crl);
    // SLH-DSA: a SHAKE-128f root, a leaf on a SHA2-128f key, a CSR and a CRL.
    let slh_key = x509::generate_key(x509::KEY_SLHDSA_SHAKE_128F);
    var st, okst = x509::template("CN=Goose Made SLH-DSA Root,O=Goose", now - 3600, now + 10 * year);
    st.is_ca = true;
    st.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let slh_root, esr = x509::create_certificate(st, x509::marshal_public_key(slh_key), "", slh_key);
    assert(esr == x509::OK);
    save(dir, "slh_root.pem", "CERTIFICATE", slh_root);
    let slh_leaf_key = x509::generate_key(x509::KEY_SLHDSA_SHA2_128F);
    var slt, okslt = x509::template("CN=www.example.com,O=Goose", now - 3600, now + year);
    slt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    slt.ext_key_usage = x509::EKU_SERVER_AUTH;
    x509::add_dns(slt.san, "www.example.com");
    let slh_leaf, esl = x509::create_certificate(slt, x509::marshal_public_key(slh_leaf_key), slh_root, slh_key);
    assert(esl == x509::OK);
    save(dir, "leaf_slhdsa.pem", "CERTIFICATE", slh_leaf);
    save(dir, "leaf_slhdsa.key", "PRIVATE KEY", x509::marshal_pkcs8(slh_leaf_key));
    let csr_slh, ecsr_slh = x509::create_csr(subj, san, slh_leaf_key);
    assert(ecsr_slh == x509::OK);
    save(dir, "csr_slhdsa.pem", "CERTIFICATE REQUEST", csr_slh);
    let slh_crl, escrl = x509::create_crl(slh_root, slh_key, empty, now - 600, now + 86400, 1);
    assert(escrl == x509::OK);
    save(dir, "crl_slhdsa.pem", "X509 CRL", slh_crl);
    print("ok");
}
