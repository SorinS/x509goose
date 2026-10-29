// x509.keys and x509.create. Keys made by openssl (vectors/keys.txt) must
// parse from PKCS #8, SEC 1 and PKCS #1 and marshal back to openssl's
// bytes, public keys included. Then a PKI made here: a P-384 root, an RSA
// intermediate with name constraints and a policy, signed with RSA-PSS,
// and leaves on Ed25519, P-256 and P-521 keys, one from a CSR; their
// fields must read back, their paths validate (and fail where a name
// constraint, a policy or a CRL says so), and a CRL made here must revoke
// what it lists. scripts/check_created.py checks such files with openssl.
import std;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.keys;
import x509.create;
import x509.verify;
import x509.crl;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn key_line(kind: const u8[:], idx: i64) -> u8[>..] {
    for line in split(embed_file("vectors/keys.txt"), '\n') {
        let w = words(line);
        if w.len == 5 && w[1] == kind { return unhex(w[idx]); }
    }
    assert(false);
    var none: u8[>..] = [];
    return none;
}

let NOW: i64 = 1800000000;
let YEAR: i64 = 31536000;

// A CA certificate, self-issued, under `key` (its own, or another's for a
// signature that does not verify).
fn ca_cert(name: const u8[:], serial: i64, key: const x509::PrivateKey&) -> u8[>..] {
    var t, ok = x509::template(name, NOW - YEAR, NOW + YEAR);
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN;
    t.serial.push((serial >> 8) as! u8);
    t.serial.push(serial as! u8);
    let c, e = x509::create_certificate(t, x509::marshal_public_key(key), "", key);
    assert(ok && e == x509::OK);
    return c;
}

fn leaf_under(ca: const u8[:], ca_key: const x509::PrivateKey&) -> u8[>..] {
    let lk = x509::generate_key(x509::KEY_ED25519);
    var lt, ok = x509::template("CN=www.example.com", NOW - 10, NOW + YEAR);
    lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
    x509::add_dns(lt.san, "www.example.com");
    let leaf, e = x509::create_certificate(lt, x509::marshal_public_key(lk), ca, ca_key);
    assert(ok && e == x509::OK);
    return leaf;
}

// Intermediates sent with a certificate must not buy unbounded work.
fn path_search_bounded(root: const u8[:]) {
    // Copies of one CA, same subject and key, serials apart: each verifies
    // every other, and none leads to a root. Without telling them apart the
    // search walks their permutations, 12!/4! paths.
    let ck = x509::generate_key(x509::KEY_ED25519);
    let first = ca_cert("CN=Goose Copied CA", 1, ck);
    var copies: u8[>..] = [];
    copies.append(first);
    for i in 11 { copies.append(ca_cert("CN=Goose Copied CA", i + 2, ck)); }
    let leaf = leaf_under(first, ck);
    check("copies of one CA: unknown issuer", x509::verify_chain(leaf, copies, root, NOW, "") == x509::ERR_UNKNOWN_ISSUER);
    // 120 CAs of the leaf's issuer name, none its signer: the search gives
    // up after Go's 100 signature checks.
    let signer = x509::generate_key(x509::KEY_ED25519);
    let lone = ca_cert("CN=Goose Busy CA", 1, signer);
    var many: u8[>..] = [];
    for i in 120 {
        let k = x509::generate_key(x509::KEY_ED25519);
        many.append(ca_cert("CN=Goose Busy CA", i + 2, k));
    }
    let busy = leaf_under(lone, signer);
    check("120 candidates: signature checks capped",
          x509::verify_chain(busy, many, root, NOW, "") == x509::ERR_TOO_MANY_SIGNATURES);
    // Under the cap a real issuer is still found among decoys.
    var some: u8[>..] = [];
    for i in 20 {
        let k = x509::generate_key(x509::KEY_ED25519);
        some.append(ca_cert("CN=Goose Busy CA", i + 200, k));
    }
    some.append(lone);
    var roots: u8[>..] = [];
    roots.append(root);
    roots.append(lone);
    check("decoys, then the issuer", x509::verify_chain(busy, some, roots, NOW, "") == x509::OK);
}

fn main() {
    // Keys: parse and marshal against openssl's bytes.
    for kind in ["rsa", "p256", "p384", "p521", "ed25519", "p224"] {
        let pkcs8 = key_line(kind, 2);
        let native = key_line(kind, 3);
        let spki = key_line(kind, 4);
        let k, ok = x509::parse_private_key(pkcs8);
        check(kind, ok);
        check("pkcs8 round trip", x509::marshal_pkcs8(k) == pkcs8);
        check("spki", x509::marshal_public_key(k) == spki);
        if native.len > 0 {
            let k2, ok2 = x509::parse_private_key(native);
            check("native parse", ok2 && k2.kind == k.kind);
            let again = if k.kind == x509::KEY_RSA { x509::marshal_pkcs1(k2) } else { x509::marshal_sec1(k2) };
            check("native round trip", again == native);
        }
    }
    let bad, okbad = x509::parse_private_key("junk");
    check("bad key", !okbad);

    // A root, self-signed.
    let root_key = x509::generate_key(x509::KEY_EC_P384);
    var rt, okr = x509::template("CN=Goose Made Root,O=Goose,C=US", NOW - YEAR, NOW + 10 * YEAR);
    rt.is_ca = true;
    rt.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let root, er = x509::create_certificate(rt, x509::marshal_public_key(root_key), "", root_key);
    check("root", okr && er == x509::OK);
    let rc, erc = x509::parse(root);
    check("root fields", erc == x509::OK && x509::subject_text(rc) == "CN=Goose Made Root,O=Goose,C=US"
          && x509::self_issued(rc) && rc.is_ca && rc.key_usage == (x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN)
          && x509::check_signature(rc, rc) == x509::OK && rc.sig_hash == 384);

    // An RSA intermediate under it, constrained to example.com.
    let int_key, oki = x509::parse_private_key(key_line("rsa", 2));
    var it, okit = x509::template("CN=Goose Made Issuing,O=Goose,C=US", NOW - YEAR, NOW + 5 * YEAR);
    it.is_ca = true;
    it.path_len = 0;
    it.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    x509::add_dns(it.permitted, "example.com");
    x509::add_dns(it.excluded, "bad.example.com");
    it.policies.append("1.3.6.1.4.1.55555.1");
    it.crl_urls.append("http://crl.example.com/issuing.crl");
    let inter, ei = x509::create_certificate(it, x509::marshal_public_key(int_key), root, root_key);
    check("intermediate", ei == x509::OK);
    let ic, eic = x509::parse(inter);
    check("intermediate fields", eic == x509::OK && ic.path_len == 0 && ic.has_name_constraints && ic.has_policies
          && x509::issued_by(ic, rc) && x509::check_signature(ic, rc) == x509::OK);
    var urls_ok = false;
    for u in x509::crl_urls(ic) { urls_ok = u == "http://crl.example.com/issuing.crl"; }
    check("crl url", urls_ok);

    // Leaves on four key types; the P-521 one through the RSA-PSS path.
    var leaves: u8[][>..] = [];
    var keys_made: i64[4] = [x509::KEY_ED25519, x509::KEY_EC_P256, x509::KEY_EC_P521, x509::KEY_EC_P224];
    for i in 4 {
        let lk = x509::generate_key(keys_made[i]);
        var lt, oklt = x509::template("CN=www.example.com", NOW - 10, NOW + YEAR);
        lt.basic_constraints = true;
        lt.key_usage = x509::KU_DIGITAL_SIGNATURE;
        lt.ext_key_usage = x509::EKU_SERVER_AUTH | x509::EKU_CLIENT_AUTH;
        x509::add_dns(lt.san, "www.example.com");
        x509::add_dns(lt.san, "api.example.com");
        let ip: u8[4] = [192, 0, 2, 9];
        x509::add_ip(lt.san, ip);
        lt.policies.append("1.3.6.1.4.1.55555.1");
        if i == 2 { lt.sig_alg = x509::SIG_RSA_PSS; lt.sig_hash = 512; }
        if i == 1 { lt.sig_alg = x509::SIG_RSA_PKCS1; lt.sig_hash = 384; }
        let leaf, el = x509::create_certificate(lt, x509::marshal_public_key(lk), inter, int_key);
        check("leaf", el == x509::OK);
        let lc, elc = x509::parse(leaf);
        var names: u8[>..] = [];
        for n in x509::dns_names(lc) { names.append(n); names.push(' '); }
        check("leaf fields", elc == x509::OK && names == "www.example.com api.example.com " && !lc.is_ca
              && lc.has_basic_constraints && lc.ext_key_usage == (x509::EKU_SERVER_AUTH | x509::EKU_CLIENT_AUTH)
              && x509::matches_host(lc, "192.0.2.9") && lc.key_type == keys_made[i]
              && lc.aki.end - lc.aki.off == 20 && lc.serial.end - lc.serial.off == 16);
        check("leaf chain", x509::verify_chain(leaf, inter, root, NOW, "api.example.com") == x509::OK);
        var opts = x509::options();
        opts.require_explicit_policy = true;
        opts.policies.append("1.3.6.1.4.1.55555.1");
        check("leaf policy", x509::verify_chain_with(leaf, inter, root, "", NOW, "", opts) == x509::OK);
        leaves.push(copy(leaf));
    }
    if leaves.len > 0 { check("pss leaf", true); }
    let pss_leaf_alg = {
        var a = 0;
        var k = 0;
        for l in leaves { if k == 2 { let c, e = x509::parse(l); a = c.sig_alg; } k++; }
        a
    };
    check("pss alg", pss_leaf_alg == x509::SIG_RSA_PSS);

    // A P-224 intermediate under the root, signing with ECDSA and SHA-256
    // as Go does, and a leaf it issues.
    let k224 = x509::generate_key(x509::KEY_EC_P224);
    var t224, ok224 = x509::template("CN=Goose P-224 Issuing", NOW - YEAR, NOW + 5 * YEAR);
    t224.is_ca = true;
    t224.key_usage = x509::KU_KEY_CERT_SIGN;
    let int224, e224 = x509::create_certificate(t224, x509::marshal_public_key(k224), root, root_key);
    let lk224 = x509::generate_key(x509::KEY_EC_P256);
    var lt224, oklt224 = x509::template("CN=p224.example.com", NOW - 10, NOW + YEAR);
    x509::add_dns(lt224.san, "p224.example.com");
    let leaf224, el224 = x509::create_certificate(lt224, x509::marshal_public_key(lk224), int224, k224);
    let c224, ec224 = x509::parse(leaf224);
    check("p224 issuer", e224 == x509::OK && el224 == x509::OK && ec224 == x509::OK
          && c224.sig_alg == x509::SIG_ECDSA && c224.sig_hash == 256
          && x509::verify_chain(leaf224, int224, root, NOW, "p224.example.com") == x509::OK);
    var bad224 = copy(leaf224);
    bad224[bad224.len - 5] ^= 1;
    check("p224 bad signature", x509::verify_chain(bad224, int224, root, NOW, "") != x509::OK);

    // Name constraints bind what the intermediate issues.
    let bk = x509::generate_key(x509::KEY_EC_P256);
    var bt, okbt = x509::template("CN=x.bad.example.com", NOW - 10, NOW + YEAR);
    x509::add_dns(bt.san, "x.bad.example.com");
    let bleaf, eb = x509::create_certificate(bt, x509::marshal_public_key(bk), inter, int_key);
    check("excluded name", eb == x509::OK && x509::verify_chain(bleaf, inter, root, NOW, "") == x509::ERR_NAME_CONSTRAINTS);
    // A leaf cannot issue.
    var lf: u8[>..] = [];
    for l in leaves { if lf.len == 0 { lf = copy(l); } }
    let nk = x509::generate_key(x509::KEY_EC_P256);
    let ok_wrong, ew = x509::create_certificate(bt, x509::marshal_public_key(nk), lf, nk);
    check("leaf as issuer", ew == x509::ERR_KEY_USAGE);
    // The wrong key for the issuer.
    let mismatch, em = x509::create_certificate(bt, x509::marshal_public_key(nk), inter, root_key);
    check("issuer key mismatch", em == x509::ERR_BAD_SIGNATURE);

    // A CSR, made, parsed, checked, and turned into a certificate.
    let ck = x509::generate_key(x509::KEY_EC_P256);
    let subj, oks = x509::name_der("CN=csr.example.com,O=Requester\\, Inc.,C=US");
    var san: u8[..4096] = [];
    x509::add_dns(san, "csr.example.com");
    let csr, ecsr = x509::create_csr(subj, san, ck);
    let cr, ecr = x509::parse_csr(csr);
    check("csr", oks && ecsr == x509::OK && ecr == x509::OK && x509::check_csr(cr) == x509::OK && cr.key_type == x509::KEY_EC_P256);
    var csr_names: u8[>..] = [];
    for n in x509::csr_dns_names(cr) { csr_names.append(n); }
    check("csr san", csr_names == "csr.example.com");
    var tampered = copy(csr);
    tampered[20] ^= 1;
    let tr, etr = x509::parse_csr(tampered);
    check("csr tampered", etr != x509::OK || x509::check_csr(tr) != x509::OK);
    var ct, okct = x509::template("", NOW - 10, NOW + YEAR);
    ct.subject.clear();
    ct.subject.append(cr.der[cr.subject.start..cr.subject.end]);
    ct.san.append(cr.der[cr.san.off..cr.san.end]);
    let from_csr, efc = x509::create_certificate(ct, cr.der[cr.spki.start..cr.spki.end], inter, int_key);
    let fc, efcp = x509::parse(from_csr);
    check("from csr", efc == x509::OK && x509::subject_text(fc) == "CN=csr.example.com,O=Requester\\, Inc.,C=US"
          && x509::verify_chain(from_csr, inter, root, NOW, "csr.example.com") == x509::OK);

    // CRLs: the intermediate revokes one leaf; the root revokes nothing.
    let rl, erl = x509::parse(lf);
    var entries: x509::Revoked[>..] = [];
    var serial: u8[..20] = [];
    serial.append(rl.der[rl.serial.off..rl.serial.end]);
    entries.push(x509::Revoked { serial: serial, time: NOW - 100, reason: x509::REASON_KEY_COMPROMISE });
    let crl, ecrl = x509::create_crl(inter, int_key, entries, NOW - 3600, NOW + 86400, 7);
    let empty: x509::Revoked[0] = [];
    let root_crl, ercrl = x509::create_crl(root, root_key, empty, NOW - 3600, NOW + 86400, 1);
    check("crl made", ecrl == x509::OK && ercrl == x509::OK);
    let pc, epc = x509::parse_crl(crl);
    let listed, reason = x509::crl_lookup(pc, rl);
    check("crl parsed", epc == x509::OK && pc.crl_number == 7 && listed && reason == x509::REASON_KEY_COMPROMISE
          && x509::check_crl(pc, ic, NOW) == x509::OK);
    var crls: u8[>..] = [];
    crls.append(crl);
    crls.append(root_crl);
    var copts = x509::options();
    copts.crl_check = x509::CRL_ALL;
    check("revoked", x509::verify_chain_with(lf, inter, root, crls, NOW, "", copts) == x509::ERR_REVOKED);
    check("not revoked", x509::verify_chain_with(from_csr, inter, root, crls, NOW, "", copts) == x509::OK);

    // Names from text.
    let n1, ok1 = x509::name_der("CN=a+OU=b,O=c");
    let n2, ok2 = x509::name_der("XX=bad");
    let n3, ok3 = x509::name_der("C=Ü");
    check("names", ok1 && !ok2 && !ok3);
    var holder = x509::empty_cert();
    holder.der.append(n1);
    let t1, okt = asn1::parse(holder.der);
    check("multi-valued rdn", x509::name_text(holder.der, t1) == "CN=a+OU=b,O=c");

    path_search_bounded(root);

    print("keys and creation: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
