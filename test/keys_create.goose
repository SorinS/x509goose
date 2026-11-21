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
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
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

let NOW:  i64 = 1800000000;
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

// sign_digest and verify_digest under one key, against sign and
// verify_with over the message.
fn digest_checks(kind: const u8[:], k: const x509::PrivateKey&, alg: i64, h: i64, salt: i64) {
    let c, e = x509::parse(ca_cert("CN=Goose Digest", 7, k));
    assert(e == x509::OK);
    let msg = "handshake messages";
    let d = bignum::hash_bits(h, msg);
    let s1, ok1 = x509::sign_digest(k, alg, h, d);
    check(str(kind, " sign_digest"), ok1);
    check(str(kind, " its signature verifies"), x509::verify_with(c, alg, h, salt, msg, s1) == x509::OK);
    let s2, ok2 = x509::sign(k, alg, h, msg);
    check(str(kind, " verify_digest"), ok2 && x509::verify_digest(c, alg, h, salt, d, s2) == x509::OK);
    check(str(kind, " other digest refused"),
          x509::verify_digest(c, alg, h, salt, bignum::hash_bits(h, "other messages"), s2) == x509::ERR_BAD_SIGNATURE);
    let short = d[..d.len - 1];
    let s3, ok3 = x509::sign_digest(k, alg, h, short);
    check(str(kind, " short digest not signed"), !ok3 && s3.len == 0);
    check(str(kind, " short digest refused"), x509::verify_digest(c, alg, h, salt, short, s2) == x509::ERR_BAD_SIGNATURE);
}

// A CRL as create_crl makes it, re-signed with an issuingDistributionPoint
// whose fullName is the one URI.
fn crl_with_idp(crl: const u8[:], key: const x509::PrivateKey&, uri: const u8[:]) -> u8[>..] {
    let top, okt = asn1::parse(crl);
    let parts, okp = asn1::children(crl, top);
    let f, okf = asn1::children(crl, parts[0]);
    let wrap, okw = asn1::explicit(crl, f[f.len - 1]);
    assert(okt && okp && okf && okw);
    var name: u8[>..] = [];
    asn1::put(name, asn1::ctx(6, false), uri);
    var full: u8[>..] = [];
    asn1::put(full, asn1::ctx(0, true), name);
    var dpn: u8[>..] = [];
    asn1::put(dpn, asn1::ctx(0, true), full);
    var idp: u8[>..] = [];
    asn1::put(idp, asn1::SEQUENCE, dpn);
    var exts: u8[>..] = [];
    exts.append(crl[wrap.off..wrap.end]);
    x509::put_ext(exts, "2.5.29.28", true, idp);
    var extseq: u8[>..] = [];
    asn1::put(extseq, asn1::SEQUENCE, exts);
    var tbs: u8[>..] = [];
    for i in f.len - 1 { tbs.append(crl[f[i].start..f[i].end]); }
    asn1::put(tbs, asn1::ctx(0, true), extseq);
    var tbs_seq: u8[>..] = [];
    asn1::put(tbs_seq, asn1::SEQUENCE, tbs);
    let alg, h = x509::default_sig(key.kind);
    let out, ok = x509::signed(tbs_seq, crl[parts[1].start..parts[1].end], key, alg, h);
    assert(ok);
    return out;
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

    // Signatures over digests: RSA, ECDSA (any hash on any curve), and
    // none for Ed25519, which signs messages.
    let rsa_key, okrk = x509::parse_private_key(key_line("rsa", 2));
    check("rsa key", okrk);
    digest_checks("pkcs1 sha256", rsa_key, x509::SIG_RSA_PKCS1, 256, 0);
    digest_checks("pkcs1 sha512", rsa_key, x509::SIG_RSA_PKCS1, 512, 0);
    digest_checks("pss sha256", rsa_key, x509::SIG_RSA_PSS, 256, 32);
    digest_checks("pss sha384", rsa_key, x509::SIG_RSA_PSS, 384, 48);
    let p256_key = x509::generate_key(x509::KEY_EC_P256);
    digest_checks("p256 sha256", p256_key, x509::SIG_ECDSA, 256, 0);
    digest_checks("p256 sha512", p256_key, x509::SIG_ECDSA, 512, 0);
    let p384_key = x509::generate_key(x509::KEY_EC_P384);
    digest_checks("p384 sha256", p384_key, x509::SIG_ECDSA, 256, 0);
    let ed_key = x509::generate_key(x509::KEY_ED25519);
    let ed_cert, eed = x509::parse(ca_cert("CN=Goose Ed", 8, ed_key));
    let eds, oked = x509::sign_digest(ed_key, x509::SIG_ED25519, 0, "");
    check("ed25519 sign_digest refused", !oked && eds.len == 0);
    let edsig, okes = x509::sign(ed_key, x509::SIG_ED25519, 0, "m");
    check("ed25519 verify_digest refused", eed == x509::OK && okes &&
          x509::verify_digest(ed_cert, x509::SIG_ED25519, 0, 0, "", edsig) == x509::ERR_UNSUPPORTED_ALGORITHM);

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
    var leaves:    u8[][>..] = [];
    var keys_made: i64[4]    = [x509::KEY_ED25519, x509::KEY_EC_P256, x509::KEY_EC_P521, x509::KEY_EC_P224];
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
    // A decoy of the intermediate's name and another key, sent before or
    // after it: the path through the intermediate came closer, so its
    // error is the one reported, not the decoy's bad signature.
    let decoy_key = x509::generate_key(x509::KEY_EC_P256);
    let decoy = ca_cert("CN=Goose Made Issuing,O=Goose,C=US", 3, decoy_key);
    var decoy_first: u8[>..] = [];
    decoy_first.append(decoy);
    decoy_first.append(inter);
    var decoy_last: u8[>..] = [];
    decoy_last.append(inter);
    decoy_last.append(decoy);
    check("excluded name, decoy first", x509::verify_chain(bleaf, decoy_first, root, NOW, "") == x509::ERR_NAME_CONSTRAINTS);
    check("excluded name, decoy last", x509::verify_chain(bleaf, decoy_last, root, NOW, "") == x509::ERR_NAME_CONSTRAINTS);
    // A wildcard reaches into the excluded subtree under it.
    var wt, okwt = x509::template("", NOW - 10, NOW + YEAR);
    x509::add_dns(wt.san, "*.example.com");
    let wleaf, ewl = x509::create_certificate(wt, x509::marshal_public_key(bk), inter, int_key);
    check("wildcard over excluded", ewl == x509::OK && x509::verify_chain(wleaf, inter, root, NOW, "") == x509::ERR_NAME_CONSTRAINTS);
    var wt2, okwt2 = x509::template("", NOW - 10, NOW + YEAR);
    x509::add_dns(wt2.san, "*.good.example.com");
    let wleaf2, ewl2 = x509::create_certificate(wt2, x509::marshal_public_key(bk), inter, int_key);
    check("wildcard beside excluded", ewl2 == x509::OK && x509::verify_chain(wleaf2, inter, root, NOW, "") == x509::OK);
    // SAN entries that are not context-class GeneralNames, patched into a
    // made certificate in place (parse does not check the signature): a
    // high tag number 130 (one octet would make it [2]), universal 2 and a
    // constructed [2].
    var pt0, okpt0 = x509::template("", NOW - 10, NOW + YEAR);
    x509::add_dns(pt0.san, "xxevil.com");
    let good_leaf, egl = x509::create_certificate(pt0, x509::marshal_public_key(bk), inter, int_key);
    var at = -1;
    for k in good_leaf.len - 12 {
        if good_leaf[k] == 0x82 && good_leaf[k + 1] == 0x0a && good_leaf[k + 2] == 'x' && good_leaf[k + 3] == 'x' { at = k; }
    }
    check("san to patch", egl == x509::OK && at >= 0);
    for form in 3 {
        var bad = copy(good_leaf);
        if form == 0 {
            bad[at] = 0x1f; bad[at + 1] = 0x81; bad[at + 2] = 0x02; bad[at + 3] = 0x08;
        } else {
            bad[at] = if form == 1 { 0x02 } else { 0xa2 };
        }
        let hc, ehc = x509::parse(bad);
        check(str("san not a GeneralName ", form), ehc == x509::ERR_MALFORMED
              && x509::verify_chain(bad, inter, root, NOW, "evil.com") != x509::OK);
    }
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
    // A DSA request from openssl (1024-bit, SHA-256): its key's parameters
    // are in the SubjectPublicKeyInfo.
    var dsa_hex: u8[>..] = [];
    dsa_hex.append("30820237308201e3020100301a3118301606035504030c0f6473612e6578616d706c652e636f6d308201be3082013306");
    dsa_hex.append("072a8648ce3804013082012602818100dcaa986eaae798859a132321684202a1cd238ca4c3998fc079cfff305bd94ab8");
    dsa_hex.append("6d07826625d53fd838f1f4404134255d0d76280f68d10903e73e29e386c14e11b1e1b43963cf9ff86d8e61d8edcb8605");
    dsa_hex.append("f524cc695cf603e37ac0c20706a34fad0b8b3dd0207f26f3da29eba1e151c5137ff0f0ea6fc03b177540cd618f54b35f");
    dsa_hex.append("021d00ed9e3e41d7d44231fdab4a3c0f967f6e702838cd4479f6f70b4cb5f702818039e783735158a8fff3126007fea0");
    dsa_hex.append("7027a52e519d2503f74c9e12efb69ed7f6c289560e13053c0647bfbe2588e73213d66bd7b053cf1a11616954975408e3");
    dsa_hex.append("ed0d9a505bfbea6db5dab33f4bae8d72bc26e859f06376103206ebd429024e7deead28c4c99c31f2e18e91aeeeeff19c");
    dsa_hex.append("94197354b314e8cfac4c0f9372e014e53044038184000281803317e4ad3e660854083e902f3b253dc8154a5a42e59d63");
    dsa_hex.append("abbbaacdde347f12578aeb967e6e361be7d91da8ffbfb175edf5fb66919eb895e0a165092a954d39b0c04f9c407cc7dc");
    dsa_hex.append("5aaeb66613967cbfaf3570b3ddea6f5f771afe935d8869faa3024aec58484fc19a2efec0b3b341bc6db223e21a1e85c7");
    dsa_hex.append("21c87b89e91e0fc5b2a000300b0609608648016503040302034100303e021d00e3592e6daad75b5ae31ea2f05a49f469");
    dsa_hex.append("84f7e247445d97b15ff28616021d00c3100b30f92a885aa39aad02117e211e6f3ed797673880d72170f5a1");
    let dsa_csr = unhex(dsa_hex);
    let dr, edr = x509::parse_csr(dsa_csr);
    check("dsa csr", edr == x509::OK && dr.key_type == x509::KEY_DSA && x509::check_csr(dr) == x509::OK);
    var dsa_bad = copy(dsa_csr);
    dsa_bad[30] ^= 1;
    let dbr, edbr = x509::parse_csr(dsa_bad);
    check("dsa csr tampered", edbr != x509::OK || x509::check_csr(dbr) != x509::OK);
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
    var serial:  u8[..20]           = [];
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

    // Partitioned CRLs: one whose issuingDistributionPoint names another
    // partition does not cover a leaf, nor does one with a name a leaf
    // without CRL distribution points cannot match.
    var pt, okpt = x509::template("CN=part.example.com", NOW - 10, NOW + YEAR);
    x509::add_dns(pt.san, "part.example.com");
    pt.crl_urls.append("http://crl.example.com/b.crl");
    let pk = x509::generate_key(x509::KEY_EC_P256);
    let pleaf, epl = x509::create_certificate(pt, x509::marshal_public_key(pk), inter, int_key);
    let pcert, epc2 = x509::parse(pleaf);
    var pentries: x509::Revoked[>..] = [];
    var pserial:  u8[..20]           = [];
    pserial.append(pcert.der[pcert.serial.off..pcert.serial.end]);
    pentries.push(x509::Revoked { serial: pserial, time: NOW - 100, reason: -1 });
    let base_b, eb1 = x509::create_crl(inter, int_key, pentries, NOW - 3600, NOW + 86400, 8);
    let base_a, eb2 = x509::create_crl(inter, int_key, empty, NOW - 3600, NOW + 86400, 9);
    let crl_b = crl_with_idp(base_b, int_key, "http://crl.example.com/b.crl");
    let crl_a = crl_with_idp(base_a, int_key, "http://crl.example.com/a.crl");
    let pa, epa = x509::parse_crl(crl_a);
    let pb, epb = x509::parse_crl(crl_b);
    check("idp crls", epl == x509::OK && eb1 == x509::OK && eb2 == x509::OK && epa == x509::OK && epb == x509::OK
          && pa.has_dp && x509::check_crl(pa, ic, NOW) == x509::OK && !x509::crl_covers(pa, pcert) && x509::crl_covers(pb, pcert));
    var lopts = x509::options();
    lopts.crl_check = x509::CRL_LEAF;
    check("idp right partition", x509::verify_chain_with(pleaf, inter, root, crl_b, NOW, "", lopts) == x509::ERR_REVOKED);
    check("idp other partition", x509::verify_chain_with(pleaf, inter, root, crl_a, NOW, "", lopts) == x509::ERR_REVOCATION_UNKNOWN);
    check("idp, leaf without crl dp", x509::verify_chain_with(from_csr, inter, root, crl_b, NOW, "", lopts) == x509::ERR_REVOCATION_UNKNOWN);

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
