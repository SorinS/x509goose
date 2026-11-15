// x509.verify: the rules that hold over a whole path, on certificates made
// here with x509.create. A path length constraint counts only the
// non-self-issued intermediates below it, so a CA's key rollover (a
// self-issued certificate for its new key, signed by the old) fits under
// path length 0 where another CA does not. Of the extended key usages
// asked for, one must be allowed by every certificate on the path: a
// server-only leaf under a client-only CA is good for neither; and the
// search backs up from a path that leaves none to one that does.
// scripts/check_created.py has openssl verify such paths
// (tools/make_pki.goose).
import std;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.pool;
import x509.verify;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

let NOW:  i64 = 1793000000;
let YEAR: i64 = 31536000;

// A CA certificate for `key` (self-signed when `issuer` is empty), with a
// path length constraint unless `path_len` is -1, and these extended key
// usages unless 0.
fn ca(subject: const u8[:], key: const x509::PrivateKey&, issuer: const u8[:], issuer_key: const x509::PrivateKey&,
      path_len: i64, eku: u32) -> u8[>..] {
    var t, ok = x509::template(subject, NOW - YEAR, NOW + YEAR);
    t.is_ca = true;
    t.path_len = path_len;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    t.ext_key_usage = eku;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), issuer, issuer_key);
    assert(ok && e == x509::OK);
    return der;
}

fn leaf(key: const x509::PrivateKey&, issuer: const u8[:], issuer_key: const x509::PrivateKey&, eku: u32) -> u8[>..] {
    var t, ok = x509::template("CN=www.example.com", NOW - YEAR, NOW + YEAR);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = eku;
    x509::add_dns(t.san, "www.example.com");
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), issuer, issuer_key);
    assert(ok && e == x509::OK);
    return der;
}

fn cat(a: const u8[:], b: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    out.append(a);
    out.append(b);
    return out;
}

fn with_usages(u: u32) -> x509::Options {
    var o = x509::options();
    o.key_usages = u;
    return o;
}

fn main() {
    let ed = x509::KEY_ED25519;
    let server = x509::EKU_SERVER_AUTH;
    let client = x509::EKU_CLIENT_AUTH;
    let both = with_usages(server | client);
    let client_only = with_usages(client);
    let any_usage = with_usages(x509::EKU_ANY);
    let server_only = x509::options();
    let root_key = x509::generate_key(ed);
    let root = ca("CN=Path Root", root_key, "", root_key, -1, 0);

    // Path length: a rollover under path length 0, and another CA there.
    let old_key = x509::generate_key(ed);
    let new_key = x509::generate_key(ed);
    let old = ca("CN=Rollover", old_key, root, root_key, 0, 0);
    let rolled = ca("CN=Rollover", new_key, old, old_key, -1, 0);
    let rc, erc = x509::parse(rolled);
    check("rollover is self-issued", erc == x509::OK && x509::self_issued(rc));
    let leaf_key = x509::generate_key(ed);
    let by_new = leaf(leaf_key, rolled, new_key, server);
    check("rollover within path length 0",
          x509::verify_chain(by_new, cat(old, rolled), root, NOW, "www.example.com") == x509::OK);
    check("rollover, intermediates the other way round",
          x509::verify_chain(by_new, cat(rolled, old), root, NOW, "www.example.com") == x509::OK);
    let by_old = leaf(leaf_key, old, old_key, server);
    check("old key still", x509::verify_chain(by_old, cat(old, rolled), root, NOW, "") == x509::OK);
    let ca2_key = x509::generate_key(ed);
    let ca2 = ca("CN=Second", ca2_key, old, old_key, -1, 0);
    let by_ca2 = leaf(leaf_key, ca2, ca2_key, server);
    check("another CA beyond path length 0",
          x509::verify_chain(by_ca2, cat(old, ca2), root, NOW, "") == x509::ERR_PATH_LENGTH);
    // Under path length 1, the rollover and a CA below it fit; a second
    // non-self-issued CA does not.
    let one = ca("CN=Rollover", old_key, root, root_key, 1, 0);
    let rolled1 = ca("CN=Rollover", new_key, one, old_key, -1, 0);
    let mid_key = x509::generate_key(ed);
    let mid = ca("CN=Mid", mid_key, rolled1, new_key, -1, 0);
    let by_mid = leaf(leaf_key, mid, mid_key, server);
    var inters = cat(one, rolled1);
    inters.append(mid);
    check("rollover and a CA within path length 1", x509::verify_chain(by_mid, inters, root, NOW, "") == x509::OK);
    let low_key = x509::generate_key(ed);
    let low = ca("CN=Low", low_key, mid, mid_key, -1, 0);
    let by_low = leaf(leaf_key, low, low_key, server);
    inters.append(low);
    check("two CAs beyond path length 1", x509::verify_chain(by_low, inters, root, NOW, "") == x509::ERR_PATH_LENGTH);

    // Extended key usage over the path.
    let ck = x509::generate_key(ed);
    let client_ca = ca("CN=Client CA", ck, root, root_key, -1, client);
    let server_leaf = leaf(leaf_key, client_ca, ck, server);
    check("no usage common to the path",
          x509::verify_chain_with(server_leaf, client_ca, root, "", NOW, "", both) == x509::ERR_EXTENDED_KEY_USAGE);
    check("server only", x509::verify_chain(server_leaf, client_ca, root, NOW, "") == x509::ERR_EXTENDED_KEY_USAGE);
    check("client only", x509::verify_chain_with(server_leaf, client_ca, root, "", NOW, "", client_only) ==
                         x509::ERR_EXTENDED_KEY_USAGE);
    check("any usage", x509::verify_chain_with(server_leaf, client_ca, root, "", NOW, "", any_usage) ==
                       x509::OK);
    let sk = x509::generate_key(ed);
    let server_ca = ca("CN=Server CA", sk, root, root_key, -1, server);
    let server_leaf2 = leaf(leaf_key, server_ca, sk, server);
    check("server common to the path", x509::verify_chain_with(server_leaf2, server_ca, root, "", NOW, "", both) == x509::OK);
    let both_leaf = leaf(leaf_key, client_ca, ck, server | client);
    check("client common to the path", x509::verify_chain_with(both_leaf, client_ca, root, "", NOW, "", both) == x509::OK);
    let ak = x509::generate_key(ed);
    let any_ca = ca("CN=Any CA", ak, root, root_key, -1, x509::EKU_ANY);
    let any_leaf = leaf(leaf_key, any_ca, ak, client);
    check("anyExtendedKeyUsage CA", x509::verify_chain_with(any_leaf, any_ca, root, "", NOW, "", both) == x509::OK);
    // A root restricted to client authentication leaves nothing of a
    // server-only leaf either.
    let crk = x509::generate_key(ed);
    let client_root = ca("CN=Client Root", crk, "", crk, -1, client);
    let ik = x509::generate_key(ed);
    let plain = ca("CN=Issuing", ik, client_root, crk, -1, 0);
    let under_client_root = leaf(leaf_key, plain, ik, server);
    check("no usage common to the path up to the root",
          x509::verify_chain_with(under_client_root, plain, client_root, "", NOW, "", both) ==
          x509::ERR_EXTENDED_KEY_USAGE);

    // Backing up: one key, "CN=Issuing", certified under the client-only
    // root and under the plain one; the search tries the first, finds no
    // usage left at the root, and goes on to the second.
    let other = ca("CN=Issuing", ik, root, root_key, -1, 0);
    var ip = x509::new_pool();
    check("intermediates", x509::pool_add(ip, plain) && x509::pool_add(ip, other));
    var rp = x509::new_pool();
    check("roots", x509::pool_add(rp, client_root) && x509::pool_add(rp, root));
    check("backs up to the path with a usage left",
          x509::verify_pools(under_client_root, ip, rp, "", NOW, "", both) == x509::OK);
    check("backs up for the server's usage",
          x509::verify_pools(under_client_root, ip, rp, "", NOW, "www.example.com", server_only) == x509::OK);
    check("no path for the client's", x509::verify_pools(under_client_root, ip, rp, "", NOW, "", client_only) ==
                                      x509::ERR_EXTENDED_KEY_USAGE);
    // The same a level up: "CN=Issuing 2", server-only, certified first by a
    // client-only CA and second by the root itself.
    let mk = x509::generate_key(ed);
    let client_mid = ca("CN=Client Mid", mk, root, root_key, -1, client);
    let ik2 = x509::generate_key(ed);
    let under_mid = ca("CN=Issuing 2", ik2, client_mid, mk, -1, server);
    let under_root = ca("CN=Issuing 2", ik2, root, root_key, -1, server);
    var ip2 = x509::new_pool();
    check("intermediates 2", x509::pool_add(ip2, under_mid) && x509::pool_add(ip2, client_mid) &&
          x509::pool_add(ip2, under_root));
    var rp2 = x509::new_pool();
    check("root", x509::pool_add(rp2, root));
    let deep_leaf = leaf(leaf_key, under_root, ik2, server | client);
    check("backs up from a dead end two deep", x509::verify_pools(deep_leaf, ip2, rp2, "", NOW, "", both) == x509::OK);
    print("paths: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
