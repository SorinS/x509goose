// Path validation over certificate pools, as a TLS client does it: roots
// in one pool (from PEM), the intermediates the server sent in another,
// and the search through them, which skips a decoy CA of the right name
// and finds the real issuer. Then the constraints a CA puts on what is
// below it: name constraints (permitted and excluded DNS subtrees) and
// certificate policies, and a client certificate checked for clientAuth.
//
//   goose examples/verify_pool.goose
import std;
import os;
import x509 from "..";
import entropy from "SorinS/entropygoose@v0.9.1";
import bignum from "SorinS/bigmongoose@v0.9.1";
import asn1 from "SorinS/asn1goose@v0.9.1";
import x509.keys;
import x509.create;
import x509.pool;
import x509.verify;
import x509.constraints;
import x509.policy;

let DAY:    i64         = 86400;
let POLICY: const u8[:] = "1.3.6.1.4.1.55555.1";       // an example arc

fn expect(what: const u8[:], got: i64, want: i64) {
    print(what, ": ", x509::error_text(got));
    guard got == want else { print("verify_pool: wanted ", x509::error_text(want)); exit(1); }
}

fn ca(name: const u8[:], key: const x509::PrivateKey&, issuer: const u8[:], issuer_key: const x509::PrivateKey&,
      now: i64) -> u8[>..] {
    var t, ok = x509::template(name, now - DAY, now + 365 * DAY);
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    if issuer.len > 0 {
        // The intermediate may only issue for example.com, never for
        // internal.example.com, and under our policy.
        t.path_len = 0;
        x509::add_dns(t.permitted, "example.com");
        x509::add_dns(t.excluded, "internal.example.com");
        t.policies.append(POLICY);
    }
    let der, e = x509::create_certificate(t, x509::marshal_public_key(key), issuer, issuer_key);
    guard ok && e == x509::OK else { print("verify_pool: ", name, ": ", x509::error_text(e)); exit(1); }
    return der;
}

fn leaf(host: const u8[:], eku: u32, issuer: const u8[:], issuer_key: const x509::PrivateKey&, now: i64) -> u8[>..] {
    let k = x509::generate_key(x509::KEY_ED25519);
    var t, ok = x509::template(str("CN=", host), now - 60, now + 90 * DAY);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    t.ext_key_usage = eku;
    x509::add_dns(t.san, host);
    t.policies.append(POLICY);
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), issuer, issuer_key);
    guard ok && e == x509::OK else { print("verify_pool: ", host, ": ", x509::error_text(e)); exit(1); }
    return der;
}

fn main() {
    let now = time() as i64;
    let root_key = x509::generate_key(x509::KEY_EC_P256);
    let root = ca("CN=Example Root CA,O=Example", root_key, "", root_key, now);
    let int_key = x509::generate_key(x509::KEY_EC_P256);
    let inter = ca("CN=Example Issuing CA,O=Example", int_key, root, root_key, now);
    // A decoy: same subject as the intermediate, another key, self-signed.
    let decoy_key = x509::generate_key(x509::KEY_EC_P256);
    let decoy = ca("CN=Example Issuing CA,O=Example", decoy_key, "", decoy_key, now);

    // Roots come as a PEM bundle (a CA file); intermediates as DER.
    var bundle: u8[>..] = [];
    asn1::pem_encode(bundle, "CERTIFICATE", root);
    var roots = x509::new_pool();
    let added = x509::pool_append_pem(roots, bundle);
    var inters = x509::new_pool();
    x509::pool_add(inters, decoy);
    x509::pool_add(inters, inter);
    print("roots: ", added, " added, ", x509::pool_len(roots), " in the pool; intermediates: ", x509::pool_len(inters));
    guard x509::pool_contains(roots, root) && !x509::pool_contains(roots, inter) else { print("verify_pool: pools"); exit(1); }

    let www = leaf("www.example.com", x509::EKU_SERVER_AUTH, inter, int_key, now);
    let opts = x509::options();
    expect("www.example.com through the pools, decoy skipped",
           x509::verify_pools(www, inters, roots, "", now, "www.example.com", opts), x509::OK);
    // verify_with_roots takes the intermediates as concatenated DER, as a
    // TLS Certificate message carries them.
    var sent: u8[>..] = [];
    sent.append(decoy);
    sent.append(inter);
    expect("the same, intermediates as sent", x509::verify_with_roots(www, sent, roots, now, "www.example.com"), x509::OK);

    // Name constraints: outside example.com, or inside the excluded subtree.
    // The decoy is still in the pool, but a failed search reports the error
    // of the path that came closest, here the one through the real issuer,
    // not the decoy's bad signature.
    let other = leaf("www.example.org", x509::EKU_SERVER_AUTH, inter, int_key, now);
    let internal = leaf("db.internal.example.com", x509::EKU_SERVER_AUTH, inter, int_key, now);
    expect("www.example.org", x509::verify_pools(other, inters, roots, "", now, "", opts), x509::ERR_NAME_CONSTRAINTS);
    expect("db.internal.example.com", x509::verify_pools(internal, inters, roots, "", now, "", opts),
           x509::ERR_NAME_CONSTRAINTS);
    // The same check, one CA against one certificate.
    let ic, e1 = x509::parse(inter);
    let oc, e2 = x509::parse(other);
    guard x509::check_name_constraints(ic, oc) == x509::ERR_NAME_CONSTRAINTS else { print("verify_pool: direct"); exit(1); }

    // Policies: require ours, then require one nobody asserted.
    var want = x509::options();
    want.require_explicit_policy = true;
    want.policies.append(POLICY);
    expect("with our policy required", x509::verify_pools(www, inters, roots, "", now, "", want), x509::OK);
    var other_policy = x509::options();
    other_policy.require_explicit_policy = true;
    other_policy.policies.append("1.3.6.1.4.1.55555.2");
    expect("with another policy required", x509::verify_pools(www, inters, roots, "", now, "", other_policy), x509::ERR_POLICY);

    // A client certificate (clientAuth) is checked for clientAuth, and a
    // server certificate does not pass as one.
    let client = leaf("alice.example.com", x509::EKU_CLIENT_AUTH, inter, int_key, now);
    let cr = x509::verify_client_with_roots(client, inter, roots, now);
    let sr = x509::verify_client_with_roots(www, inter, roots, now);
    expect("client certificate", cr, x509::OK);
    expect("server certificate as a client's", sr, x509::ERR_EXTENDED_KEY_USAGE);
    print("all paths checked");
}
