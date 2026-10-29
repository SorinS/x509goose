// ML-DSA and DSA keys and certificates against vectors/pq.txt
// (scripts/pq_vectors.py): openssl's keys must parse from each PKCS #8
// form (the expanded key alone refused, as Go refuses it), marshal back to
// openssl's seed-only PKCS #8 (and DSA's) and SubjectPublicKeyInfo, and
// Go's keys to Go's bytes; certificates made by openssl and by Go must
// parse and their path cases give the result openssl or Go gave; and each
// key must sign a certificate here that checks, and TLS signatures under
// its scheme.
import std;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.keys;
import x509.create;
import x509.verify;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 15 { print("FAIL ", what[..::min(what.len, 60)]); } }
}

fn unhex(s: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if s == "-" { return out; }
    var i = 0;
    while i < s.len {
        let v, ok = parse_int(s[i..i + 2], 16);
        assert(ok);
        out.push(v as! u8);
        i += 2;
    }
    return out;
}

fn vectors() -> const u8[:] { embed_file("vectors/pq.txt") }

fn cert_der(name: const u8[:]) -> u8[>..] {
    for line in split(vectors(), '\n') {
        let w = words(line);
        if w.len == 3 && w[0] == "cert" && w[1] == name { return unhex(w[2]); }
    }
    print("no certificate ", name);
    assert(false);
    var none: u8[>..] = [];
    return none;
}

fn bundle(names: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if names == "-" { return out; }
    for n in split(names, ',') { out.append(cert_der(n)); }
    return out;
}

let NOW: i64 = 1793000000;

// A certificate the key signs for itself, which must check, and a TLS
// signature under `scheme` (0: none), which must verify under it and not
// under `wrong`.
fn sign_checks(label: const u8[:], k: const x509::PrivateKey&, scheme: u16, wrong: u16) {
    var t, okt = x509::template("CN=Goose PQ Self,O=Goose", NOW - 3600, NOW + 86400);
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_DIGITAL_SIGNATURE;
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), "", k);
    check(str(label, " self-signed made"), e == x509::OK);
    let c, ep = x509::parse(der);
    check(str(label, " self-signed parses"), ep == x509::OK && c.key_type == k.kind);
    check(str(label, " self-signed checks"), x509::check_signature(c, c) == x509::OK);
    var bad: u8[>..] = [];
    bad.append(der);
    bad[c.tbs.end - 5] ^= 1;
    let cb, eb = x509::parse(bad);
    check(str(label, " altered certificate refused"), eb != x509::OK || x509::check_signature(cb, c) == x509::ERR_BAD_SIGNATURE);
    let a, h = x509::default_sig(k.kind);
    let msg = "a CertificateVerify, as it were";
    let sig, oksig = x509::sign(k, a, h, msg);
    check(str(label, " signs"), oksig);
    if scheme != 0 {
        check(str(label, " scheme verifies"), x509::verify_scheme(c, scheme, msg, sig) == x509::OK);
        check(str(label, " other message refused"), x509::verify_scheme(c, scheme, "another", sig) != x509::OK);
        check(str(label, " other scheme refused"), x509::verify_scheme(c, wrong, msg, sig) != x509::OK);
    } else {
        check(str(label, " signature verifies"), x509::verify_with(c, a, h, 0, msg, sig) == x509::OK);
        check(str(label, " other message refused"), x509::verify_with(c, a, h, 0, "another", sig) != x509::OK);
    }
}

fn scheme_of(set: i64) -> u16 { x509::mldsa_scheme(set) }

fn main() {
    var certs = 0;
    var cases = 0;
    for line in split(vectors(), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        let label = line[..::min(line.len, 24)];
        if w[0] == "mlkey" {
            let set, oks = parse_int(w[1], 10);
            let seed_only = unhex(w[2]);
            let both = unhex(w[3]);
            let expanded = unhex(w[4]);
            let spki = unhex(w[5]);
            let k, ok = x509::parse_private_key(seed_only);
            check(str(label, " seed-only parses"), ok && k.kind == x509::mldsa_kind(set));
            check(str(label, " PKCS #8 back"), x509::marshal_pkcs8(k) == seed_only);
            check(str(label, " SPKI"), x509::marshal_public_key(k) == spki);
            let kb, okb = x509::parse_private_key(both);
            check(str(label, " seed and expanded parse"), okb && kb.kind == k.kind && kb.seed == k.seed);
            var tampered: u8[>..] = [];
            tampered.append(both);
            tampered[tampered.len - 1] ^= 1;
            let kt, okt = x509::parse_private_key(tampered);
            check(str(label, " disagreeing expanded key refused"), !okt);
            let ke, oke = x509::parse_private_key(expanded);
            check(str(label, " expanded key alone refused"), !oke);
            sign_checks(label, k, scheme_of(set), if set == 44 { x509::MLDSA65 } else { x509::MLDSA44 });
        } else if w[0] == "gokey" {
            let set, oks = parse_int(w[1], 10);
            let seed = unhex(w[2]);
            let der = unhex(w[3]);
            let k, ok = x509::parse_private_key(der);
            check(str(label, " parses"), ok && k.kind == x509::mldsa_kind(set) && k.seed[..] == seed);
            check(str(label, " PKCS #8 is Go's"), x509::marshal_pkcs8(k) == der);
            check(str(label, " SPKI is Go's"), x509::marshal_public_key(k) == unhex(w[4]));
        } else if w[0] == "dsakey" {
            let pkcs8 = unhex(w[2]);
            let trad = unhex(w[3]);
            let k, ok = x509::parse_private_key(pkcs8);
            check(str(label, " PKCS #8 parses"), ok && k.kind == x509::KEY_DSA);
            check(str(label, " PKCS #8 back"), x509::marshal_pkcs8(k) == pkcs8);
            check(str(label, " SPKI"), x509::marshal_public_key(k) == unhex(w[4]));
            let kt, okt = x509::parse_private_key(trad);
            check(str(label, " traditional parses"), okt && kt.kind == x509::KEY_DSA && kt.dsa.x == k.dsa.x && kt.dsa.y == k.dsa.y);
            // A traditional key whose y is not g^x is refused.
            var bad: u8[>..] = [];
            bad.append(trad);
            bad[bad.len - 40] ^= 1;
            let kbad, okbad = x509::parse_private_key(bad);
            check(str(label, " inconsistent key refused"), !okbad);
            sign_checks(label, k, 0, 0);
        } else if w[0] == "cert" {
            let c, e = x509::parse(unhex(w[2]));
            let pq_sig = c.sig_alg == x509::SIG_MLDSA || c.sig_alg == x509::SIG_DSA;
            check(str(label, " parses"), e == x509::OK && pq_sig && c.key_type != x509::KEY_UNKNOWN);
            certs++;
        } else if w[0] == "case" {
            let leaf = cert_der(w[2]);
            let inters = bundle(w[3]);
            let roots = bundle(w[4]);
            let now, okn = parse_int(w[5], 10);
            let want, okw = parse_int(w[7], 10);
            let host = if w[6] == "-" { "" } else { w[6] };
            let got = x509::verify_chain(leaf, inters, roots, now, host);
            check(line, got == want);
            if got != want { print("    got ", got, " (", x509::error_text(got), ")"); }
            cases++;
        }
    }
    // Keys made here.
    for kind in [x509::KEY_MLDSA44, x509::KEY_MLDSA65, x509::KEY_MLDSA87] {
        let k = x509::generate_key(kind);
        let back, ok = x509::parse_private_key(x509::marshal_pkcs8(k));
        check("generated ML-DSA key round trip", ok && back.kind == kind && back.seed == k.seed);
        sign_checks("generated", k, scheme_of(x509::mldsa_set(kind)), x509::ED25519);
    }
    print(certs, " certificates, ", cases, " path cases");
    print("pq keys and certificates: ", checks, " checks, ", failures, " failed");
    if failures > 0 { exit(1); }
}
