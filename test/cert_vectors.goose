// x509 against vectors/certs.txt (scripts/gen_vectors.py): a PKI made by
// openssl with every signature algorithm the package checks and one
// certificate for each way a path fails. Each certificate's subject,
// issuer, serial, dates, SANs and CA constraints must parse as openssl
// prints them; each path case must give its expected result, on which
// `openssl verify` agreed (pass or fail) when the vectors were made; the
// RFC 8448 server's CertificateVerify must verify under its certificate.
import std;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.verify;
import x509.crl;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; if failures <= 15 { print("FAIL ", what); } }
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

fn vectors() -> const u8[:] { embed_file("vectors/certs.txt") }

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

fn crl_der(name: const u8[:]) -> u8[>..] {
    for line in split(vectors(), '\n') {
        let w = words(line);
        if w.len == 3 && w[0] == "crl" && w[1] == name { return unhex(w[2]); }
    }
    print("no CRL ", name);
    assert(false);
    var none: u8[>..] = [];
    return none;
}

// The DER of the named certificates (or CRLs), concatenated.
fn bundle(names: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if names == "-" { return out; }
    for n in split(names, ',') { out.append(cert_der(n)); }
    return out;
}

fn crl_bundle(names: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    if names == "-" { return out; }
    for n in split(names, ',') { out.append(crl_der(n)); }
    return out;
}

fn options_of(text: const u8[:]) -> x509::Options {
    var o = x509::options();
    if text == "-" { return o; }
    for opt in split(text, ',') {
        if opt == "crl_leaf" { o.crl_check = x509::CRL_LEAF; }
        else if opt == "crl_all" { o.crl_check = x509::CRL_ALL; }
        else if opt == "explicit" { o.require_explicit_policy = true; }
        else if opt == "inhibit_map" { o.inhibit_policy_mapping = true; }
        else if opt == "inhibit_any" { o.inhibit_any_policy = true; }
        else if opt.len > 7 && opt[..7] == "policy=" {
            if o.policies.len > 0 { o.policies.push(' '); }
            o.policies.append(opt[7..]);
        }
    }
    return o;
}

// The rest of a line after its first two words, as written.
fn tail(line: const u8[:]) -> u8[>..] {
    var out: u8[>..] = [];
    var spaces = 0;
    for i in line.len {
        if spaces == 2 { out.append(line[i..]); break; }
        if line[i] == ' ' { spaces++; }
    }
    return out;
}

fn main() {
    var c = x509::empty_cert();
    var count = 0;
    for line in split(vectors(), '\n') {
        let w = words(line);
        if w.len == 0 { continue; }
        if w[0] == "cert" {
            let parsed, e = x509::parse(unhex(w[2]));
            check(line[..::min(line.len, 30)], e == x509::OK);
            c = copy(parsed);
            count++;
        } else if w[0] == "subject" {
            let want: u8[>..] = if w[2] == "-" { "" } else { tail(line) };
            check(line, x509::subject_text(c) == want);
        } else if w[0] == "issuer" {
            check(line, x509::issuer_text(c) == tail(line));
        } else if w[0] == "serial" {
            check(line, x509::serial_hex(c) == w[2]);
        } else if w[0] == "dates" {
            let nb, ok1 = parse_int(w[2], 10);
            let na, ok2 = parse_int(w[3], 10);
            check(line, c.not_before == nb && c.not_after == na);
        } else if w[0] == "dns" {
            var got: u8[>..] = [];
            for n in x509::dns_names(c) {
                if got.len > 0 { got.push(' '); }
                got.append(n);
            }
            let want: u8[>..] = if w[2] == "-" { "" } else { tail(line) };
            check(line, got == want);
        } else if w[0] == "ip" {
            var got: u8[>..] = [];
            for a in x509::ip_addresses(c) {
                if got.len > 0 { got.push(' '); }
                for x in a { format_int(got, x, 16, 2, '0'); }
            }
            let want: u8[>..] = if w[2] == "-" { "" } else { tail(line) };
            check(line, got == want);
        } else if w[0] == "ca" {
            let pl, ok = parse_int(w[3], 10);
            check(line, c.is_ca == (w[2] == "1") && c.path_len == pl);
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
        } else if w[0] == "case2" {
            let leaf = cert_der(w[2]);
            let inters = bundle(w[3]);
            let roots = bundle(w[4]);
            let crls = crl_bundle(w[5]);
            let opts = options_of(w[6]);
            let now, okn = parse_int(w[7], 10);
            let want, okw = parse_int(w[9], 10);
            let host = if w[8] == "-" { "" } else { w[8] };
            let got = x509::verify_chain_with(leaf, inters, roots, crls, now, host, opts);
            check(line, got == want);
            if got != want { print("    got ", got, " (", x509::error_text(got), ")"); }
        } else if w[0] == "crlinfo" {
            let crl, e = x509::parse_crl(crl_der(w[1]));
            let tu, ok1 = parse_int(w[2], 10);
            let nu, ok2 = parse_int(w[3], 10);
            let count, ok3 = parse_int(w[4], 10);
            let num, ok4 = parse_int(w[5], 10);
            var n = 0;
            if crl.has_revoked {
                let es, oke = asn1::children(crl.der, crl.revoked);
                n = es.len;
            }
            check(line, e == x509::OK && crl.version == 2 && crl.this_update == tu && crl.next_update == nu
                  && n == count && crl.crl_number == num && !crl.unsupported);
        } else if w[0] == "rfc8448" {
            let cert, e = x509::parse(unhex(w[1]));
            check("rfc8448 cert", e == x509::OK && cert.key_type == x509::KEY_RSA);
            let scheme = unhex(w[2]);
            let content = unhex(w[3]);
            var sig = unhex(w[4]);
            let s: u16 = (scheme[0] as u16) << 8 | scheme[1];
            check("rfc8448 scheme", s == x509::RSA_PSS_RSAE_SHA256);
            check("rfc8448 CertificateVerify", x509::verify_scheme(cert, s, content, sig) == x509::OK);
            check("rfc8448 wrong scheme", x509::verify_scheme(cert, x509::RSA_PKCS1_SHA256, content, sig) != x509::OK);
            check("rfc8448 ecdsa scheme on rsa", x509::verify_scheme(cert, x509::ECDSA_SECP256R1_SHA256, content, sig) != x509::OK);
            sig[10] ^= 1;
            check("rfc8448 changed", x509::verify_scheme(cert, s, content, sig) == x509::ERR_BAD_SIGNATURE);
        }
    }
    // Signature algorithms and key types as parsed.
    let pss, e1 = x509::parse(cert_der("leaf_pss"));
    check("pss alg", pss.sig_alg == x509::SIG_RSA_PSS && pss.sig_hash == 512 && pss.pss_salt == 64);
    let ed, e2 = x509::parse(cert_der("leaf_ed"));
    check("ed alg", ed.sig_alg == x509::SIG_ED25519 && ed.key_type == x509::KEY_ED25519);
    let ec, e3 = x509::parse(cert_der("leaf_ec"));
    check("ec alg", ec.sig_alg == x509::SIG_ECDSA && ec.sig_hash == 384 && ec.key_type == x509::KEY_EC_P256);
    check("ku eku", ec.has_key_usage && ec.key_usage == x509::KU_DIGITAL_SIGNATURE
          && ec.ext_key_usage == x509::EKU_SERVER_AUTH && ec.aki.end > ec.aki.off && ec.ski.end > ec.ski.off);
    let ca, e4 = x509::parse(cert_der("int_ec"));
    check("ca ku", ca.key_usage == (x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN) && ca.path_len == 0);
    check("issued by", x509::issued_by(ec, ca) && !x509::issued_by(ca, ec));
    // CRL details: the revoked entry, its reason, and the issuer's checks.
    let crl, ce = x509::parse_crl(crl_der("crl_int"));
    let revoked_leaf, er = x509::parse(cert_der("leaf_revoked"));
    let int_ec, ei = x509::parse(cert_der("int_ec"));
    let listed, reason = x509::crl_lookup(crl, revoked_leaf);
    check("crl lookup", listed && reason == x509::REASON_KEY_COMPROMISE);
    let not_listed, r2 = x509::crl_lookup(crl, ec);
    check("crl not listed", !not_listed);
    check("crl check", x509::check_crl(crl, int_ec, 1793000000) == x509::OK);
    check("crl covers", x509::crl_covers(crl, revoked_leaf) && !x509::crl_covers(crl, int_ec));
    let root, eroot = x509::parse(cert_der("root_rsa"));
    check("crl wrong issuer", x509::check_crl(crl, root, 1793000000) == x509::ERR_UNKNOWN_ISSUER);
    check("crl too late", x509::check_crl(crl, int_ec, 1793000000 + 40 * 86400) == x509::ERR_EXPIRED);
    var bad_crl = crl_der("crl_int");
    bad_crl[bad_crl.len - 2] ^= 1;
    let bc, ebc = x509::parse_crl(bad_crl);
    check("crl bad signature", ebc == x509::OK && x509::check_crl(bc, int_ec, 1793000000) == x509::ERR_BAD_SIGNATURE);
    let nc, enc = x509::parse(cert_der("int_nc"));
    check("nc parsed", enc == x509::OK && nc.has_name_constraints);
    let req, ereq = x509::parse(cert_der("int_req"));
    check("policy constraints parsed", req.require_explicit_policy == 0 && req.inhibit_policy_mapping == -1 && req.has_policies);
    let inh, einh = x509::parse(cert_der("int_anyinh"));
    check("inhibit any parsed", inh.inhibit_any_policy == 0);
    let mp, emp = x509::parse(cert_der("int_map"));
    check("mappings parsed", mp.has_policy_mappings);
    // Truncated and altered DER does not parse.
    let der = cert_der("leaf_ec");
    let t1, et1 = x509::parse(der[..der.len - 1]);
    check("truncated", et1 == x509::ERR_MALFORMED);
    var extra: u8[>..] = [];
    extra.append(der);
    extra.push(0);
    let t2, et2 = x509::parse(extra);
    check("trailing byte", et2 == x509::ERR_MALFORMED);
    print("cert vectors: ", count, " certificates, ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
