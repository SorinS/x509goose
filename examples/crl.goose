// Revocation with CRLs: a CA revokes one of two certificates it issued
// and publishes a signed CRL; a relying party parses it, checks it
// (signer, dates), looks certificates up, and validates paths with CRL
// checking on, where the revoked one fails and the other passes. A path
// with no CRL at hand gives "revocation status unknown".
//
//   goose examples/crl.goose
import std;
import os;
import x509 from "..";
import bignum from "SorinS/bigmongoose@v0.7.0";
import asn1 from "SorinS/asn1goose@v0.7.0";
import x509.keys;
import x509.create;
import x509.verify;
import x509.crl;

let DAY: i64 = 86400;

fn fail(what: const u8[:], e: i64) { print("crl: ", what, ": ", x509::error_text(e)); exit(1); }

fn issue(host: const u8[:], ca: const u8[:], ca_key: const x509::PrivateKey&, now: i64) -> u8[>..] {
    let k = x509::generate_key(x509::KEY_EC_P256);
    var t, ok = x509::template(str("CN=", host), now - DAY, now + 90 * DAY);
    t.key_usage = x509::KU_DIGITAL_SIGNATURE;
    x509::add_dns(t.san, host);
    t.crl_urls.append("http://crl.example.com/ca.crl");     // where clients find the CRL
    let der, e = x509::create_certificate(t, x509::marshal_public_key(k), ca, ca_key);
    guard ok && e == x509::OK else { fail(host, e); }
    return der;
}

fn main() {
    let now = time() as i64;
    let ca_key = x509::generate_key(x509::KEY_EC_P256);
    var t, okt = x509::template("CN=Example CA,O=Example", now - 2 * DAY, now + 365 * DAY);
    t.is_ca = true;
    t.key_usage = x509::KU_KEY_CERT_SIGN | x509::KU_CRL_SIGN;
    let ca, eca = x509::create_certificate(t, x509::marshal_public_key(ca_key), "", ca_key);
    guard okt && eca == x509::OK else { fail("CA", eca); }
    let good = issue("good.example.com", ca, ca_key, now);
    let lost = issue("lost.example.com", ca, ca_key, now);
    let cac, e1 = x509::parse(ca);
    let gc, e2 = x509::parse(good);
    let lc, e3 = x509::parse(lost);
    for u in x509::crl_urls(lc) { print("lost.example.com names its CRL at ", u); }

    // The CA revokes lost.example.com (its key was compromised an hour ago)
    // in CRL number 1, valid for a week.
    var entries: x509::Revoked[>..] = [];
    var serial:  u8[..20]           = [];
    serial.append(lc.der[lc.serial.off..lc.serial.end]);
    entries.push(x509::Revoked { serial: serial, time: now - 3600, reason: x509::REASON_KEY_COMPROMISE });
    let crl, ec = x509::create_crl(ca, ca_key, entries, now - 60, now + 7 * DAY, 1);
    guard ec == x509::OK else { fail("create_crl", ec); }
    var pem: u8[>..] = [];
    asn1::pem_encode(pem, "X509 CRL", crl);
    print("published a ", crl.len, "-byte CRL (", pem.len, " as PEM)");

    // The relying party: parse, check it is the CA's and current, look up.
    let pc, ep = x509::parse_crl(crl);
    guard ep == x509::OK else { fail("parse_crl", ep); }
    let chk = x509::check_crl(pc, cac, now);
    let listed, reason = x509::crl_lookup(pc, lc);
    let glisted, greason = x509::crl_lookup(pc, gc);
    print("CRL number ", pc.crl_number, ", check: ", x509::error_text(chk), "; lost listed: ", listed, " (reason ", reason,
          "), good listed: ", glisted);
    guard chk == x509::OK && listed && reason == x509::REASON_KEY_COMPROMISE && !glisted else {
        print("crl: lookup gave the wrong answer");
        exit(1);
    }
    // After its nextUpdate the CRL is stale and no longer counts.
    guard x509::check_crl(pc, cac, now + 8 * DAY) == x509::ERR_EXPIRED else { print("crl: stale CRL used"); exit(1); }

    // One call for one certificate, over any number of CRLs (concatenated).
    guard x509::revocation_status(lc, cac, crl, now) == x509::ERR_REVOKED &&
          x509::revocation_status(gc, cac, crl, now) == x509::OK else {
        print("crl: revocation_status");
        exit(1);
    }

    // Path validation with CRL checking: CRL_LEAF checks the leaf,
    // CRL_ALL every certificate below the root.
    var opts = x509::options();
    opts.crl_check = x509::CRL_LEAF;
    opts.key_usages = x509::EKU_ANY;
    let vg = x509::verify_chain_with(good, "", ca, crl, now, "good.example.com", opts);
    let vl = x509::verify_chain_with(lost, "", ca, crl, now, "lost.example.com", opts);
    let vn = x509::verify_chain_with(good, "", ca, "", now, "good.example.com", opts);
    print("good: ", x509::error_text(vg), "; lost: ", x509::error_text(vl), "; good with no CRL: ", x509::error_text(vn));
    guard vg == x509::OK && vl == x509::ERR_REVOKED && vn == x509::ERR_REVOCATION_UNKNOWN else {
        print("crl: path validation gave the wrong answer");
        exit(1);
    }
}
