// The name forms' subtree matching in x509.constraints, at its edges.
import std;
import x509 from "..";
import asn1 from "../../asn1goose.git";
import bignum from "../../bigmongoose.git";
import x509.constraints;

var failures = 0;
var checks = 0;

fn check(what: const u8[:], ok: bool) {
    checks++;
    if !ok { failures++; print("FAIL ", what); }
}

fn main() {
    // DNS: a base covers itself and names below it, at a label boundary.
    check("dns self", x509::dns_within("example.com", "example.com"));
    check("dns below", x509::dns_within("a.b.example.com", "example.com"));
    check("dns case", x509::dns_within("WWW.Example.COM", "example.com"));
    check("dns not a label", !x509::dns_within("badexample.com", "example.com"));
    check("dns dot below only", !x509::dns_within("example.com", ".example.com"));
    check("dns dot below", x509::dns_within("www.example.com", ".example.com"));
    check("dns empty base", x509::dns_within("anything.org", ""));
    check("dns trailing dot", x509::dns_within("www.example.com.", "example.com"));
    check("dns wildcard name", x509::dns_within("*.example.com", "example.com"));
    // Email.
    check("email host", x509::email_within("a@example.com", "example.com"));
    check("email host case", x509::email_within("a@EXAMPLE.com", "example.com"));
    check("email not subdomain", !x509::email_within("a@mail.example.com", "example.com"));
    check("email subdomain", x509::email_within("a@mail.example.com", ".example.com"));
    check("email mailbox", x509::email_within("Alice@example.com", "Alice@example.com"));
    check("email mailbox local case", !x509::email_within("alice@example.com", "Alice@example.com"));
    check("email no at", !x509::email_within("example.com", "example.com"));
    // URI hosts.
    check("uri host", x509::uri_host("https://user:pw@www.example.com:8443/p?q#f") == "www.example.com");
    check("uri no authority", x509::uri_host("urn:isbn:123").len == 0);
    check("uri within", x509::uri_within("https://www.example.com/", ".example.com"));
    check("uri exact", !x509::uri_within("https://www.example.com/", "example.com"));
    // IP: address and mask, same family only.
    let net: u8[8] = [192, 0, 2, 0, 255, 255, 255, 0];
    let in4: u8[4] = [192, 0, 2, 200];
    let out4: u8[4] = [192, 0, 3, 1];
    var in6: u8[16] = [0; 16];
    check("ip in", x509::ip_within(in4, net));
    check("ip out", !x509::ip_within(out4, net));
    check("ip family", !x509::ip_within(in6, net));
    print("constraints api: ", checks, " checks, ", failures, " failed");
    assert(failures == 0);
}
