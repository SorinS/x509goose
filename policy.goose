// x509.policy: certificate policy processing (RFC 5280 §6.1.2 to §6.1.5):
// the valid_policy_tree built from certificatePolicies, policy mappings,
// policyConstraints (requireExplicitPolicy, inhibitPolicyMapping),
// inhibitAnyPolicy, and the intersection with the policies the caller
// accepts. Qualifiers are not interpreted. The tree is capped in size, so
// a path cannot make it grow without bound by mapping policies.

namespace x509;

import std;
import x509;
import asn1;

// A node of the tree: its depth, parent (-1 for the root), and valid
// policy as OID content octets; deleted nodes stay in place.
struct PolicyNode { depth: i64, parent: i64, policy: u8[..64], deleted: bool }

// One member of a node's expected_policy_set.
struct Expected { node: i64, policy: u8[..64] }

let MAX_POLICY_NODES: i64 = 1000;

fn any_policy_oid() -> u8[..64] {
    let enc, ok = asn1::oid_encode(ANY_POLICY);
    var r: u8[..64] = [];
    r.append(enc);
    return r;
}

fn oid64(der: const u8[:], t: asn1::Tlv) -> u8[..64], bool {
    var r: u8[..64] = [];
    if t.end - t.off > 64 { return r, false; }
    r.append(der[t.off..t.end]);
    return r, true;
}

// The policies of a certificate's certificatePolicies, as OID contents.
fn cert_policies(c: const Cert&) -> u8[..64][>..], bool {
    var out: u8[..64][>..] = [];
    let d = c.der[..];
    let ps, ok = asn1::children(d, c.policies);
    for p in ps {
        let pi, okp = asn1::children(d, p);
        let o, oko = oid64(d, pi[0]);
        if !oko { return out, false; }
        out.push(o);
    }
    return out, true;
}

// Deletes nodes without children, from depth `below` up to the root.
fn prune(nodes: PolicyNode[>..]&, below: i64) {
    var depth = below;
    while depth >= 0 {
        for i in nodes.len {
            if nodes[i].deleted || nodes[i].depth != depth { continue; }
            var has_child = false;
            for j in nodes.len {
                if !nodes[j].deleted && nodes[j].parent == i { has_child = true; break; }
            }
            if !has_child { nodes[i].deleted = true; }
        }
        depth--;
    }
}

// Deletes the descendants of deleted nodes. A child is always added after
// its parent, so one pass in order reaches every level.
fn propagate(nodes: PolicyNode[>..]&) {
    for j in nodes.len {
        let p = nodes[j].parent;
        if p >= 0 && nodes[p].deleted { nodes[j].deleted = true; }
    }
}

fn expects(exp: const Expected[:], node: i64, policy: const u8[:]) -> bool {
    for e in exp { if e.node == node && e.policy[..] == policy { return true; } }
    return false;
}

fn live_at(nodes: const PolicyNode[:], depth: i64) -> bool {
    for n in nodes { if !n.deleted && n.depth == depth { return true; } }
    return false;
}

fn add_node(nodes: PolicyNode[>..]&, exp: Expected[>..]&, depth: i64, parent: i64, policy: const u8[:]) -> bool {
    if nodes.len >= MAX_POLICY_NODES { return false; }
    var p: u8[..64] = [];
    p.append(policy);
    nodes.push(PolicyNode { depth: depth, parent: parent, policy: p, deleted: false });
    exp.push(Expected { node: nodes.len - 1, policy: p });
    return true;
}

// Runs policy processing over a path given top-down, without the trust
// anchor: certs[0] is issued by the anchor, certs[n - 1] is the leaf.
// OK, or ERR_POLICY when an explicit policy is required and none is left.
fn check_policies(certs: const u8[:], n: i64, opts: const Options&) -> i64 {
    let anyp = any_policy_oid();
    var nodes: PolicyNode[>..] = [];
    var exp: Expected[>..] = [];
    let ok0 = add_node(nodes, exp, 0, -1, anyp);
    var tree = true;                     // false once the tree is NULL
    var explicit_policy = if opts.require_explicit_policy { 0 } else { n + 1 };
    var inhibit_any = if opts.inhibit_any_policy { 0 } else { n + 1 };
    var policy_mapping = if opts.inhibit_policy_mapping { 0 } else { n + 1 };
    var off = 0;
    for i in 1..n + 1 {
        let c, next = cert_at(certs, off);
        if next < 0 { return ERR_MALFORMED; }
        off = next;
        let d = c.der[..];
        let self_iss = self_issued(c);
        // (d) and (e): grow the tree by this certificate's policies.
        if c.has_policies && tree {
            let pols, okp = cert_policies(c);
            if !okp { return ERR_MALFORMED; }
            var has_any = false;
            for p in pols {
                if p[..] == anyp[..] { has_any = true; continue; }
                var matched = false;
                for k in nodes.len {
                    if nodes[k].deleted || nodes[k].depth != i - 1 { continue; }
                    if expects(exp, k, p) {
                        if !add_node(nodes, exp, i, k, p) { return ERR_POLICY; }
                        matched = true;
                    }
                }
                if !matched {
                    for k in nodes.len {
                        if nodes[k].deleted || nodes[k].depth != i - 1 || nodes[k].policy[..] != anyp[..] { continue; }
                        if !add_node(nodes, exp, i, k, p) { return ERR_POLICY; }
                    }
                }
            }
            if has_any && (inhibit_any > 0 || (i < n && self_iss)) {
                let count = nodes.len;
                for k in count {
                    if nodes[k].deleted || nodes[k].depth != i - 1 { continue; }
                    // Every expected policy of k without a child for it yet.
                    let ecount = exp.len;
                    for e in ecount {
                        if exp[e].node != k { continue; }
                        let v = exp[e].policy;
                        var present = false;
                        for j in nodes.len {
                            if !nodes[j].deleted && nodes[j].parent == k && nodes[j].policy[..] == v[..] { present = true; }
                        }
                        if !present && !add_node(nodes, exp, i, k, v) { return ERR_POLICY; }
                    }
                }
            }
            prune(nodes, i - 1);
            if !live_at(nodes, i) { tree = false; }
        } else {
            tree = false;
        }
        // (f)
        if explicit_policy == 0 && !tree { return ERR_POLICY; }
        if i == n { break; }
        // Preparation for the next certificate (§6.1.4).
        if c.has_policy_mappings && tree {
            let ms, okm = asn1::children(d, c.policy_mappings);
            // Each issuerDomainPolicy once, with all its subject policies.
            var done: u8[..64][>..] = [];
            for m in ms {
                let pair, okp = asn1::children(d, m);
                let idp, ok1 = oid64(d, pair[0]);
                if !ok1 { return ERR_MALFORMED; }
                var seen = false;
                for x in done { if x[..] == idp[..] { seen = true; } }
                if seen { continue; }
                done.push(idp);
                var targets: u8[..64][>..] = [];
                for m2 in ms {
                    let pair2, okq = asn1::children(d, m2);
                    if d[pair2[0].off..pair2[0].end] == idp[..] {
                        let sdp, ok2 = oid64(d, pair2[1]);
                        if !ok2 { return ERR_MALFORMED; }
                        targets.push(sdp);
                    }
                }
                if policy_mapping > 0 {
                    var found = false;
                    for k in nodes.len {
                        if nodes[k].deleted || nodes[k].depth != i || nodes[k].policy[..] != idp[..] { continue; }
                        found = true;
                        // Replace the node's expected set by the mapped policies.
                        var keep: Expected[>..] = [];
                        for e in exp { if e.node != k { keep.push(e); } }
                        exp = copy(keep);
                        for tp in targets { exp.push(Expected { node: k, policy: tp }); }
                    }
                    if !found {
                        for k in nodes.len {
                            if nodes[k].deleted || nodes[k].depth != i || nodes[k].policy[..] != anyp[..] { continue; }
                            if !add_node(nodes, exp, i, nodes[k].parent, idp) { return ERR_POLICY; }
                            let fresh = nodes.len - 1;
                            var keep: Expected[>..] = [];
                            for e in exp { if e.node != fresh { keep.push(e); } }
                            exp = copy(keep);
                            for tp in targets { exp.push(Expected { node: fresh, policy: tp }); }
                        }
                    }
                } else {
                    for k in nodes.len {
                        if !nodes[k].deleted && nodes[k].depth == i && nodes[k].policy[..] == idp[..] { nodes[k].deleted = true; }
                    }
                    prune(nodes, i - 1);
                    if !live_at(nodes, i) { tree = false; }
                }
            }
        }
        if !self_iss {
            if explicit_policy > 0 { explicit_policy--; }
            if policy_mapping > 0 { policy_mapping--; }
            if inhibit_any > 0 { inhibit_any--; }
        }
        if c.require_explicit_policy >= 0 { explicit_policy = ::min(explicit_policy, c.require_explicit_policy); }
        if c.inhibit_policy_mapping >= 0 { policy_mapping = ::min(policy_mapping, c.inhibit_policy_mapping); }
        if c.inhibit_any_policy >= 0 { inhibit_any = ::min(inhibit_any, c.inhibit_any_policy); }
    }
    // Wrap-up (§6.1.5), at the leaf.
    let leaf, lnext = cert_at(certs, off);
    if explicit_policy > 0 { explicit_policy--; }
    if leaf.require_explicit_policy == 0 { explicit_policy = 0; }
    // (g): intersect with the acceptable policies, unless they are any.
    var user: u8[..64][>..] = [];
    var user_any = opts.policies.len == 0;
    for text in split(opts.policies, ' ') {
        if text.len == 0 { continue; }
        let enc, oke = asn1::oid_encode(text);
        if !oke || enc.len > 64 { return ERR_MALFORMED; }
        var o: u8[..64] = [];
        o.append(enc);
        if o[..] == anyp[..] { user_any = true; }
        user.push(o);
    }
    if tree && !user_any {
        // The valid_policy_node_set: nodes whose parent is an anyPolicy node.
        let count = nodes.len;
        for k in count {
            let par = nodes[k].parent;
            if nodes[k].deleted || par < 0 || nodes[par].policy[..] != anyp[..] { continue; }
            if nodes[k].policy[..] == anyp[..] { continue; }
            var accepted = false;
            for u in user { if u[..] == nodes[k].policy[..] { accepted = true; } }
            if !accepted { nodes[k].deleted = true; }
        }
        // An anyPolicy leaf node stands for every acceptable policy.
        for k in count {
            if nodes[k].deleted || nodes[k].depth != n || nodes[k].policy[..] != anyp[..] { continue; }
            for u in user {
                var present = false;
                for j in nodes.len {
                    if !nodes[j].deleted && nodes[j].depth == n && nodes[j].policy[..] == u[..] { present = true; }
                }
                if !present && !add_node(nodes, exp, n, nodes[k].parent, u) { return ERR_POLICY; }
            }
            nodes[k].deleted = true;
        }
        propagate(nodes);
        prune(nodes, n - 1);
        // Deleting at depth n may leave the tree empty.
        if !live_at(nodes, n) { tree = false; }
    }
    if explicit_policy == 0 && !tree { return ERR_POLICY; }
    return OK;
}
