#!/usr/bin/env python3
"""AAE receiver-side verifier — clean-room implementation.

Written from the text of draft-kroehl-agentic-trust-aae-00 (Sections 2.4, 3, 5)
and the vector-format description in the vectors repo README (lines 1-82 at the
pin). The reference verifier source (examples/python-verify.py) was NOT read.
DID resolution is the offline testkey mapping described by the vectors repo's
testkeys/ directory layout.

Step numbering follows the vectors' expected verification_step:
  1 signature + signing authority
  2 payload & schema (incl. cty)
  3 temporal validity
  4 subject binding (challenge-response flag from harness context)
  5 single-use
  6 action check
  7 constraint evaluation
  8 revocation check
  9 delegation chain (ancestors, subordination, depth, cycles)
"""
import base64, hashlib, json, sys, os
from datetime import datetime, timezone
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

RECOGNIZED = ("max_transaction_value", "allowed_domains", "rate_limit")


def b64u(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def jws_parts(token):
    p0, p1, p2 = token.split(".")
    return (
        json.loads(b64u(p0)),
        json.loads(b64u(p1)),
        b64u(p2),
        (p0 + "." + p1).encode("ascii"),
    )


def resolve_did(did, keydir):
    if not did.startswith("did:web:"):
        return None
    name = did.split(":")[-1]
    p = os.path.join(keydir, name + ".json")
    return json.load(open(p)) if os.path.exists(p) else None


def vm_key(doc, vm_id):
    for vm in doc.get("verificationMethod", []):
        if vm["id"] == vm_id:
            j = vm.get("publicKeyJwk", {})
            if j.get("kty") == "OKP" and j.get("crv") == "Ed25519":
                return Ed25519PublicKey.from_public_bytes(b64u(j["x"]))
    return None


def authorized(doc, vm_id, purpose):
    return vm_id in doc.get(purpose, [])


def parse_time(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).astimezone(timezone.utc)


def sig_step(h, payload, sig, signing_input, keydir):
    """Step 1: signature verification + signing authority."""
    if h.get("alg") != "EdDSA":
        return "alg_not_eddsa"
    kid = h.get("kid", "")
    did = kid.split("#")[0] if "#" in kid else kid
    doc = resolve_did(did, keydir)
    if doc is None:
        return "did_unresolvable"
    if not authorized(doc, kid, "assertionMethod"):
        return "vm_not_assertion_method"
    key = vm_key(doc, kid)
    if key is None:
        return "key_not_ed25519"
    try:
        key.verify(sig, signing_input)
    except Exception:
        return "signature_invalid"
    aae = payload["credentialSubject"]["aae"]
    issuer = payload["issuer"]
    delg = aae["mandate"].get("delegation")
    if delg is None:
        if did != issuer:
            return "signing_authority_mismatch"
        return None
    dd = delg["delegator_did"]
    if did == dd and issuer == dd:
        return None  # case (a)
    ddoc = resolve_did(dd, keydir)
    if ddoc is not None:
        for vm in ddoc.get("verificationMethod", []):
            if vm["id"] in ddoc.get("assertionMethod", []) and vm["id"].split("#")[0] == dd:
                if did == dd:
                    return None
    return "signing_authority_mismatch"


def schema_step(h, payload):
    """Step 2."""
    if h.get("cty") != "aae+json":
        return "cty_mismatch"
    for m in ("id", "issuer"):
        if m not in payload:
            return "vc_member_missing"
    cs = payload.get("credentialSubject", {})
    if "id" not in cs or "aae" not in cs:
        return "vc_member_missing"
    aae = cs["aae"]
    for m in ("mandate", "constraints", "validity"):
        if m not in aae or not isinstance(aae[m], dict):
            return "aae_member_missing"
    return None


def temporal_step(aae, now):
    """Step 3."""
    v = aae["validity"]
    if not (parse_time(v["not_before"]) <= now <= parse_time(v["not_after"])):
        return "outside_validity_window"
    return None


def constraint_eval(constraints, ctx):
    """Step 7."""
    ac = ctx.get("action_context", {})
    for name, spec in (constraints or {}).items():
        required = spec.get("required", True) if isinstance(spec, dict) else True
        if name not in RECOGNIZED:
            if required:
                return "unrecognized_required_constraint"
            continue
        if name == "max_transaction_value":
            amount = ac.get("amount")
            if amount is not None:
                if ac.get("currency") != spec.get("currency") or amount > spec.get("value", 0):
                    return "constraint_violated_max_transaction_value"
        elif name == "allowed_domains":
            dom = ac.get("domain")
            if dom is not None and dom not in spec.get("value", []):
                return "constraint_violated_allowed_domains"
    return None


def revocation_step(aae, vc_id, ctx):
    """Step 8, per Section 2.4: 5xx / absent / unparseable => reject (no fail-open)."""
    tmpl = aae["validity"].get("revocation_check")
    if not tmpl:
        return None
    resp = ctx.get("revocation_responses", {}).get(vc_id)
    if resp is None:
        return "revocation_status_indeterminate"
    status = resp.get("http_status")
    if status is not None and 500 <= status < 600:
        return "revocation_status_indeterminate"
    body = resp.get("body")
    if body is not None:
        if not isinstance(body, dict) or body.get("id") != vc_id or not isinstance(body.get("revoked"), bool):
            return "revocation_response_unparseable"
        if body["revoked"]:
            return "revoked"
    elif resp.get("revoked") is True:
        return "revoked"
    return None


def subordination(child_aae, parent_aae):
    """Section 3: actions subset; numeric upper bounds and currency not relaxed."""
    child_mandate, parent_mandate = child_aae["mandate"], parent_aae["mandate"]
    if not set(child_mandate.get("actions", [])) <= set(parent_mandate.get("actions", [])):
        return "delegation_action_superset"
    pc = parent_aae.get("constraints") or {}
    cc = child_aae.get("constraints") or {}
    for name in RECOGNIZED:
        if name in cc and name in pc and name == "max_transaction_value":
            c, p = cc[name], pc[name]
            if c.get("value", 0) > p.get("value", 0):
                return "delegation_constraint_relaxation"
            if c.get("currency") != p.get("currency"):
                return "delegation_currency_mismatch"
    return None


def verify_aae(token, ctx, keydir, now, consumed):
    try:
        h, payload, sig, signing_input = jws_parts(token)
    except Exception as e:
        return "REJECT", 1, "jws_unparseable:" + str(e), None

    r = sig_step(h, payload, sig, signing_input, keydir)
    if r:
        return "REJECT", 1, r, None
    aae = payload["credentialSubject"]["aae"]
    vc_id = payload["id"]

    r = schema_step(h, payload)
    if r:
        return "REJECT", 2, r, aae
    r = temporal_step(aae, now)
    if r:
        return "REJECT", 3, r, aae
    sb = ctx.get("subject_binding", {})
    if sb.get("challenge_response_valid") is not True:
        return "REJECT", 4, "subject_binding_failed", aae
    if vc_id in consumed:
        return "REJECT", 5, "single_use_already_consumed", aae
    if ctx.get("requested_action") not in aae["mandate"].get("actions", []):
        return "REJECT", 6, "action_not_in_mandate", aae
    r = constraint_eval(aae.get("constraints") or {}, ctx)
    if r:
        return "REJECT", 7, r, aae

    delg = aae["mandate"].get("delegation")
    r = revocation_step(aae, vc_id, ctx)
    if r:
        return "REJECT", 8, r, aae

    if delg is None:
        return "ACCEPT", 9, None, aae

    # step 9: delegation chain
    depth, maxd = delg["depth"], delg["max_depth"]
    if depth > maxd:
        return "REJECT", 9, "delegation_depth_exceeded", aae
    chain = ctx.get("delegation_chain", [])
    if not chain:
        return "REJECT", 9, "delegation_chain_missing", aae

    visited = {vc_id}
    anc_aaes = []
    for anc_token in chain:
        try:
            ah, ap, asig, asin = jws_parts(anc_token)
        except Exception:
            return "REJECT", 9, "ancestor_jws_unparseable", aae
        # ancestor steps 1,2,3,8 (no subject-binding/single-use, per Section 5 step 9)
        r = sig_step(ah, ap, asig, asin, keydir)
        if r:
            return "REJECT", 9, "ancestor_step1:" + r, aae
        anc = ap["credentialSubject"]["aae"]
        anc_id = ap["id"]
        r = schema_step(ah, ap)
        if r:
            return "REJECT", 9, "ancestor_step2:" + r, aae
        r = temporal_step(anc, now)
        if r:
            return "REJECT", 9, "ancestor_step3:" + r, aae
        r = revocation_step(anc, anc_id, ctx)
        if r:
            return "REJECT", 9, "ancestor_step8:" + r, aae
        if anc_id in visited:
            return "REJECT", 9, "delegation_cycle", aae
        visited.add(anc_id)
        # chain is ordered root -> immediate parent; each ancestor must be
        # subordinate to its own parent within the chain
        if anc_aaes:
            r = subordination(anc, anc_aaes[-1])
            if r:
                return "REJECT", 9, "chain_" + r, aae
        anc_aaes.append(anc)

    # child links to the immediate parent = last chain element
    parent = anc_aaes[-1]
    child_delg = delg
    ddid = child_delg["delegator_did"]
    if ap["credentialSubject"]["id"] != ddid:
        return "REJECT", 9, "delegator_binding_mismatch", aae
    if "delegator_aae_hash" in child_delg:
        want = child_delg["delegator_aae_hash"].split(":", 1)[1]
        got = base64.urlsafe_b64encode(hashlib.sha256(chain[-1].encode("ascii")).digest()).rstrip(b"=").decode()
        if got != want:
            return "REJECT", 9, "delegator_aae_hash_mismatch", aae
    r = subordination(aae, parent)
    if r:
        return "REJECT", 9, r, aae
    # depth bookkeeping: root ancestor must declare delegation_policy
    eff_maxd = maxd
    root = anc_aaes[0]
    root_delg = root["mandate"].get("delegation")
    if root_delg is None:
        pol = (root["mandate"].get("delegation_policy") or {}).get("max_depth")
        if pol is None:
            return "REJECT", 9, "root_without_delegation_policy", aae
        eff_maxd = min(eff_maxd, pol)
    else:
        eff_maxd = min(eff_maxd, root_delg["max_depth"])
    for anc in anc_aaes[1:]:
        eff_maxd = min(eff_maxd, anc["mandate"]["delegation"]["max_depth"])
    if delg["depth"] > eff_maxd:
        return "REJECT", 9, "delegation_depth_exceeded", aae
    return "ACCEPT", 9, None, aae


def main():
    vecdir, keydir = sys.argv[1], sys.argv[2]
    out = []
    for fn in sorted(os.listdir(vecdir)):
        if not fn.endswith(".json") or fn == "enforce" or os.path.isdir(os.path.join(vecdir, fn)):
            continue
        v = json.load(open(os.path.join(vecdir, fn)))
        ctx = v["input"]["context"]
        consumed = set(ctx.get("consumed_ids", []))
        now = parse_time(ctx["current_time"])
        result, step, reason, _ = verify_aae(v["input"]["secured_aae"], ctx, keydir, now, consumed)
        exp = v["expected"]
        match = result == exp["result"] and (result == "ACCEPT" or step == exp["verification_step"])
        out.append({
            "vector": v["id"], "file": fn,
            "our_result": result,
            "our_step": step if result == "REJECT" else None,
            "our_reason": reason,
            "expected_result": exp["result"],
            "expected_step": exp.get("verification_step"),
            "match": match,
        })
    print(json.dumps(out, indent=1))
    bad = [r for r in out if not r["match"]]
    print(f"\n{len(out) - len(bad)}/{len(out)} vectors match", file=sys.stderr)
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
