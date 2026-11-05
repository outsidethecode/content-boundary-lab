# F-06: Authorisation snapshot in a long-lived token

> Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

| | |
|---|---|
| Boundary | TB3: what may you touch? (the authorisation decision, made after authentication) |
| Severity (in-scenario, educational) | Medium |
| Weakness | CWE-863, a Class that MITRE marks "Allowed-with-Review": no Base child fits stale authorisation better, which is why it is used; CWE-1464 (Improper Session Invalidation) is related. CWE-613 is deprecated and "Prohibited" for mapping, so it is not used |
| ASVS 5.0.0 | 8.3.2 (L3, authorisation changes apply immediately, or compensating controls exist), 7.4.2 (L1, end sessions when an account is disabled), 9.2.1 (L1, enforce token validity times) |
| Seam | `authz.authorize_engagement`; the seeded twin is [labs/f06_stale_authorisation/vulnerable.py](../../labs/f06_stale_authorisation/vulnerable.py) |
| Reproduce | `python -m labs.f06_stale_authorisation` or `pytest tests/findings/test_f06_stale_authorisation.py -v` |
| Evidence | [docs/evidence/f06.txt](../evidence/f06.txt) |

Versions and retrieval dates for the mappings are in [references.md](../references.md). No level of any standard is claimed.

## 1. Context

A vendor is given a signed, short-lived token by the identity provider and an engagement in a production by a coordinator.
The coordinator can revoke the engagement at any time, and every engagement has an end date. The requirement the lab states
for itself is **immediate revocation for time-boxed external access to unreleased content**.

**Attacker capability.** A former vendor, or one whose time has run out, who still holds a token that has not expired. It does
nothing but use the token. It forges nothing.

**Impact.** The vendor keeps the access the coordinator took away for as long as the token lives: it can still see its
engagement and still declare new deliveries. Revocation during a suspected leak fails exactly when it matters.

**Honesty note.** ASVS 8.3.2 explicitly allows compensating controls where self-contained tokens make immediate revocation
impossible. F-06 is a finding **against this lab's stated requirement**, not a claim that authorising from token claims is wrong
everywhere. The reference application does not rely on a compensating control: it asks the engagement store on every request.

## 2. Boundary

TB3. Authentication (TB1/TB2) succeeds in both variants and is not the subject: the token is signed by the same key and
verifies in the reference's own verifier after the revocation. What differs is the decision made on the verified identity.

## 3. Vulnerable code and root cause

[labs/f06_stale_authorisation/vulnerable.py](../../labs/f06_stale_authorisation/vulnerable.py) (the whole file is one function).
It authorises from the `productions` claim that the identity provider baked into the token when it issued it, and never looks
at the engagement store:

```python
role = (claims.get("productions") or {}).get(production_id)   # a snapshot, taken at issuance
if role is None: raise AuthorizationDenied(NO_ENGAGEMENT)
```

The root cause is treating a claim about the past as the current state. Revoking the engagement, or reaching its end date,
changes the store and not the token.

**The seam.** M0's Addendum calls it `active_engagement`; no function of that name exists in `src/`, and none was added. The
actual decision boundary is `authz.authorize_engagement`, which every route reaches through the shared request flow, and that
is what the lab replaces. The reference deliberately keeps only the issuer and subject of a verified token, so a twin that
reads claims needs somewhere to read them: [labs/carrier.py](../../labs/carrier.py) copies the bearer token's payload into a
context variable for the length of one request. It verifies nothing and decides nothing (the reference has already verified
the token before it reaches authorisation), and it wraps the application in both variants, so it is not what differs.

## 4. Exploitation scenario

Scenario: [labs/f06_stale_authorisation/scenario.py](../../labs/f06_stale_authorisation/scenario.py).

1. A vendor with an active ALPHA engagement uses its signed token: it asks for its engagement and declares a delivery.
2. The ALPHA coordinator revokes the engagement.
3. The same token still verifies, as the same subject.
4. The vendor asks for its engagement again, and declares another delivery, with the same token. This is the exploit.
5. A vendor whose engagement ends in five minutes asks for it, then asks again 301 seconds later, past the end date and
   inside the token's life.
6. A BRAVO-only vendor presents a token whose claim names ALPHA.

The resources measured are the two that only the engagement decision guards. The asset route is deliberately not one: its
lookup re-checks the engagement in the same statement (the F-02 control), so it stays closed after a revocation in both
variants (403 in the reference, 404 in the seeded variant, never the bytes). The lab does not add a second flaw to make the
finding easier to see.

## 5. Corrected code

The reference, [authz.authorize_engagement](../../src/content_boundary_lab/authz.py), takes the verified issuer and subject
only, looks the engagement up in SQLite on every request, inside the request's transaction and on the request's one clock
reading, and refuses a missing, revoked or ended engagement or a role the action is not in. Tokens carry identity and
nothing the application believes about permissions, and are capped at ten minutes. The end date of an engagement is mandatory
and capped.

### Remediation matrix

[labs/f06_stale_authorisation/matrix.py](../../labs/f06_stale_authorisation/matrix.py) runs twenty attempts against four
applications: the reference (R), the seeded variant (V), and two naive fixes. N1 checks the token again for validity and still
believes its claim. N2 reads the engagement store on every request and honours a revocation but forgets that an engagement also
ends. The boundary rows use an injected clock and the exact instants (one microsecond before the end date, the end date itself,
one microsecond after); the T rows damage the token in the ways M0 lists (algorithm none, another key, another issuer or
audience, expired, not yet valid, a spoofed identity header). Verbatim from
[docs/evidence/f06-matrix.txt](../evidence/f06-matrix.txt).

<!-- evidence: docs/evidence/f06-matrix.txt -->
```text
row  kind        R    V    N1   N2   what
L4   legitimate  yes  NO   NO   yes  authorisation does not depend on the token's claims: a token with none still works
L5   legitimate  yes  yes  yes  yes  the last instant of an engagement (one microsecond before its end) is served
X1   exploit     yes  NO   NO   yes  the original exploit: the same token, the first request after the revocation
X3   boundary    yes  NO   NO   NO   exactly at the end date (now = ends_at) the engagement is over
X4   boundary    yes  NO   NO   NO   one microsecond after the end date it is still over
X6   boundary    yes  NO   NO   yes  a token whose claim names a higher role grants nothing: the role comes from the store
X7   boundary    yes  yes  yes  yes  a delivery uploaded before the revocation cannot be sealed after it
T1   boundary    yes  yes  yes  yes  a token with the algorithm 'none' is a 401
T5   boundary    yes  yes  yes  yes  an expired token is a 401
T7   boundary    yes  yes  yes  yes  a valid vendor token with a coordinator's name in a header acts as the vendor
R   fails: none  [as expected]
V   fails: L4, X1, X2, X3, X4, X5, X6  [as expected]
N1  fails: L4, X1, X2, X3, X4, X5, X6  [as expected]
N2  fails: X3, X4  [as expected]
```

What it shows. Validating a JWT's signature and expiry does not prove that an engagement granted earlier is still active: N1
fails exactly the rows the seeded variant fails, because the reference's verifier has already refused every invalid token and
re-checking it adds nothing. N2 does consult the store and is right on the first request after a revocation (X1 holds), and is
wrong at the end date and after it (X3, X4): only the exact-boundary rows tell it from the reference, and L5 shows that the
last instant before the end date is still served. The seeded variant also fails L4, a legitimate row: it refuses a token that
carries no claim, so its authority is the claim and not the engagement. The T rows hold in every variant, which is why F-06
is a finding about authorisation and not about the verifier. The audit assertions are in
`tests/findings/test_audit_assertions.py::test_a_revoked_vendors_denied_requests_are_recorded_with_who_where_and_why`.

## 6. Before and after results

Verbatim from [docs/evidence/f06.txt](../evidence/f06.txt) (lines elided with … are in the file).

<!-- evidence: docs/evidence/f06.txt -->
```text
== REFERENCE
  3. the SAME token still verifies, as the same subject
       -> signature, issuer, audience and times are good for vendor-alpha-1
  4. the vendor asks for its engagement with that token
       -> 403 Forbidden
  5. what the audit trail recorded for that request
       -> access.denied denied (engagement_revoked), by vendor-alpha-1
  6. the vendor declares another delivery with that token
       -> 403; deliveries created after the revocation: 0
…
== SEEDED VARIANT (only the seam above is swapped)
  3. the SAME token still verifies, as the same subject
       -> signature, issuer, audience and times are good for vendor-alpha-1
  4. the vendor asks for its engagement with that token
       -> 200 vendor
  5. what the audit trail recorded for that request
       -> engagement.viewed allowed, by vendor-alpha-1
  6. the vendor declares another delivery with that token
       -> 201; deliveries created after the revocation: 1
  8. a vendor whose engagement ends in five minutes asks for it, then asks again 301 seconds later (past the end date, inside the token's life)
       -> 200, then 200

RESULT     seeded variant exploited: YES   reference blocked: YES
```

## 7. Residual risk and assumptions

- **The window is the token's life.** The reference caps a token at ten minutes (a lab assumption), so the staleness window of
  the seeded variant here is at most ten minutes, not the twelve hours of the M0 narrative: the lab keeps authentication intact
  in both variants rather than weaken it to lengthen the window. After the token expires the request is a 401 in both
  (`tests/findings/test_f06_stale_authorisation.py::test_the_window_is_the_life_of_the_token_and_no_longer`).
- A claim in the seeded variant is an authority: a token whose claim names a production it has no engagement in grants access
  to it (step 6). That is the same flaw, not a second one.
- Revocation of the identity itself (disabling the account at the identity provider) is not modelled, and a token stays valid
  until it expires in the reference too; the reference's answer is that authorisation is nil once the engagement is revoked.
- The lab shows the seeded decision is stale and the reference's is not under the stated assumptions; it says nothing about
  any real identity provider, whose claims and lifetimes differ.
- Everything is synthetic: made-up identities, a signing key made in memory, no network.
