# F-02: Object access checks the parent, not the child

> Every vulnerability here is deliberately constructed for education; none is a discovery in any third-party system.

| | |
|---|---|
| Boundary | TB3: what may you touch? (the engagement store and the object lookup) |
| Severity (in-scenario, educational) | High |
| Weakness | CWE-639 (Base); CWE-566 is the variant where the user-controlled key is the SQL primary key. Both are listed under OWASP Top 10:2025 A01. OWASP API1:2023 (Broken Object Level Authorization) is the nearest API category (the category was read, the mapping is a judgement) |
| ASVS 5.0.0 | 8.2.2 (L1, data-level access only with explicit permission), 8.4.1 (L2, cross-tenant controls; treating productions as tenants is a judgement), 16.3.2 (L2, log failed authorisation) |
| Seam | `assets.get_asset_in_scope`; the seeded twin is [labs/f02_parent_check/vulnerable.py](../../labs/f02_parent_check/vulnerable.py) |
| Reproduce | `python -m labs.f02_parent_check` or `pytest tests/findings/test_f02_object_scope.py -v` |
| Evidence | [docs/evidence/f02.txt](../evidence/f02.txt) |

Versions and retrieval dates for the mappings are in [references.md](../references.md). No level of any standard is claimed.

## 1. Context

The lab models two productions, ALPHA and BRAVO, each with its own vendors and coordinator and its own unreleased assets. A
vendor is engaged in a production for a time, and may read that production's assets. Asset ids are UUIDs, which is no
protection: ids leak through logs, shared manifests and links.

**Attacker capability.** An authenticated vendor with a genuine, current engagement in ALPHA and nothing else. It knows the id
of an unreleased BRAVO asset and can send HTTP requests to the application. It forges nothing and breaks no signature.

**Impact.** Cross-production reads of unreleased content: the headline risk of the scenario. Reading changes nothing, so the
impact is confidentiality only.

## 2. Boundary

TB3, between a caller who has proved who they are and the data they may touch. The route is
`/productions/{production_id}/assets/{asset_id}`: the URL names a production and an asset, and the application must decide
whether this caller may read **this asset**. Authentication (TB1/TB2) and the engagement on the URL's production are not at
issue and are the same in both variants.

## 3. Vulnerable code and root cause

[labs/f02_parent_check/vulnerable.py](../../labs/f02_parent_check/vulnerable.py) (the whole file is one function). The lookup
asks whether the caller is engaged in the production **named in the URL** (the parent), and then loads the asset by its id
alone, without asking whether that asset belongs to that production (the child):

```text
SELECT … FROM assets AS a WHERE a.id = ?
  AND EXISTS (SELECT 1 FROM engagements … WHERE e.production_id = ?  -- the URL's production
              AND subject, not revoked, not ended)
```

The check exists, so the function passes a quick read; it guards the wrong object. The single mistake is that
`a.production_id` is never compared with the URL's production.

## 4. Exploitation scenario

Deterministic, in a throwaway synthetic world ([labs/world.py](../../labs/world.py)); the scenario is
[labs/f02_parent_check/scenario.py](../../labs/f02_parent_check/scenario.py) and is the same code for both variants.

1. A vendor engaged only in ALPHA reads an ALPHA asset through the ALPHA url. This works in both variants (control).
2. The same vendor asks for BRAVO's asset **through the ALPHA url**. This is the exploit.
3. It asks for a nonexistent id, for BRAVO's asset through the BRAVO url, and with no token, to show what is and is not at issue.
4. A vendor engaged in **both** productions asks for BRAVO's asset through the ALPHA url, and then through the BRAVO url.
5. An ALPHA coordinator asks for BRAVO's asset through the ALPHA url.

## 5. Corrected code

The reference, [assets.get_asset_in_scope](../../src/content_boundary_lab/assets.py), binds the asset, **its real production**,
the production the request named and the caller's current engagement in one parameterised statement. Anything that does not
match is one and the same 404, whether the asset is missing, belongs elsewhere or is malformed, and the refusal is recorded as
`access.denied` (`not_found_or_forbidden`). Tokens, roles and the engagement on the URL's production are checked first, as in
both variants.

**A naive fix does not do this.** Checking only "is the caller engaged where the asset lives?" repairs the headline case and
leaves the caller who is engaged in both productions able to read BRAVO's asset through ALPHA's url: the relationship between
the URL and the asset's owner is not enforced.
`tests/findings/test_f02_object_scope.py::test_a_naive_fix_that_checks_the_assets_own_production_but_not_the_url_still_leaks_to_a_caller_engaged_in_both`
shows it.

### Remediation matrix

[labs/f02_parent_check/matrix.py](../../labs/f02_parent_check/matrix.py) runs fourteen attempts against four applications:
the reference (R), the seeded variant (V), the naive fix above (N1) and a different, complete fix (A1) that requires the asset
to belong to the production the request named. Verbatim from [docs/evidence/f02-matrix.txt](../evidence/f02-matrix.txt).

```text
row  kind        R    V    N1   A1   what
L1   legitimate  yes  yes  yes  yes  an ALPHA vendor reads ALPHA's asset through the ALPHA url
L4   legitimate  yes  yes  yes  yes  a vendor engaged in both reads each asset through its own production's url
X1   exploit     yes  NO   yes  yes  the original exploit: an ALPHA-only vendor asks for BRAVO's asset through the ALPHA url
X4   exploit     yes  NO   NO   yes  a vendor engaged in BOTH asks for BRAVO's asset through the ALPHA url
X5   exploit     yes  NO   NO   yes  a vendor engaged in BOTH asks for ALPHA's asset through the BRAVO url
B2   boundary    yes  NO   yes  yes  a refusal is byte-identical to the answer for an asset that does not exist
B4   boundary    yes  yes  yes  yes  a revoked vendor is refused its own production's asset
R   fails: none  [as expected]
V   fails: X1, X2, X3, X4, X5, B2  [as expected]
N1  fails: X4, X5  [as expected]
A1  fails: none  [as expected]
```

What it shows. The reference holds every row, including every legitimate read, and the original exploit (X1) is blocked. N1
passes X1 and fails only X4 and X5: it repairs every caller engaged in one production, which is why it looks fixed, and fails
the callers engaged in both, because the asset's production was never bound to the production that was authorised. A1 passes
every row, so the matrix measures the security condition (an asset is served only through the production that owns it, and a
refusal reveals nothing about whether it exists) and not the reference's wording. The audit assertions are in
`tests/findings/test_audit_assertions.py::test_a_denied_cross_production_read_records_one_denial_and_no_successful_read`.

## 6. Before and after results

Verbatim from [docs/evidence/f02.txt](../evidence/f02.txt) (lines elided with … are in the file).

```text
== REFERENCE
  2. the same vendor asks for BRAVO's asset through the ALPHA url
       -> 404 {"detail":"Not found"}
  3. what the audit trail recorded for that request
       -> access.denied denied (not_found_or_forbidden), production ALPHA, object BRAVO asset
  5. is the refusal the same as for a missing asset?
       -> True
  7. a vendor engaged in BOTH asks for BRAVO's asset through the ALPHA url
       -> 404 {"detail":"Not found"}
…
== SEEDED VARIANT (only the seam above is swapped)
  2. the same vendor asks for BRAVO's asset through the ALPHA url
       -> 200, 3500 bytes: exactly BRAVO's asset
  3. what the audit trail recorded for that request
       -> asset.read allowed, production ALPHA, object BRAVO asset
  5. is the refusal the same as for a missing asset?
       -> False
  7. a vendor engaged in BOTH asks for BRAVO's asset through the ALPHA url
       -> 200, 3500 bytes: exactly BRAVO's asset
  9. an ALPHA coordinator asks for BRAVO's asset through the ALPHA url
       -> 200, 3500 bytes: exactly BRAVO's asset

RESULT     seeded variant exploited: YES   reference blocked: YES
```

In the seeded variant the audit trail records BRAVO's asset as an ordinary read in ALPHA: the read is real and its attribution
is wrong. For the caller engaged in both productions the data was reachable anyway; what the flaw breaks is the binding
between the URL and the asset's owner (and with it any rule, report or alert keyed on the production of a request).

## 7. Residual risk and assumptions

- Access is scoped **per production**. Over-exposure within a production (a vendor reading another vendor's asset of the same
  production) is not addressed (design decision D4).
- The lab proves the corrected lookup blocks the cases above under the stated assumptions; it does not prove no other route
  has the same flaw, and the one asset route is the only object read in the lab.
- The remediation matrix above covers the roles, the productions and the naive-fix bypasses it lists; it is not a proof that
  no other route has the same flaw.
- Everything is synthetic: made-up identities and bytes, a key made in memory, no network. Nothing here describes any real
  system.
