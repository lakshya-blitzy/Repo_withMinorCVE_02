# lodash remediation report — GHSA-f23m-r3pf-42rh (CVE-2026-2950)

Closure record for the `lodash` version move in this repository, transcribed from the values the
remediation run measured. `package-lock.json` carries four changed values and `package.json` the
mirrored pin; `"server (1).js"` is unchanged. No source or configuration file needed a change: the
vulnerable implementation is the published library, and nothing in this repository calls a lodash
function.

## 1. Target release and provenance

| Attribute | Value |
|---|---|
| Release installed | `lodash@4.18.1` |
| Advisory closed | GHSA-f23m-r3pf-42rh / CVE-2026-2950, CWE-1321 — prototype pollution in `_.unset` and `_.omit` via array-wrapped path segments |
| Affected range | GHSA-f23m-r3pf-42rh's own affected set for `lodash`, `lodash-es` and `lodash-amd` is `= 4.17.23`, patched in 4.18.1. The wider `<=4.17.23` npm's package-level scan reports for the package on the 4.17.15 tree (§5) is an aggregate contributed by the sibling advisories named in §6, not by this one, and 4.17.15 lies outside this advisory's set altogether — what the 4.17.15 tree really carried is the earlier `_.unset`/`_.omit` advisory GHSA-xxjr-mmjv-4gpg / CVE-2025-13465 (`>=4.0.0 <4.17.23`), which the same bump clears |
| Version this repository carried | 4.17.15, pinned at `package.json:5`, `package-lock.json:11` and `package-lock.json:15` — outside this advisory's affected set (`= 4.17.23`); the advisory the 4.17.15 tree was inside is GHSA-xxjr-mmjv-4gpg / CVE-2025-13465 (`>=4.0.0 <4.17.23`) together with the four other siblings in §6, all cleared by the same move |
| Advisory databases' first-patched release | 4.18.1 for `lodash`, `lodash-es` and `lodash-amd` — the GitHub Advisory Database's `first_patched_version`, OSV's `fixed` event and the CVE record's unaffected version — and 4.18.0 only for the standalone `lodash.unset`/`lodash.omit` packages. 4.18.0 carries the same guard, but 4.18.1 is targeted instead because it is the version the CVE record and NVD call unaffected for `lodash`, the version `npm audit` itself offers as the fix, the current `latest` dist-tag, and the only one of the two that is not deprecated as a bad release — npm's deprecation notice for 4.18.0 reads `Bad release. Please use lodash@4.17.21 instead.` (re-read with `npm view lodash@4.18.0 deprecated` during the run), because 4.18.0 shipped a broken template build (`ReferenceError: assignWith is not defined`, lodash issue #6167). 4.18.1 is not a source-identical republish of 4.18.0: nine files differ between the two published tarballs, the `_.unset`/`_.omit` guard itself byte-equal except for one dropped advisory-comment line, while `template.js` and `fromPairs.js` add the requires that repair 4.18.0's broken template build |
| Version line the fix stays inside | `lodash` 4.x — no major-version jump. Advisories left open elsewhere on the line are not a licence to leave it, and the release that npm's deprecation notice for 4.18.0 names (4.17.21) still sits inside two advisory ranges (GHSA-r5fr-rjxr-66jc `>=4.0.0 <=4.17.23` and GHSA-xxjr-mmjv-4gpg `>=4.0.0 <=4.17.22`, measured with `npm audit --json` against a lockfile pinned to 4.17.21). The target carries no advisory of its own |
| Registry resolution | `https://registry.npmjs.org/lodash/-/lodash-4.18.1.tgz`, published digest `sha512-dMInicTPVE8d1e5otfwmmjlxkZoUpiVLwyeTdUsi/Caj/gfzzblBcCE5sRHV/AsjuCmxWrte2TNGSYuCeCq+0Q==`, not deprecated, not unpublished — re-read from `npm view lodash@4.18.1 dist.integrity dist.tarball` and `npm view lodash dist-tags` (`{ latest: '4.18.1' }`) during the run |

The change was applied by **editing both manifests directly and installing with `npm ci`**, never
`npm install`, and never with `npm audit fix --force` (which would rewrite the exact pin as the caret
range `^4.18.1`). The project's own recorded remediation mechanism was `npm install lodash@4.18.1
--save-exact`, which preserves the exact pin by construction; the request forbids `npm install`
outright and mandates `npm ci`, so the version, the resolved URL and the integrity digest were edited
by hand — a hand edit cannot write a caret — and the install ran as `npm ci --no-fund` from the
rewritten lockfile. Both constraints hold at once.

## 2. Severity, root cause and the advisory's guidance

**Severity, stated once here and used consistently.** This advisory is **moderate**: the CNA's
(openjs) CVSS 3.1 base score is **6.5** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L`) and NVD
publishes **5.3** (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N`), noting that its score differs from
the CNA's. The aggregate `npm audit` reports for the `lodash` *package* at 4.17.15 is **high**, measured
in this run as `metadata.vulnerabilities = {info:0, low:0, moderate:0, high:1, critical:0, total:1}`
(§5) — one package flagged `high` because the five other advisories on the package ride on it, not because
this advisory is high. The two figures measure different things and are not conflated anywhere in this
report; the per-advisory column in §6 is npm's severity for each advisory, stated as reported.

**Root cause.** lodash 4.17.23 addressed CVE-2025-13465 (GHSA-xxjr-mmjv-4gpg), the earlier prototype
pollution in `_.unset` and `_.omit`, with a **string-key-only guard**: it blocks `__proto__`,
`constructor` and `prototype` only when they appear as string path members. That guard does not inspect
array-wrapped segments of the same path, so a caller that passes the path as an array still bypasses it
and reaches the prototype chain, deleting properties from `Object.prototype`, `Number.prototype` and
`String.prototype`. Deleting a built-in member is a denial of service against any code that later calls
it; the advisory is explicit that the original behaviour cannot be overwritten. The affected range npm's
scan reports for the package on the 4.17.15 tree is `<= 4.17.23` (§5), an aggregate of the sibling
advisories; this advisory's own affected set is narrower — `= 4.17.23`, patched in 4.18.1 — so 4.17.15
lies outside it and was vulnerable through the earlier `_.unset`/`_.omit` advisory
GHSA-xxjr-mmjv-4gpg (`>=4.0.0 <4.17.23`), which the same bump clears.

**Guidance.** The advisory states there is **no workaround**: it prescribes **upgrading** and nothing
else, so the remediation is the version move rather than a code-level guard, a package substitution or
a suppressed finding. The general prototype-pollution hardening guidance (reject `__proto__`,
`constructor` and `prototype` segments in set-by-path helpers, prefer `Map`, freeze built-in
prototypes) is recorded for completeness and deliberately not applied as a code change: there is no
call site to harden (§8), and no source change is in this fix's scope.

## 3. The committed lockfile entry, quoted verbatim

`package-lock.json` after the change (537 bytes before, 534 bytes after; exactly four values moved):

```json
{
  "name": "cve-test-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {
      "name": "cve-test-fixture",
      "version": "1.0.0",
      "dependencies": {
        "lodash": "4.18.1"
      }
    },
    "node_modules/lodash": {
      "version": "4.18.1",
      "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.18.1.tgz",
      "integrity": "sha512-dMInicTPVE8d1e5otfwmmjlxkZoUpiVLwyeTdUsi/Caj/gfzzblBcCE5sRHV/AsjuCmxWrte2TNGSYuCeCq+0Q==",
      "license": "MIT"
    }
  }
}
```

Unchanged by the edit: `"lockfileVersion": 3`, `"requires": true`, `"license": "MIT"`, the entry's
field order `version`, `resolved`, `integrity`, `license`, the `packages` key set
`["", "node_modules/lodash"]`, two-space indentation, LF endings and the trailing newline. No
`overrides`, `resolutions` or `hasInstallScript` key was added to either manifest
(`grep -nE '"(overrides|resolutions|hasInstallScript)"' package.json package-lock.json` → exit 1), and
no key was added to the `node_modules/lodash` entry, which still carries exactly `version`, `resolved`,
`integrity` and `license`. The `dependencies` key is not new either: it is the root record's
pre-existing key at `package-lock.json:10`, still holding the single pin, now `4.18.1`
(`package-lock.json:11`). No range operator appears next to either pin
(`grep -nE 'lodash": *"[\^~x*]' package.json package-lock.json` → exit 1).

## 4. Install evidence

| Check | Command | Result |
|---|---|---|
| Install from the rewritten lockfile | `CI=true npm ci --no-fund` | exit **0** — `added 1 package, and audited 2 packages`; `found 0 vulnerabilities` |
| Installed module version | `node -p "require('lodash').VERSION"` | `4.18.1` |
| Installed package manifest | `node -p "require('./node_modules/lodash/package.json').version"` | `4.18.1` |
| Derived tree record | `node -p "require('./node_modules/.package-lock.json').packages['node_modules/lodash'].version"` | `4.18.1` (derived, untracked, not committed) |
| Rewrite not served from a warm cache | `CI=true npm ci --no-fund --cache <fresh-cache-dir>` | exit **0** with an empty cache, resolving `4.18.1` |
| Manifest, root record and entry agree | `node -p` over all three | `4.18.1\|4.18.1\|4.18.1` |

## 5. Scan evidence

Run online from the repository root after the install. `npm audit --offline` is not used as evidence
here: it reports `found 0 vulnerabilities` on the vulnerable tree as well.

| Scan | Exit status | Result |
|---|---|---|
| Before the change (`npm audit --json` on the committed 4.17.15 tree) | **1** | `metadata.vulnerabilities` = `{info:0, low:0, moderate:0, high:1, critical:0, total:1}`; one vulnerable package `lodash`, range `<=4.17.23`, `fixAvailable` `{name:"lodash", version:"4.18.1", isSemVerMajor:false}` |
| After the change (`npm audit --json`) | **0** | `"vulnerabilities": {}`, `metadata.vulnerabilities` = `{info:0, low:0, moderate:0, high:0, critical:0, total:0}` |
| After the change (`npm audit`, text) | **0** | `found 0 vulnerabilities` |

**`GHSA-f23m-r3pf-42rh` is absent after the change, and `grep -c f23m audit-after.json` = 0.** It is
absent from the *before* capture too, and that is correct filtering rather than a gap in the advisory
feed: the advisory scopes `lodash` to the single version `= 4.17.23`, patched in 4.18.1, and the locked
4.17.15 is outside that set, so no audit configuration can report this identifier against 4.17.15.
What the feed reported for the 4.17.15 tree is the five lodash advisories listed in §6 below — a
correction to the plan's "same six advisories before" expectation, and the count is stated as measured
here and in §6. Closure is therefore evidenced by the installed tree leaving the advisory's affected
set, together with the package-level audit moving from one vulnerable package (`lodash`, aggregate
severity `high`, exit status **1**, capture `audit-before.json`) at 4.17.15 to none at 4.18.1 in both
manifests and in the installed tree (`"vulnerabilities": {}`, exit status **0**, capture
`audit-after.json`).

## 6. Advisories reported, and what happened to them

| Advisory | npm audit severity reported for it (before) | Disposition |
|---|---|---|
| GHSA-35jh-r3h4-6jhm / CVE-2021-23337 — command injection via `_.template`'s `variable` option | high | Closed by the same bump; not separately addressed |
| GHSA-p6mc-m468-83gw / CVE-2020-8203 — prototype pollution in `pick`/`set`/`setWith`/`update`/`updateWith`/`zipObjectDeep` | high | Closed by the same bump; not separately addressed |
| GHSA-29mw-wpgm-hmr9 / CVE-2020-28500 — ReDoS in `toNumber`/`trim` | moderate | Closed by the same bump; not separately addressed |
| GHSA-r5fr-rjxr-66jc / CVE-2026-4800 — code injection via `_.template` imports key names | high | Closed by the same bump; not separately addressed |
| GHSA-xxjr-mmjv-4gpg / CVE-2025-13465 — prototype pollution in `_.unset`, `_.omit` and `_.pullAt` | moderate | Closed by the same bump; not separately addressed |

**No advisory survives at `4.18.1`** (after-set empty), and **no advisory appeared after the change
that was not already present before it** (`comm -13` of the two identifier sets is empty). Nothing was
worked around, no `overrides` or `resolutions` entry was added, and no pin silences a finding.

## 7. Behaviour parity

The version move must change nothing observable. The pre-change baseline was captured on the
committed tree — `npm ci --no-fund` first (the tree was not installed yet), then a freshly started
process — and only then were the manifests edited.

| Capture | Command | Value |
|---|---|---|
| Baseline response | `curl -s -D headers-before.txt -o body-before.txt -w "%{http_code}" http://127.0.0.1:3000/` | `200` |
| Baseline body | `wc -c`, `sha256sum` | 14 bytes, sha256 `c98c24b677eff44860afea6f493bbaec5bb1c4cbb209c6fc2bbb47f66ff2ad31` |
| Baseline headers | `cat headers-before.txt` | `HTTP/1.1 200 OK`, `Date: …`, `Connection: keep-alive`, `Keep-Alive: timeout=5`, `Content-Length: 14` — no `Content-Type` |
| After response | `curl -s -D headers-after.txt -o body-after.txt …` | `200`, 14 bytes, same sha256 |
| After, arbitrary path | `curl … http://127.0.0.1:3000/nonexistent` | `200` with the byte-identical body |
| Header comparison | `diff <(grep -v '^Date:' headers-before.txt) <(grep -v '^Date:' headers-after.txt)` | no output, exit 0 (`Date` is a timestamp and is excluded by construction) |
| Body comparison | `cmp body-before.txt body-after.txt` | no output, exit 0 |
| Startup line | `node "server (1).js"` | `Server running at http://127.0.0.1:3000/` on both sides |

The after-state came from a **freshly started process**: `require` evaluates once per process, so an
instance started before the install keeps serving 4.17.15 from memory. Port 3000 is hard-coded and
exclusive, so the port was probed free (node `net.connect` probe → `FREE`, exit 0) before each start,
each process was killed by its exact child pid and awaited, and the port was released after each probe.

## 8. Reachability invariant

Reported as evidence that the bump has no call-site consequence, not as the remediation.

| Check | Command | Result |
|---|---|---|
| lodash references in the server | `grep -n "_" "server (1).js"` | only `1:const _ = require('lodash');` |
| lodash calls in the server | `grep -c "_\\." "server (1).js"` | `0` |
| lodash calls anywhere | `grep -rnE "_\.(unset\|omit\|set\|get\|template)\(" . --exclude-dir=.git` | no match, exit 1 |
| Loaded module in a fresh process | `node -p "require('lodash').VERSION"` | `4.18.1` |

`_.unset`, `_.omit`, `_.set` and `_.get` are never invoked, and the request handler ignores its `req`
argument, so no request-derived key or array-wrapped path segment reaches any lodash function, and
this repository had no reachable exploit path to begin with: the only reference to the package is the
line-1 import, `_` is never invoked, and the handler replies with a constant body.

**How the finding is closed.** By moving the pinned version, not by cutting a reachable path — static
scanning reads the manifests and the lockfile, and runtime scanning inspects process memory, so the
artifact's version in both places is what clears it. The vulnerable implementation is removed from the
installed tree rather than guarded, so no later call path can re-reach it. The reachability evidence
above is what shows the bump changes no call site; it is not the remediation.

## 9. Integrity negative control

Built in an isolated scratch copy from the committed pair, with the version and resolved URL bumped
to 4.18.1 and **the 4.17.15 digest left in place**:

| Variant | Result |
|---|---|
| Cold cache (empty cache dir) + stale digest | exit **1** — `npm error code EINTEGRITY … integrity checksum failed when using sha512: wanted sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A== but got sha512-dMInicTPVE8d1e5otfwmmjlxkZoUpiVLwyeTdUsi/Caj/gfzzblBcCE5sRHV/AsjuCmxWrte2TNGSYuCeCq+0Q==. (315640 bytes)` |
| Warm shared cache `/root/.npm` + stale digest | exit **0** — but the installed version was `4.17.15`: the digest is the key npm's content-addressed cache stores content under, so the stale digest silently restored the vulnerable tarball while the lockfile said 4.18.1, and the install even printed `found 0 vulnerabilities` |
| Cold cache + the correct digest | exit **0**, installed version `4.18.1` |

This is why the digest was replaced rather than only the version, and why the install was repeated
above with a fresh cache.

## 10. Diff and commit hygiene

`git diff --stat 44b04ea HEAD -- package.json package-lock.json` → `package-lock.json | 8 ++++----`,
`package.json | 2 +-`, 5 insertions and 5 deletions; the lockfile hunk changes four values and nothing
else (no record added, none removed).
The change touches exactly these three paths and nothing else — `package.json`,
`package-lock.json` and this report — with each path staged explicitly, never by `git add -A` or
`git add .`. The derived `node_modules/` tree (including `node_modules/.package-lock.json`) stays
untracked and is not committed; no `.gitignore` was created, and no second lockfile, test file,
dependency, script, CI configuration or configuration file was added. `"server (1).js"` is
byte-unchanged. A secret-pattern scan over the changed files and the server returned nothing.

## 11. Whole-package gate

The project's own gate, run from the repository root, exited 0 end to end:

```
CI=true npm ci --no-fund && node --check "server (1).js" && node -p "require('lodash').VERSION" && npm audit
# added 1 package … found 0 vulnerabilities / 4.18.1 / found 0 vulnerabilities
```

followed by the runtime leg: start `node "server (1).js"` → `curl` → `200` with the 14-byte body
matching the baseline → stop the server. The project ships no test suite, no test script and no
devDependencies, so there is no coverage gate to attach and none was invented.

## 12. Fallback decision

The request's fallback — if no fixed release exists, make the vulnerable code path unreachable
instead, record that decision and its reason, and never silently accept or suppress the finding —
**was not triggered**. 4.18.1 is published, is not deprecated, installs from the rewritten lockfile
with npm verifying the published digest (§4), and resolves from an empty cache, so the fixed release
exists and the version move is the remediation. Had it been uninstallable, this section would carry
the unreachable-path decision and its reason rather than a silent pass, and the surviving finding
would be named here.

## 13. Rollback

Rollback, if ever needed: `git checkout 44b04ea9ccf95c952233fc7165bd45c8da2a91a6 -- package.json
package-lock.json && npm ci --no-fund` restores `lodash` 4.17.15 and re-verifies its digest. The
pre-change revision is named in that command because the change is committed: the 4.17.15 values live
only at `44b04ea9ccf95c952233fc7165bd45c8da2a91a6`, so a bare `git checkout -- package.json
package-lock.json` would restore the committed `4.18.1` state instead (the pin at `package.json:5` and
both the root record and the artifact record in `package-lock.json` read `4.18.1` in the committed
tree) and the following `npm ci --no-fund` would install `4.18.1`. The command above restores the
pre-change pair — version `4.17.15`, resolved
`https://registry.npmjs.org/lodash/-/lodash-4.17.15.tgz`, integrity
`sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A==`,
the digest the registry publishes for `4.17.15` — and `npm ci --no-fund` verifies that digest against
the tarball it fetches. Rollback deliberately reintroduces the finding and is a recovery action only,
never a resolution.

Environment: node v22.23.4, npm 11.21.0, registry `https://registry.npmjs.org/`, no `.npmrc`, no
environment variable and no secret involved. All capture artifacts live outside the checkout in the
run's private scratch directory and are not committed.
