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
| Affected range | `lodash <= 4.17.23` |
| Version this repository carried | 4.17.15, pinned at `package.json:5`, `package-lock.json:11` and `package-lock.json:15` |
| Advisory databases name 4.18.0 as the patched release | 4.18.0 carries the code fix; 4.18.1 is targeted instead because it is the version the CVE record and NVD call unaffected for `lodash`, the version `npm audit` itself offers as the fix, the current `latest` dist-tag, and the only one of the two that is not deprecated as a bad release |
| Registry resolution | `https://registry.npmjs.org/lodash/-/lodash-4.18.1.tgz`, published digest `sha512-dMInicTPVE8d1e5otfwmmjlxkZoUpiVLwyeTdUsi/Caj/gfzzblBcCE5sRHV/AsjuCmxWrte2TNGSYuCeCq+0Q==`, not deprecated, not unpublished — re-read from `npm view lodash@4.18.1 dist.integrity dist.tarball` and `npm view lodash dist-tags` (`{ latest: '4.18.1' }`) during the run |

The change was applied by **editing both manifests directly and installing with `npm ci`**, never
`npm install`, and never with `npm audit fix --force` (which would rewrite the exact pin as the caret
range `^4.18.1`).

## 2. The committed lockfile entry, quoted verbatim

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
`overrides`, `resolutions`, `hasInstallScript` or `dependencies` key was added
(`grep -nE '"(overrides|resolutions|hasInstallScript)"'` → exit 1), and no range operator appears next
to either pin (`grep -nE 'lodash": *"[\^~x*]'` → exit 1).

## 3. Install evidence

| Check | Command | Result |
|---|---|---|
| Install from the rewritten lockfile | `CI=true npm ci --no-fund` | exit **0** — `added 1 package, and audited 2 packages in 328ms` |
| Installed module version | `node -p "require('lodash').VERSION"` | `4.18.1` |
| Installed package manifest | `node -p "require('./node_modules/lodash/package.json').version"` | `4.18.1` |
| Derived tree record | `node -p "require('./node_modules/.package-lock.json').packages['node_modules/lodash'].version"` | `4.18.1` (derived, untracked, not committed) |
| Rewrite not served from a warm cache | `CI=true npm ci --no-fund --cache <fresh-cache-dir>` | exit **0** with an empty cache, resolving `4.18.1` |
| Manifest, root record and entry agree | `node -p` over all three | `4.18.1\|4.18.1\|4.18.1` |

## 4. Scan evidence

Run online from the repository root after the install. `npm audit --offline` is not used as evidence
here: it reports `found 0 vulnerabilities` on the vulnerable tree as well.

| Scan | Exit status | Result |
|---|---|---|
| Before the change (`npm audit --json` on the committed 4.17.15 tree) | **1** | `metadata.vulnerabilities` = `{info:0, low:0, moderate:0, high:1, critical:0, total:1}`; one vulnerable package `lodash`, range `<=4.17.23`, `fixAvailable` `{name:"lodash", version:"4.18.1", isSemVerMajor:false}` |
| After the change (`npm audit --json`) | **0** | `"vulnerabilities": {}`, `metadata.vulnerabilities` = `{info:0, low:0, moderate:0, high:0, critical:0, total:0}` |
| After the change (`npm audit`, text) | **0** | `found 0 vulnerabilities` |

**`GHSA-f23m-r3pf-42rh` is absent after the change, and `grep -c f23m audit-after.json` = 0.** The
identifier is also absent from this host's *before* output: the advisory data the scan queries
reported the 4.17.15 tree through five lodash advisories, not six. That is a correction to the plan's
"same six advisories before" expectation — the measured before-set is the five below, and the
version move still leaves the vulnerable range `<=4.17.23` behind in both manifests and in the
installed tree.

## 5. Advisories reported, and what happened to them

| Advisory | Severity (before) | Disposition |
|---|---|---|
| GHSA-35jh-r3h4-6jhm / CVE-2021-23337 — command injection via `_.template`'s `variable` option | high | Closed by the same bump; not separately addressed |
| GHSA-p6mc-m468-83gw / CVE-2020-8203 — prototype pollution in `pick`/`set`/`setWith`/`update`/`updateWith`/`zipObjectDeep` | high | Closed by the same bump; not separately addressed |
| GHSA-29mw-wpgm-hmr9 / CVE-2020-28500 — ReDoS in `toNumber`/`trim` | moderate | Closed by the same bump; not separately addressed |
| GHSA-r5fr-rjxr-66jc / CVE-2026-4800 — code injection via `_.template` imports key names | high | Closed by the same bump; not separately addressed |
| GHSA-xxjr-mmjv-4gpg / CVE-2025-13465 — prototype pollution in `_.unset`/`_.omit` | moderate | Closed by the same bump; not separately addressed |

**No advisory survives at `4.18.1`** (after-set empty), and **no advisory appeared after the change
that was not already present before it** (`comm -13` of the two identifier sets is empty). Nothing was
worked around, no `overrides` or `resolutions` entry was added, and no pin silences a finding.

## 6. Behaviour parity

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

## 7. Reachability invariant

Reported as evidence that the bump has no call-site consequence, not as the remediation.

| Check | Command | Result |
|---|---|---|
| lodash references in the server | `grep -n "_" "server (1).js"` | only `1:const _ = require('lodash');` |
| lodash calls in the server | `grep -c "_\\." "server (1).js"` | `0` |
| lodash calls anywhere | `grep -rnE "_\.(unset\|omit\|set\|get\|template)\(" . --exclude-dir=.git` | no match, exit 1 |
| Loaded module in a fresh process | `node -e "…require('lodash').VERSION"` | `4.18.1` |

`_.unset`, `_.omit`, `_.set` and `_.get` are never invoked, and the request handler ignores its `req`
argument, so no request-derived key or array-wrapped path segment reaches any lodash function. The
find is closed by removing the vulnerable implementation from the installed tree, which no later call
path can re-reach.

## 8. Integrity negative control

Built in an isolated scratch copy from the committed pair, with the version and resolved URL bumped
to 4.18.1 and **the 4.17.15 digest left in place**:

| Variant | Result |
|---|---|
| Cold cache (empty cache dir) + stale digest | exit **1** — `npm error code EINTEGRITY … integrity checksum failed when using sha512: wanted sha512-8xOcRHvCjnocdS5cpwXQXVzmmh5e5+saE2QGoeQmbKmRS6J3VQppPOIt0MnmE+4xlZoumy0GPG0D0MVIQbNA1A== but got sha512-dMInicTPVE8d1e5otfwmmjlxkZoUpiVLwyeTdUsi/Caj/gfzzblBcCE5sRHV/AsjuCmxWrte2TNGSYuCeCq+0Q==. (315640 bytes)` |
| Warm shared cache `/root/.npm` + stale digest | exit **0** — but the installed version was `4.17.15`: the digest is the key npm's content-addressed cache stores content under, so the stale digest silently restored the vulnerable tarball while the lockfile said 4.18.1, and the install even printed `found 0 vulnerabilities` |
| Cold cache + the correct digest | exit **0**, installed version `4.18.1` |

This is why the digest was replaced rather than only the version, and why the install was repeated
above with a fresh cache.

## 9. Diff and commit hygiene

`git diff --stat` → `package-lock.json | 8 ++++----`, `package.json | 2 +-`, 5 insertions and 5
deletions; the lockfile hunk changes four values and nothing else (no record added, none removed).
`git status --short` lists `M package-lock.json`, `M package.json` and this report as added; the
derived `node_modules/` tree (including `node_modules/.package-lock.json`) stays untracked and is not
committed; no `.gitignore` was created, and no second lockfile exists. `"server (1).js"` is
byte-unchanged. A secret-pattern scan over the changed files and the server returned nothing.

## 10. Whole-package gate and rollback

The project's own gate, run from the repository root, exited 0 end to end:

```
CI=true npm ci --no-fund && node --check "server (1).js" && node -p "require('lodash').VERSION" && npm audit
# added 1 package … found 0 vulnerabilities / 4.18.1 / found 0 vulnerabilities
```

followed by the runtime leg: start `node "server (1).js"` → `curl` → `200` with the 14-byte body
matching the baseline → stop the server. The project ships no test suite, no test script and no
devDependencies, so there is no coverage gate to attach and none was invented.

Rollback, if ever needed: `git checkout -- package.json package-lock.json && npm ci --no-fund`
restores `lodash` 4.17.15 and re-verifies its digest. Rollback deliberately reintroduces the finding
and is a recovery action only, never a resolution.

Environment: node v22.23.4, npm 11.21.0, registry `https://registry.npmjs.org/`, no `.npmrc`, no
environment variable and no secret involved. All capture artifacts live outside the checkout in the
run's private scratch directory and are not committed.
