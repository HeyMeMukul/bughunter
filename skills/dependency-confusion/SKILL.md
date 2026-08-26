# Dependency Confusion / Supply Chain — Vulnerability Skill

**Phase:** 3 | **Skill Type:** Infrastructure / Supply Chain | **Impact:** Critical | **Prerequisite:** Source/build artifacts accessible (repos, package manifests, CI configs, Dockerfiles), dependency manifests enumerated (Phase 0/2)

---

## Mental Model

Dependency confusion happens when a private/internal package's name also exists on a public registry (npm, PyPI, Maven Central, NuGet, RubyGems, Go proxy) — and the package manager resolves to the **public** copy. Attackers (or you, in a PoC) publish a malicious package under that name to the public registry with a higher version, and the target's next build/install pulls *the attacker's* package instead of the internal one → arbitrary code execution on build servers, deploy pipelines, and any developer who installs.

**The core assumption you're violating:** "If the package is internal, the build only looks at the internal registry." The reality: many package managers merge registries, and internal packages are often published with **no version above what the public registry has** (or the internal one is never published publicly at all). The resolver's job is to pick *a* matching version — and it doesn't care that the winner is malicious.

**The resolution-order mechanics (know which manager):**

| Manager | Internal vs public resolution | Poison vector |
|---------|------------------------------|---------------|
| **npm** | No `@scope` = public registry wins unless `.npmrc` scopes to private | Publish same name, higher semver |
| **PyPI** | `pip install name` → public index unless `-i` private / `--extra-index-url` | Publish same name, higher version |
| **Maven** | Order of repositories in `pom.xml`/settings | Publish to Central with higher version |
| **NuGet** | Order of sources; missing packages fall through to nuget.org | Publish to nuget.org |
| **RubyGems** | Multiple sources merged in Gemfile | Publish to rubygems.org |
| **Go** | `proxy.golang.org` fallback for missing modules | Publish to proxy.golang.org |

**Why it pays (bounty math):** one poisoned dependency = RCE on every build + developer machine + CI pipeline. Critical severity. But **YOU MUST NOT actually publish malicious packages** — that's both illegal and destructive. Your job is to *identify and prove* the confusion condition safely, then report.

**The hunt is a name-collision audit:**
1. Enumerate all dependencies and their sources
2. Identify internal-only packages (org-prefixed, versioned `0.x`, not on the public registry)
3. Check whether the public registry already has the name, and at what version
4. Determine which registry the build would resolve to

---

## Phase 1: OOB-First Detection (MANDATORY)

Dependency resolution itself doesn't call out to *your* OOB server — but the attack payload would (a malicious package beaconing home). You can simulate the beacon **safely** by checking resolution behavior, and use OOB to prove that a *dependency's install-time code* can phone home:

```bash
./tools/interactsh_launcher.sh start --output-dir engagement/oob/
OOB_URL=$(cat engagement/oob/oob_url.txt)
```

### 1.1 Install-time execution proof (safe, controlled)
Show that the package manager executes `postinstall`/`setup.py` scripts (the exfiltration channel for a real attack) using a *harmless* local test package:

```bash
mkdir -p /tmp/dep-test && cd /tmp/dep-test
npm init -y >/dev/null
# Local harmless package with a postinstall that "beacons" to a localhost sink,
# or simply demonstrate postinstall runs:
npm install --save "postinstall-test@latest" 2>&1 | head
```

The real confirmation of the *condition* is in Phase 2 (name collisions). OOB serves as the evidence pattern: in your report, show that install-time scripts execute `fetch("http://OOB_URL/beacon")`-style code — proving the RCE primitive a real dependency-confusion package would use.

### 1.2 Registry resolution probe
For each suspected internal package, probe which source the manager would pick:

```bash
# npm: does the name resolve on the public registry?
npm view <internal-pkg-name> version --json
# pip: does it resolve on public PyPI?
python3 -c "import urllib.request,json; print(json.load(urllib.request.urlopen('https://pypi.org/pypi/<internal-pkg-name>/json'))['info'].get('version'))"
```

A public hit at a **higher version** than the internal one → collision candidate. Confirm with OOB-style proof in the report that the manager would fetch the public copy.

---

## Phase 2: Confirmation

### 2.1 Enumerate the Dependency Surface

Collect every manifest and pin file from the spider/build artifacts:

```bash
# JS/TS projects
package.json  package-lock.json  yarn.lock  pnpm-lock.yaml  .npmrc
# Python
requirements.txt  setup.py  pyproject.toml  Pipfile  pip.conf
# Java
pom.xml  build.gradle  settings.xml
# .NET
*.csproj  packages.config  nuget.config
# Ruby
Gemfile  Gemfile.lock  .gemrc
# Go
go.mod  go.sum
# Also: Dockerfiles, Makefiles, CI configs (.github/workflows, .gitlab-ci.yml, Jenkinsfile)
```

### 2.2 Flag Internal-Looking Packages

Filter for names that scream "private":
- Not on the public registry (the giveaway)
- Org/project-prefixed but not `@scope`-published (npm), no lowercase/underscore pattern on PyPI
- Version pinned as `0.0.x`, `0.1.x`, `1.0.0-alpha` (never "released" publicly)
- Unusual namespace matching an internal repo/tool name from recon
- Packages whose lockfile points at a private registry URL (`registry.internal.corp`, `git+ssh://git@...`)

### 2.3 Collision Check (the core confirmation)

For each candidate, query the public registry:

```bash
# npm
npm view <name> versions --json
# PyPI (JSON API is fastest)
curl -s https://pypi.org/pypi/<name>/json | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['info']['version'])"
# RubyGems
curl -s https://rubygems.org/api/v1/gems/<name>.json | python3 -c "import json,sys;print(json.load(sys.stdin).get('version'))"
# Maven Central
curl -s "https://search.maven.org/solrsearch/select?q=g:<grp>+AND+a:<name>&rows=1&wt=json"
# NuGet
curl -s https://api.nuget.org/v3-flatcontainer/<name>/index.json
# Go proxy
curl -s https://proxy.golang.org/<module>/@v/list
```

**Confirmation criteria (all three needed for HIGH confidence):**
1. The name EXISTS on the public registry
2. The public version ≥ internal pinned version (resolver picks public)
3. The build's registry config would prefer the public source (no strict `@scope`/`--index-url` isolation)

If the name is *absent* from the public registry → it's a **private-package-takeover** vector (someone could register the name later) — report as medium, still valuable.

### 2.4 Resolution-Path Proof (build-side)

Confirm which source wins:
- Read `.npmrc` / `pip.conf` / `settings.xml` / `nuget.config` for registry ordering
- Check lockfiles: does the resolved URL point at the private registry or the public one?
- For npm: unscoped internal names with no private `registry` override resolve to the **public** registry by default → confusion is automatic

### 2.5 Install-time Execution Channel

Confirm the *payload delivery* mechanism would execute (the RCE claim):
- npm: `postinstall`/`preinstall` scripts run on install
- PyPI: `setup.py`/`setup.cfg` custom code runs on build
- RubyGems: `extconf.rb`/gem build hooks
- NuGet: `build/*.targets`, `tools/` executables run in MSBuild
- Show one example of install-time execution with a harmless local package (see 1.1) as evidence of the primitive

---

## Phase 3: Negative Verdict (MANDATORY GATE)

**DO NOT declare dependency confusion negative without:**

1. Auditing **every** manifest type present (not just package.json) — Python/Java/.NET/Ruby/Go each have their own registry rules
2. Checking **all** internal-looking packages, not a sample — one colliding package is the finding
3. Querying the correct public registry for each ecosystem (npm, PyPI, Maven Central, NuGet, RubyGems, Go proxy)
4. Reading the actual registry config (`.npmrc`, `pip.conf`, `settings.xml`, `nuget.config`, Gemfile sources) — the *config* decides resolution, not the manifest alone
5. Checking both directions: name-exists-with-higher-version (confusion) AND name-absent (future takeover)
6. Verifying version comparison carefully — an internal package pinned at `1.0.0` while public has `0.5.0` is NOT exploitable today
7. Confirming `@scope`/isolation is truly absent for npm (scoped packages are not confused)

If no name collides with an equal-or-higher public version AND registry config fully isolates private deps → NEGATIVE.

---

## Phase 4: Exploitation (Proof WITHOUT Publishing)

**CRITICAL:** Never publish a malicious package to npm/PyPI/Maven/et al. It is illegal, harmful, and destroys the finding's credibility. Prove the impact with a **safe local simulation**.

### 4.1 Safe Local Simulation (private-registry PoC)
1. Stand up a local registry (e.g., Verdaccio for npm) or a local PyPI mirror
2. Configure the build to point at it (copy of the target's config)
3. Publish a **harmless** package with the colliding name + higher version + a `postinstall` that writes a marker file / prints "PWNED" (no exfiltration)
4. Run the target's install command → marker appears → **the resolver installed the higher-version impostor**

```bash
# npm example
npm install -g verdaccio && verdaccio &   # local registry
npm publish --registry http://localhost:4873   # your harmless colliding pkg
npm install <colliding-name> --registry http://localhost:4873  # pulls impostor
```

This is the exact resolver behavior a real attacker would weaponize — delivered as a controlled demo.

### 4.2 Impact Narrative for the Report
- Install-time code execution (`postinstall`/`setup.py`) = RCE on: CI/CD runners, build servers, developer workstations, production deploy steps
- Pivot surface: those runners often hold repo write access, cloud credentials, production SSH keys
- Scope: every environment that reinstalls/updates dependencies

### 4.3 Chain with Other Findings
- If recon found internal repo names, a missing-namespace package (`org-tool`) is a future-takeover risk — combine with the repo-listing proof

**Stop condition:** Safe simulation proves resolution + execution. Document with the simulation output. Do NOT approach the real public registry with the package.

---

## What You DO
- Enumerate ALL dependency manifests (npm, pip, maven, nuget, gems, go) before concluding
- Flag internal-looking packages (version `0.x`, absent from public registry, private registry URLs)
- Query the correct public registry per ecosystem and compare versions precisely
- Read registry config (`.npmrc`, `pip.conf`, `settings.xml`, etc.) — it decides resolution
- Prove install-time execution with a harmless local package
- Demonstrate with a **local** registry simulation — never publish to the real public registry

## What You DO NOT Do
- Publish a malicious/confusing package to a real public registry — ever (illegal, destructive, disqualifying)
- Check only package.json — Python/Java/.NET/Ruby/Go projects have their own registries and rules
- Compare versions sloppily — public must be ≥ internal for current exploitability
- Ignore the absent-name case — unclaimed private names are still a takeover risk
- Assume `@scope` means safe — scoped packages are protected, but unscoped internal names are the classic miss

---

## Cross-Skill Links
- [[recon-infra]] — Internal repo/package names discovered in recon feed the collision audit
- [[command-injection]] — Install-time scripts deliver command execution; same impact class
- [[cloud-misconfig]] — CI runners with cloud creds make the RCE pivot critical
- [[secret-scanner]] — Build artifacts may leak private registry tokens (amplifies the finding)
