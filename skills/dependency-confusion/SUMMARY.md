# Dependency Confusion / Supply Chain — Summary Card

**Phase:** 3 | **Type:** Supply Chain | **Impact:** Critical

## Quick Summary
Internal package names that also exist on public registries (npm, PyPI, Maven Central, NuGet, RubyGems, Go) at equal-or-higher versions get resolved from the **public** source during builds. An attacker-controlled impostor there = RCE on build servers and developer machines. Your job is the name-collision audit + safe local simulation — NEVER publish to a real registry.

## Key Indicators
- Internal-looking packages: version `0.x`, absent from public registry, private registry URLs in lockfiles
- Manifests: package.json, requirements.txt, pom.xml, *.csproj, Gemfile, go.mod
- Unscoped npm names / no strict `--index-url` pip config
- `.npmrc`, `pip.conf`, `settings.xml`, `nuget.config` showing merged registries

## Quick Test
```bash
# Collision check per ecosystem
npm view <internal-name> version --json                 # npm
curl -s https://pypi.org/pypi/<name>/json | jq .info.version  # PyPI
curl -s https://api.nuget.org/v3-flatcontainer/<name>/index.json  # NuGet

# Confirmed when: name exists publicly AND public version >= internal
# + registry config does NOT isolate the private source
```

## Critical Bounty Potential
- RCE on build/CI/dev environments = critical ($5,000-$25,000+)
- Pivot into cloud creds/SSH keys from compromised runners

## Token Cost
~4,300 tokens (Worker reads full SKILL.md)
