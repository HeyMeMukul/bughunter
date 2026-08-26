# v3.1 Upgrade Guide

## What this is

v3.1 is an **additive** upgrade to v3.0. No phases renamed. No files deleted. No vulnerability skills changed. Three coordinated additions that fix the "vulnerability with no business impact" failure mode.

## What's new

1. **`tools/spider/spider_comprehension.sh`** — new companion tool to spider.sh. Recovers source code from .map files, enumerates webpack chunks, probes /.well-known/, finds swagger/openapi/graphql introspection, extracts CSP trust map, enumerates archive.org history.

2. **`skills/chaining/`** — new skill directory with 5 files. The chaining brain.

3. **Updated existing files:**
   - `skills/index.md` — registers chaining skill
   - `skills/mapping/SKILL.md` — adds M2.5 (business context) and M9 (chain synthesis)
   - `skills/recon/SKILL.md` — adds Step 8 (deep comprehension)
   - `lead_prompt.md` — M9 instructions for Lead
   - `CHANGELOG.md` — v3.1 entry

## How to upgrade from v3.0

### Option A — Fresh install (clean engagement state)

```bash
# Backup your current framework
mv ~/bugbounty-ai-framework ~/bugbounty-ai-framework.v3.0.backup

# Extract v3.1
unzip bugbounty-ai-framework-v3.1.zip
mv bugbounty-ai-framework ~/bugbounty-ai-framework

# Restore your active engagement data if any
cp -r ~/bugbounty-ai-framework.v3.0.backup/engagement/* ~/bugbounty-ai-framework/engagement/
cp ~/bugbounty-ai-framework.v3.0.backup/state.json ~/bugbounty-ai-framework/state.json
cp -r ~/bugbounty-ai-framework.v3.0.backup/results/* ~/bugbounty-ai-framework/results/ 2>/dev/null || true
cp -r ~/bugbounty-ai-framework.v3.0.backup/tasks/task-*.md ~/bugbounty-ai-framework/tasks/ 2>/dev/null || true

# Verify
ls ~/bugbounty-ai-framework/skills/chaining/  # should show 5 files
ls ~/bugbounty-ai-framework/tools/spider/      # should show spider.sh AND spider_comprehension.sh
```

### Option B — In-place patch (preserves all engagement data)

If you don't want to risk losing your Cleartax findings:

```bash
cd ~/bugbounty-ai-framework

# Add the new files (these don't exist in v3.0)
# Extract chaining skill from the zip:
unzip -o bugbounty-ai-framework-v3.1.zip "bugbounty-ai-framework/skills/chaining/*" -d /tmp/
cp -r /tmp/bugbounty-ai-framework/skills/chaining ~/bugbounty-ai-framework/skills/

unzip -o bugbounty-ai-framework-v3.1.zip "bugbounty-ai-framework/tools/spider/spider_comprehension.sh" -d /tmp/
cp /tmp/bugbounty-ai-framework/tools/spider/spider_comprehension.sh ~/bugbounty-ai-framework/tools/spider/
chmod +x ~/bugbounty-ai-framework/tools/spider/spider_comprehension.sh

# Replace the 5 updated files (these existed in v3.0 and got modified)
for f in skills/index.md skills/mapping/SKILL.md skills/recon/SKILL.md lead_prompt.md CHANGELOG.md; do
    unzip -o bugbounty-ai-framework-v3.1.zip "bugbounty-ai-framework/$f" -d /tmp/
    cp /tmp/bugbounty-ai-framework/$f ~/bugbounty-ai-framework/$f
done

# Verify
ls ~/bugbounty-ai-framework/skills/chaining/  # 5 files
grep "v3.1" ~/bugbounty-ai-framework/CHANGELOG.md  # shows v3.1 entry
```

## Verifying the upgrade

After install, run these checks:

```bash
cd ~/bugbounty-ai-framework

# 1. Chaining skill present
ls skills/chaining/
# Expected: SKILL.md, backward_patterns.md, business_impact_mapping.md, canonical_examples.md, forward_patterns.md

# 2. Spider comprehension tool present and executable
ls -la tools/spider/spider_comprehension.sh
# Expected: -rwxr-xr-x (executable)

# 3. Mapping skill has M9
grep -c "M9\|Cross-Endpoint Chain" skills/mapping/SKILL.md
# Expected: 10+ matches

# 4. Recon skill has Step 8
grep "Step 8" skills/recon/SKILL.md
# Expected: "### Step 8: Deep Application Comprehension (MANDATORY before Phase 2)"

# 5. Skills index registers chaining
grep "\[\[chaining\]\]" skills/index.md
# Expected: 1-2 lines mentioning chaining

# 6. Lead prompt has M9 workflow
grep -c "M9\|skills/chaining" lead_prompt.md
# Expected: 10+ matches
```

If all 6 checks pass, v3.1 is installed correctly.

## Running v3.1 on a new engagement

The workflow is unchanged except for the additions:

```bash
# Phase 1 (same as v3.0)
./tools/spider/spider.sh "https://target.com" \
    --header "X-Comolho-Client: cyb3rfy" \
    --output-dir engagement/spider/unauth

# Phase 1 NEW STEP (Step 8 in recon skill)
./tools/spider/spider_comprehension.sh engagement/spider/unauth \
    --target "https://target.com" \
    --header "X-Comolho-Client: cyb3rfy"

# ... auth spider + comprehension repeat for authenticated context ...

# Phase 2 (mapping) — Workers now also produce business_function, impact_floor, impact_ceiling
# Phase 2 M9 (NEW) — Lead runs after per-endpoint mapping completes:
#   Lead loads skills/chaining/SKILL.md and follows its 5-phase workflow
#   Output: engagement/mapping/CHAIN-INVENTORY.md and CHAINS-NNN.hypothesis.md files

# Phase 3-5 unchanged
```

## Running v3.1 on Cleartax (mid-flight engagement)

You have 3 validated findings (FIND-301 CORS, FIND-306 PubNub, FIND-503 telemetry) and 19+ mapped endpoints.

**Recommended workflow:**

1. **Run spider_comprehension on Cleartax** — this is purely additive and gives the agent application understanding it didn't have before:
   ```bash
   cd ~/bugbounty-ai-framework
   ./tools/spider/spider_comprehension.sh engagement/spider/auth \
       --target "https://cleartax.in" \
       --auth-cookie "$(cat engagement/spider/cookies_a.txt)" \
       --header "X-Comolho-Client: cyb3rfy"
   ```

2. **Run M9 (chain synthesis) against the existing 19 endpoints.** Tell Claude (Lead role): "Load skills/chaining/SKILL.md and run the 5-phase chain synthesis workflow against all existing engagement/mapping/EP-*.profile.yaml files. Produce CHAIN-INVENTORY.md and chain hypothesis files."

   The chaining skill will likely find that FIND-301 (CORS) is missing an amplifier — search the inventory for endpoints returning auth tokens, CSRF tokens, or PII under the same CORS misconfig. That's the chain candidate.

3. **Translate the 3 findings using business_impact_mapping.md** before submission. The Cleartax-specific reframings for FIND-301, FIND-306, FIND-503 are in that file. FIND-306 in particular needs the scope-safe framing ("ClearTax misuse of PubNub" not "PubNub flaw") or Com Olho will close it out of scope.

4. **Don't submit FIND-503 alone** unless chain synthesis finds an amplifier — telemetry poisoning is almost always P5 (Hall of Fame only, no cash) on the Cleartax program. The business_impact_mapping.md file has the analysis.

## Rollback

If anything breaks, your v3.0 backup at `~/bugbounty-ai-framework.v3.0.backup/` is untouched. Restore with:

```bash
rm -rf ~/bugbounty-ai-framework
mv ~/bugbounty-ai-framework.v3.0.backup ~/bugbounty-ai-framework
```

## After install — commit to private GitHub

```bash
cd ~/bugbounty-ai-framework
git add -A
git commit -m "v3.1: comprehension + chaining augmentations

- spider_comprehension.sh for deep app understanding (source map recovery, webpack chunks, /.well-known, API specs, CSP trust map, wayback)
- chaining/ skill with 5-phase workflow (gadget inventory, forward/backward synthesis, chain hypothesis construction, business-impact translation)
- mapping/SKILL.md M2.5 (business context) + M9 (chain synthesis)
- recon/SKILL.md Step 8 (deep comprehension mandatory)
- lead_prompt.md M9 workflow
- additive only, no v3.0 phases renamed or removed"
git push
```
