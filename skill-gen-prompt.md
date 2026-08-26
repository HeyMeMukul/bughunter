# Prompt: Generate Penetration Testing Skill File

Use this prompt to generate a Claude skill file for any vulnerability type.
Replace [VULNERABILITY NAME] and fill in the reference URLs before sending.

---

## THE PROMPT

You are helping build a Claude agent skill file for professional penetration testing.

**Context about the agent:**
- It operates as part of a two-model pipeline. A separate model handles attack surface identification. This agent receives already-identified endpoints/parameters and takes over from detection through to maximum demonstrated impact.
- It does not write reports. That is handled downstream.
- It has access to Claude's full existing knowledge base. The skill file's job is not to transfer knowledge — it is to give Claude a professional decision framework and methodology that structures how it applies that knowledge.

**The vulnerability to build the skill for:** [VULNERABILITY NAME]

**Reference material to inform the skill:**
[PASTE YOUR REFERENCE URLs HERE]

---

**Build the skill as a directory with the following rules:**

---

### SKILL.md (required, always the entry point)

- YAML frontmatter with `name` (lowercase, hyphens only, gerund form e.g. `testing-ssrf`) and a precise `description` that includes both what the skill does and when to trigger it
- Keep under 500 lines
- Cover: the mental model of the vulnerability, all phases listed below, professional standards for decision-making, severity criteria based on demonstrated impact
- Point to reference files only for content that genuinely requires more depth than inline allows
- Give Claude moderate freedom — provide the reasoning framework and decision logic, then trust Claude's knowledge base for the specifics

---

### Required Phases & Sections

The skill file **must** include the following phases in this order. Each phase must have a **Reasoning Checkpoint** block at the end for Claude to log its decisions.

---

#### Phase 1: Baseline Establishment

- Send a unique, benign test value and record the complete normal response profile: status code, response length, response time, content patterns, reflection location
- The baseline is the anchor for all future comparisons. Every subsequent phase decision is made *relative to this baseline*, not in isolation
- Document separately: behavior for valid inputs, behavior for invalid/non-existent inputs, and any observed variance in responses across multiple identical requests
- **Re-baseline trigger:** Any time session state changes, rate limiting appears, responses shift unexpectedly, or caching behavior is detected — Claude must re-establish baseline before continuing. See the **Session Re-verification** section.

---

#### Phase 2: Confirmation

**Goal:** Establish HIGH confidence that the vulnerability class is present before doing anything else.

- Define what HIGH / MEDIUM / LOW confidence means for this vulnerability type specifically
- Specify the minimum number of consistent test results required to reach HIGH confidence
- Include: what signal looks like (changed response, error, timing delta), what noise looks like (unstable app behavior, caching, WAF randomness), and how to tell them apart
- Set a hard cap on confirmation attempts (e.g. max 15 requests) before concluding no signal
- **Proceed to Phase 3 only at HIGH confidence.** At MEDIUM confidence, retest with a different approach. At LOW confidence, document and stop.

---

#### Negative Verdict (between Confirmation and Exploitation)

This is a **mandatory gate** between confirmation and exploitation.

Before entering any exploitation phase, Claude must explicitly evaluate and document a negative verdict if the evidence does not support it. Include:

- The exact conditions that constitute a **true negative** for this vulnerability (not just "no signal" — be precise about what a real negative looks like vs. an inconclusive result)
- The structured log format Claude must write when issuing a negative verdict:
  ```
  [VULN-NEGATIVE]
  [PARAMETER] {name}
  [STEPS-RUN] {every phase and step completed}
  [SIGNAL] {what was observed, or "nothing — all responses match baseline"}
  [CONCLUSION] {why this is a true negative, not just inconclusive}
  [ACTION] Parameter cleared. Do not proceed to exploitation.
  ```
- Distinguish between **true negative** (vulnerability definitively not present) and **inconclusive** (signal unclear, not enough information). Inconclusive is not a negative — it requires a decision about whether to try a different technique or stop
- **STOP condition:** If the negative verdict is issued, Claude must not proceed to exploitation under any framing or reinterpretation of the evidence

---

#### Phase 3: Exploitation

- Only entered after HIGH confidence from Phase 2 and no negative verdict issued
- Progressive escalation: start from lowest-impact confirmation, step up only as previous step succeeds
- Define explicit **stop conditions** at each escalation level (e.g., stop at first RCE confirmation, do not chain further)
- Every technique requiring attacker-controlled external infrastructure must be marked `[EXTERNAL INFRA REQUIRED]` inline
- Include a per-step confidence checkpoint — Claude should not assume one success propagates to the next step automatically

---

#### Session Re-verification

Include a dedicated section (not just inline notes) covering:

- **When to re-verify:** Explicit triggers that require Claude to pause and re-establish session validity before continuing (e.g., receiving a 401/403 mid-test, session token expiry signals, sudden response length shift >20% with no payload change, getting blocked responses after previously getting valid ones)
- **How to re-verify:** The exact steps to confirm the session is still valid and the target is still responding normally — re-send the original baseline request, compare against recorded baseline, check auth state
- **What to do on failure:** If session re-verification fails (session is dead, IP blocked, WAF now blocking all requests), Claude must stop the current phase, document the session state, and not count failed requests made during an invalid session as negative signal
- **Why this matters for result integrity:** A common false negative source is making exploitation attempts while the session has already expired or been blocked. Results from an invalid session are meaningless and should never be used to conclude a parameter is not vulnerable

---

### Things to Do

Include a `## Things to Do` section in SKILL.md as a professional checklist of active behaviors Claude must maintain throughout all phases. This is not a list of techniques — it is a list of *operating standards*. Examples of what to cover (adapt for the specific vulnerability):

- Always compare against baseline, never evaluate a response in isolation
- Log every phase transition decision with the reasoning checkpoint format
- Re-verify session validity at every phase boundary
- Stop and document immediately at the first confirmed high-impact result — do not chain
- Treat MEDIUM confidence as a prompt to try a different angle, not a prompt to escalate
- Issue an explicit negative verdict before closing any parameter, even if the result seems obviously negative

---

### Things Not to Do

Include a `## Things Not to Do` section in SKILL.md as a list of explicitly prohibited behaviors. These must be concrete and specific to this vulnerability class, not generic advice. Examples of the type of content to cover (adapt for the specific vulnerability):

- Do not interpret a changed response as confirmation without also verifying it differs from the *invalid input* baseline (not just the *valid input* baseline)
- Do not proceed to exploitation on MEDIUM confidence — retest first
- Do not keep trying the same technique after 3 consistent failures with no variation in response
- Do not attribute session errors, rate limit blocks, or WAF randomness to the vulnerability
- Do not issue a negative verdict when the result is actually inconclusive — distinguish clearly
- Do not run exploitation steps while session re-verification is pending or has failed

---

### Reference files (only create if genuinely needed)

- Each file should exist because the topic requires decision logic that would bloat SKILL.md, not just because it's a separate category
- Ask: would an experienced tester need a reference for this, or do they just know it? If they just know it, don't write it — let Claude know it too
- Files must have a table of contents if over 100 lines
- References stay one level deep from SKILL.md — no nested references

---

### Content philosophy — strictly enforce these

- Teach reasoning, not memorization. If a section is a list of payloads or a list of paths/parameters with no decision logic, rewrite it as reasoning about *when* and *why* to use each approach. Claude can derive specific payloads from understanding — it does not need them pre-listed.
- Every technique that requires attacker-controlled external infrastructure must be marked `[EXTERNAL INFRA REQUIRED]` inline.
- Do not include: attack surface identification (handled by another model), report writing, payload dumps, parameter name lists, URL lists without context, generic remediation advice.
- Do not over-explain things Claude already knows — only add context Claude genuinely lacks.

---

### Quality check before outputting

- Read each section and ask: *"Is this teaching Claude how to think about this, or just what to do?"* If it's just what to do without the reasoning, rewrite it.
- Read each reference file and ask: *"Could this content be one paragraph in SKILL.md instead?"* If yes, fold it in.
- Verify the **Negative Verdict** gate exists between Confirmation and Exploitation, and that it is a mandatory stop — not optional.
- Verify the **Session Re-verification** section is standalone (not buried in a phase as a footnote).
- Verify **Things to Do** and **Things Not to Do** are written as *operating standards*, not as technique lists.
- Check that every technique needing external infrastructure is marked `[EXTERNAL INFRA REQUIRED]`.
- Verify no file is a payload dump or a categorized list masquerading as methodology.
- Verify each phase ends with a **Reasoning Checkpoint** block.
