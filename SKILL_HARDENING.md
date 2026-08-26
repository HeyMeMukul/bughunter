# Skill-File Hardening Plan

## Audit result

The framework contains **51 skill files**, **22 summary cards**, and three files over the stated 500-line limit (`mapping`, `ssti`, and `xss`). Only **9 of 51** skills contain a clearly named Session Re-verification section, **24 of 51** contain a Reasoning Checkpoint, **25 of 51** contain Things to Do and Things Not to Do sections, and **39 of 51** mention a Negative Verdict. Seven skills currently contain all of the measured core markers: command-injection, file-upload, HTTP smuggling, IDOR, JWT, OAuth, and SSRF. This is a contract-consistency problem, not simply a missing-technique problem.

## Required shape for every domain skill

Each `SKILL.md` should have YAML metadata with a lowercase hyphenated name and a description that says both what it does and when it triggers. Keep the main file concise and decision-oriented. Use the same phase order across skills: Baseline, Confirmation, Negative Verdict, bounded impact demonstration, and validation handoff. End each phase with a Reasoning Checkpoint that records the input, signal/noise interpretation, confidence, request count, decision, and next action.

The domain skill should explain the mental model and decision branches, not dump payloads, paths, or parameter names. Technique detail belongs in a one-level-deep reference file only when it changes a decision. Deterministic work belongs in a script that produces structured output. Every external-infrastructure technique must be marked `[EXTERNAL INFRA REQUIRED]`.

A skill must separately define true-negative and inconclusive conditions. It must re-verify the session after 401/403 responses, material response shifts, rate-limit changes, or phase transitions. It must state the smallest reversible proof and the exact stop condition. It must define the result schema and cross-skill handoff without telling the Worker to explore outside the assigned hypothesis.

## Progressive disclosure layers

| Layer | Contents | Loading policy |
| --- | --- | --- |
| Metadata | Name, trigger description, risk flags, supported phase | Always visible for discovery |
| Summary card | 30–60 line workflow, gates, outputs, stop conditions | Read first when a task triggers the skill |
| SKILL.md | Reasoning workflow and evidence contract | Read when the summary is insufficient |
| Reference | Specialized decision tables or standards | Read only when a branch requires it |
| Script | Deterministic parser, diff, validator, or formatter | Execute; do not load source into context unless debugging |
| Fixture/eval | Sanitized examples and counterexamples | Used offline in CI and periodic regression tests |

## Missing cross-cutting skills to add

The current vulnerability catalog is broad, but framework strength also depends on operational skills. Add `authorization-scope`, `session-integrity`, `evidence-redaction`, `baseline-diffing`, `rate-limit-safety`, `knowledge-retrieval`, `provider-routing`, `mcp-tool-trust`, `report-deduplication`, and `regression-evaluation`. These are not new attack classes; they make every existing class safer and more reproducible.

## Evaluation

Create sanitized fixtures for each skill with one confirmed case, one true negative, one inconclusive case, one session-expired case, and one WAF/rate-limit noise case. Score the agent on correct verdict, required checkpoint fields, request cap, scope adherence, redaction, and stop behavior. Hold out entire programs or application patterns rather than random lines so the model cannot memorize titles. Track false-positive rate, false-negative rate, evidence completeness, average requests per hypothesis, and cost per validated finding.

Use the disclosed corpus as retrieval material and test-time context before considering model fine-tuning. A bounty amount is a sampling/ranking feature, not a correctness label. Include paid, duplicate, rejected, informative, and inconclusive outcomes. Version every skill and corpus build, hash source records, and require review before promoting extracted patterns into the runtime KB.

## Priorities

| Priority | Change | Why |
| --- | --- | --- |
| P0 | Enforce authorization/scope, session, evidence, redaction, and stop gates | Prevents unsafe or invalid results across all skills |
| P0 | Add skill linter and CI gate | Stops contract drift and missing sections |
| P1 | Add SUMMARY.md cards to every domain skill | Reduces context cost and improves reliable activation |
| P1 | Replace payload/reference dumps with decision tables and counterexamples | Improves generalization and reduces brittle memorization |
| P1 | Add offline fixtures and held-out evaluation | Measures real quality rather than prompt optimism |
| P2 | Add cross-skill dependency graph and retrieval metadata | Enables better chain hypothesis generation |
| P2 | Add route/provider provenance to results | Makes model switches and cost decisions auditable |

The improved copy includes `skills/_shared/SKILL_CONTRACT.md` and `tools/skill_lint.py` as the first implementation of this contract.
