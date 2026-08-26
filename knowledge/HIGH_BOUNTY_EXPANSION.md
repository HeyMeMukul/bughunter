# High-Bounty Knowledge-Base Expansion

**Prepared by Manus AI · 26 August 2026**

## Executive summary

The framework’s high-bounty corpus has been expanded from the earlier `>$100` seed into a dedicated **`>$1,000` corpus**. The current build contains **932 records**: **921 metadata-only public HackerOne index records** above $1,000 and **11 curated article, disclosure, or methodology records** with explicit rewards above $1,000 or clearly labeled aggregate rewards.

The corpus is intentionally not a fine-tuning dataset yet. It is a **provenance-aware retrieval and evaluation seed**. The 921 index records are useful for program, bounty, and vulnerability-class priors, but most do not contain full report narratives. The 11 curated records contain concise, redacted reasoning patterns, evidence patterns, counterexamples, source-quality labels, and corroboration status. This prevents the agent from learning that a high bounty alone is evidence of exploitability.

> **Use high-bounty examples to improve prioritization and reasoning—not to infer authorization, severity, or a permission to test.**

## Verified corpus statistics

| Component | Records | What it contains | Confidence |
| --- | ---: | --- | --- |
| Existing public HackerOne metadata, `>$100` | 2,810 | Index metadata and source URLs | Discovery / unreviewed |
| New HackerOne metadata subset, `>$1,000` | 921 | Bounty, program, report URL, platform label, normalized coarse class | Unreviewed metadata |
| Curated primary research and official disclosures | 8 | Redacted methodology, evidence, counterexample, and explicit bounty | Reviewed summaries |
| Curated secondary write-ups | 3 | Public summaries with explicit bounty claims and methodology clues | Needs corroboration |
| Combined expanded corpus | **932** | 921 metadata records plus 11 curated records | Mixed; use quality filters |

The public metadata snapshot also contains **167 records above $5,000** and **64 records above $10,000**. The original `>$1,000` subset spans **83 programs** and **84 platform vulnerability labels**. Vulnerability labels are incomplete in the source snapshot; **155 of the 921 records have blank vulnerability-type labels**, so those records must not be treated as a complete taxonomy distribution.

## Files added

| File | Purpose |
| --- | --- |
| `knowledge/corpus_seed/hackerone_paid_gt1000.ndjson` | 921 public-index records with bounty strictly greater than $1,000 |
| `knowledge/corpus_seed/curated_high_bounty_methodologies.ndjson` | 11 concise article/disclosure/methodology records |
| `knowledge/corpus_seed/expanded_high_bounty_gt1000.ndjson` | Combined 932-record corpus |
| `knowledge/HIGH_BOUNTY_EXPANSION.md` | This report and operating guidance |
| `knowledge/INGESTION_PLAN.md` | Updated source-tier, licensing, normalization, and evaluation protocol |
| `knowledge/INDEX.md` | Updated discovery map for the new high-bounty files |

The combined corpus SHA-256 is:

```text
52b6d47bfdd641896df0bdf7818a2727c4eb134b9e39c4046c1d3da7a663eac7
```

## Curated sources

| Source | Reward claim | Primary value | Status |
| --- | ---: | --- | --- |
| PortSwigger, cache poisoning research | $1,800, $2,500, $7,500, and $9,700 examples | Cache-key reasoning, safe proof, impact validation, responsible disclosure | Reviewed primary research |
| PortSwigger, Chrome infoleak | $2,000 | Browser property enumeration, cross-origin reasoning, minimal proof, patch timeline | Reviewed primary research |
| PortSwigger, hidden HTTP attack surface | Over $30,000 aggregate | Intermediary-layer methodology, unique correlation, staged scaling, scope discipline | Reviewed primary research; aggregate reward |
| GitHub Security retrospective | $10,000 single-case example | Open redirect impact chain into OAuth, trust-boundary analysis | Reviewed official summary |
| GitHub Security retrospective | $524,250 program aggregate | Triage operations, response metrics, mature program behavior | Reviewed official program report; aggregate |
| Patrik Hudak, Azure subdomain takeover | $2,000 | DNS/provider-specific verification, NXDOMAIN versus 404, harmless proof | Reviewed primary researcher write-up |
| OSINT Team, Instagram email verification | $5,000 | Business-logic state transition, client/server validation comparison | Secondary; needs corroboration |
| InfoSec Write-ups, Handlebars template issue | $10,000 | Template rendering signal, engine identification, server-side trust boundary | Secondary; needs corroboration |
| CryptoSlate, Perpetual Protocol issue | $10,000 | Smart-contract invariant and bounded impact reasoning | Secondary journalism; needs corroboration |

The curated records intentionally avoid copying live credentials, real user data, private hostnames, callback infrastructure, or destructive payloads. They store conceptual methodology and evidence requirements rather than operational exploit chains.

## What the agent should learn

The retrieval layer should prioritize **reasoning patterns** rather than bounty rankings. Each retrieved unit should answer the following questions:

| Reasoning field | Agent behavior |
| --- | --- |
| Trust boundary | Identify where the system stops verifying and starts trusting input or state. |
| Trigger signal | Name the observable, low-impact behavior that justifies the next hypothesis. |
| Confirmation pattern | Specify the minimum safe comparison or control needed to separate a bug from normal behavior. |
| Impact pattern | Explain the affected security property and realistic preconditions without exaggeration. |
| Evidence pattern | List the reproducible artifacts required for a triage-quality report. |
| Counterexample | State what would make the hypothesis invalid, out of scope, a duplicate, or inconclusive. |
| Stop condition | Define when the agent must stop testing and ask the operator for a decision. |

Do not retrieve by `bounty_usd` alone. A $10,000 record should not outrank a lower-bounty record if the latter matches the application surface, trust boundary, evidence signal, and program rules more closely. Bounty may be used as a weak prior for historical triage interest, never as a classifier for exploitability or severity.

## Recommended retrieval pipeline

The framework should load the high-bounty corpus in the following order:

1. Filter by authorization context, program scope, target surface, data class, and allowed action class.
2. Retrieve by normalized vulnerability class, trust boundary, application feature, evidence signal, and impact class.
3. Prefer `reviewed-summary` and `primary-research` records over `needs-corroboration` records.
4. Return at least one counterexample and one negative or inconclusive pattern with every high-impact hypothesis.
5. Require the Lead to cite the record IDs used for a hypothesis and distinguish source fact from model inference.
6. Convert the retrieved examples into a bounded test plan; never copy a payload or action sequence directly into live testing.
7. Record whether the hypothesis was confirmed, disproved, inconclusive, duplicate, or blocked by scope.

## Evaluation design

Create a held-out evaluation set by program and time period so the model cannot win by memorizing titles or repeated program names. The evaluation should contain positive, negative, inconclusive, duplicate, and out-of-scope examples.

| Evaluation dimension | Minimum check |
| --- | --- |
| Scope adherence | The agent refuses or pauses when authorization, asset, method, account, or rate limit is missing. |
| Hypothesis quality | The agent identifies a trust boundary, signal, precondition, counterexample, and safe next step. |
| Evidence quality | The agent requires before/after controls, reproducibility, impact explanation, and provenance. |
| False-positive control | The agent labels ambiguous behavior inconclusive instead of promoting it to a finding. |
| Redaction | No credentials, cookies, tokens, PII, or private infrastructure enter external model context. |
| Efficiency | Request count, context size, latency, and cost remain within the engagement budget. |
| Transfer | Performance holds on unseen programs, surfaces, and vulnerability classes. |

Compare four modes: direct baseline, OmniRoute free-only routing, free-only plus Memory, and free-only plus Memory plus sanitized Chaos Mode. Promote the new corpus only if evidence quality and transfer improve without increasing unsafe actions, scope violations, false positives, or request volume.

## Source and licensing policy

The current public HackerOne index is a discovery and metadata source; its records are marked `license_or_terms_checked: false` until an operator validates the applicable terms. The curated article records retain URLs and short summaries rather than full copied text. Secondary sources are explicitly flagged for corroboration. Search snippets, scraped mirrors, social posts, and AI summaries remain discovery-only and should never be used as sole evidence.

Before adding thousands of full narratives, maintain separate storage for raw source snapshots and runtime retrieval units. Apply deterministic secret and PII redaction, canonical URL normalization, content hashing, deduplication, and a human review queue for high-impact chains. If a source forbids redistribution or automated crawling, store only a citation and operator-created abstract, or omit it.

## Safety boundaries

This corpus must not become an autonomous exploitation engine. The agent may use it to rank hypotheses, ask better questions, design controlled comparisons, and improve report quality on authorized targets. It must not infer permission from a similar program, run internet-scale scans, probe third-party infrastructure, perform destructive actions, manipulate real funds or accounts, or attempt to weaponize a novel vulnerability.

For high-impact classes such as SSRF, request smuggling, template injection, browser isolation failures, cache poisoning, smart-contract accounting, and subdomain takeover, require synthetic accounts, lab or forked environments where possible, explicit program approval, a small request budget, and an operator checkpoint before any live confirmation step.

## Next expansion targets

The next safe expansion should focus on **source diversity and narrative quality**, not only record count. Add verified public Bugcrowd and Intigriti disclosures, official researcher write-ups, vendor security retrospectives, and conference papers. For every new source, require an explicit reward claim above $1,000, a canonical URL, a source-quality label, a bounty-type label, a short redacted abstract, an evidence pattern, a counterexample, and an authorization note.

A reasonable next milestone is **2,000–5,000 metadata records plus 100–250 reviewed methodology units**, rather than thousands of unverified copied articles. This will give the agent broader coverage while keeping retrieval trustworthy and evaluation tractable.

## References

[1]: https://github.com/diegosouzapw/OmniRoute/wiki/Skills "OmniRoute Skills Framework"
[2]: https://github.com/reddelexc/hackerone-reports "Public HackerOne report metadata repository"
[3]: https://portswigger.net/research/responsible-denial-of-service-with-web-cache-poisoning "PortSwigger: Responsible denial of service with web cache poisoning"
[4]: https://portswigger.net/research/using-hackability-to-uncover-a-chrome-infoleak "PortSwigger: Using Hackability to uncover a Chrome infoleak"
[5]: https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface "PortSwigger: Cracking the lens: targeting HTTP’s hidden attack-surface"
[6]: https://github.blog/security/vulnerability-research/seven-years-github-security-bug-bounty-program/ "GitHub: Seven years of the GitHub Security Bug Bounty program"
[7]: https://0xpatrik.com/subdomain-takeover-starbucks/ "Patrik Hudak: Subdomain Takeover: Starbucks points to Azure"
[8]: https://osintteam.blog/he-verified-someone-elses-email-on-instagram-and-meta-paid-5-000-73176d5e53ce "OSINT Team: He Verified Someone Else’s Email on Instagram — and Meta Paid $5,000"
[9]: https://infosecwriteups.com/the-10-000-handlebars-hack-how-email-templates-led-to-server-takeover-1458be4f48c9 "InfoSec Write-ups: The $10,000 Handlebars Hack"
[10]: https://cryptoslate.com/32-million-vulnerability-in-perpetual-protocol-uncovered-by-chainlight-nets-10k-white-hat-reward/ "CryptoSlate: $32M vulnerability in Perpetual Protocol"
