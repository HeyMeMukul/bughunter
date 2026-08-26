# Disclosed-Report Knowledge Base: Ingestion and Training Protocol

## Objective

Turn public disclosures into **structured hunting priors** that improve hypothesis generation, evidence collection, and triage-quality reporting. Do not treat this as supervised training on bounty size, and do not use it to infer permission to test a target. The primary deployment should be retrieval-augmented generation (RAG) plus offline evaluation; fine-tuning is a later option only after terms, redaction, and held-out testing are settled.

## Source tiers

| Tier | Source | Use | Required handling |
| --- | --- | --- | --- |
| A | Official public HackerOne report pages or platform export explicitly marked public | Canonical metadata and report narrative | Verify access, rate-limit requests, retain URL and hash, check terms |
| B | Public Bugcrowd/Intigriti disclosure pages and official researcher write-ups | Cross-platform diversity | Preserve attribution and platform taxonomy |
| C | Researcher blog, GitHub write-up, conference talk, or public post | Technique context and independent replication | Label as secondary; do not treat bounty or claims as verified without corroboration |
| D | Search snippets, reposts, scraped mirrors, AI summaries | Discovery only | Never use as sole evidence; deduplicate and verify against a higher-tier source |

For the expanded pass, retain records only when the source states a single-case or clearly labeled aggregate reward above $1,000. Store `bounty_type` as `single-case`, `reported-aggregate-over`, `program-aggregate`, or `reported-single-case`; never compare aggregate program awards directly with individual report rewards.

The current improved copy contains a metadata-only seed of **2,810** public HackerOne index rows with bounty amounts greater than $100 and a filtered subset of **921** rows above $1,000. It also includes **8** curated public article or methodology cases, producing a **929-record expanded high-bounty corpus**. The curated cases preserve summaries, source quality, confidence, and corroboration status; one secondary write-up remains flagged for corroboration. The importer intentionally does not crawl report bodies. These files are useful for ranking and source discovery, not yet a fully validated training corpus.

## Record extraction

For each public report, extract report ID, source URL, disclosure date, program, bounty amount, platform labels, normalized vulnerability class, application surface, trust boundary, impact type, outcome, attack precondition, minimum evidence, remediation theme, and counterexample/limit. Preserve a content hash and extractor version. Store a short redacted abstract and reasoning pattern rather than blindly copying the full report.

Before promotion, redact authorization headers, cookies, tokens, API keys, passwords, email addresses, phone numbers, private hostnames, sensitive identifiers, and live callback infrastructure. Keep raw source snapshots separate from runtime retrieval. Use a review queue for ambiguous or high-impact content.

## Normalization and quality gates

Normalize platform labels into a versioned taxonomy such as `idor`, `access-control`, `authentication`, `ssrf`, `xss`, `sqli`, `business-logic`, `race-condition`, and `information-disclosure`. Allow multiple labels when a report is genuinely chained, but retain primary and secondary classes. Deduplicate by canonical report URL, platform/report ID, and near-duplicate title plus source hash. Do not merge reports merely because they share a vulnerability label.

Reject or quarantine records with missing provenance, impossible bounty values, unclear single-versus-aggregate reward semantics, unredacted secrets, private-only references, unsupported legal status, or extracted content that consists only of a search snippet. Mark the current importer’s public-index records `unreviewed` and `license_or_terms_checked: false` until an operator approves the source terms. Mark secondary summaries as `needs-corroboration` and exclude them from high-confidence retrieval until confirmed.

## Retrieval units

Index small, composable units rather than whole reports: `mental-model`, `trigger-signal`, `confirmation-pattern`, `negative-pattern`, `impact-pattern`, `counterexample`, `triage-outcome`, and `chain-edge`. Retrieve by vulnerability class, trust boundary, application feature, evidence signal, impact class, and platform—not by bounty amount alone. Return source IDs and confidence with every retrieved unit.

## Evaluation split

Use a program-level and time-aware split. Keep entire programs or application families out of the evaluation set so performance measures transfer rather than title memorization. Include positives, true negatives, inconclusive cases, duplicates, and reports with low bounty but strong evidence. Evaluate verdict accuracy, evidence completeness, scope adherence, redaction, stop-condition compliance, request count, false-positive rate, and cost per validated finding.

## Safe promotion loop

1. Ingest public metadata and source URLs.
2. Verify access and terms; store hashes.
3. Extract structured fields with a model or parser, then redact deterministically.
4. Run schema, secret, PII, duplicate, and provenance checks.
5. Human-review a sample from each class and every high-impact chain.
6. Build retrieval indices and a held-out evaluation set.
7. Compare the framework with and without retrieval.
8. Promote only patterns that improve evidence-based metrics without increasing unsafe actions or scope violations.

The output should make the agent better at asking the right question and stopping at the right time. It should not turn historical reports into an autonomous zero-day exploitation system.
