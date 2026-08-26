# Knowledge Base Schema

The knowledge base is a **retrieval and evaluation corpus**, not a source of authority and not a license to test arbitrary systems. Every record must be derived from an openly accessible source or an engagement artifact the operator is authorized to use.

## Report record

```json
{
  "record_id": "h1-197786",
  "source": {
    "platform": "hackerone",
    "url": "https://hackerone.com/reports/197786",
    "report_id": "197786",
    "retrieved_at": "2026-08-26T00:00:00Z",
    "content_sha256": "...",
    "license_or_terms_checked": true
  },
  "labels": {
    "canonical_classes": ["information-disclosure"],
    "platform_labels": ["..."],
    "application_surface": ["rest-api"],
    "trust_boundaries": ["backend-database"],
    "impact_class": "high",
    "outcome": "accepted-paid"
  },
  "economics": {"bounty_usd": 12500, "threshold_passed": true},
  "content": {
    "title_redacted": "...",
    "abstract": "one-paragraph summary with no secrets or PII",
    "reasoning_pattern": "what assumption failed and how it was validated",
    "evidence_pattern": "what minimum evidence established impact",
    "counterexample_or_limit": "when the technique would not generalize"
  },
  "quality": {
    "source_quality": "primary|mirror|secondary",
    "extraction_confidence": 0.0,
    "review_status": "unreviewed|reviewed|rejected"
  }
}
```

## Rules

A record must retain its source URL, platform, report ID when available, retrieval time, and content hash. Bounty size is a ranking feature, not a vulnerability label. Accepted, duplicate, rejected, informative, and inconclusive outcomes should be represented separately so the model learns boundaries rather than only success narratives.

Raw cookies, authorization headers, API keys, passwords, personal email addresses, private attachments, live exploit infrastructure, and unredacted HTTP bodies do not belong in the shared corpus. Store raw evidence only inside a local, access-controlled engagement directory when the operator is authorized to retain it.

Use the corpus for RAG and offline evaluation first. Fine-tuning is optional and should be considered only after licensing, redaction, deduplication, and held-out evaluation are established. A report teaches a hypothesis pattern; it does not prove a new target is vulnerable.
