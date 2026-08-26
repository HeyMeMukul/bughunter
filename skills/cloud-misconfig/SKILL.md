---
name: testing-cloud-misconfig
description: Cloud service misconfiguration testing for AWS, GCP, Azure, and Kubernetes. Use when the target is cloud-hosted — identified by cloud provider indicators (DNS records, response headers, IP ranges, error pages), known cloud URLs in JavaScript/source, or direct cloud service exposure. Covers storage bucket enumeration and access, subdomain takeover on cloud services, metadata endpoint exploitation via SSRF, exposed management interfaces, leaked cloud credentials, and Kubernetes-specific issues.
---

# Cloud Misconfiguration Testing

Cloud misconfigurations are among the highest-impact findings in modern bug bounty. Exposed storage buckets leak data at massive scale. Dangling DNS records enable subdomain takeover. Metadata endpoints accessed via SSRF yield IAM credentials. Kubernetes API servers exposed without authentication grant cluster-wide access. The cloud provides powerful primitives, but each requires careful configuration that developers frequently get wrong.

## Reference Files

- [enumeration.md](./enumeration.md) — Cloud-specific enumeration techniques: bucket naming patterns, subdomain takeover checks, Kubernetes recon

## Mental Model

Cloud services create a new attack surface that exists OUTSIDE the application code:
- **Storage:** S3, GCS, Azure Blob — misconfigurations expose data
- **Identity:** IAM roles, service accounts — overprivileged roles enable lateral movement
- **Compute metadata:** EC2 IMDS, GCP metadata — accessible via SSRF, leaks credentials
- **Orchestration:** Kubernetes, ECS — API servers and dashboards often exposed
- **DNS:** CNAME records pointing to unclaimed services = subdomain takeover

**Key insight:** Cloud services have DEFAULT configurations that are convenient for developers but insecure. Developers who don't explicitly harden them leave them in that default state.

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (cloud mapping)   (test access)     (declare secure)     (demonstrate exposure)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline — Cloud Mapping

### Step 1.1: Provider Identification
- DNS records (CNAME to `*.amazonaws.com`, `*.googleapis.com`, `*.azurewebsites.net`)
- Response headers (`Server: AmazonS3`, `x-goog-*`, `x-ms-*`)
- IP ranges (check against known cloud provider ranges via WHOIS)
- Error pages (S3 `NoSuchBucket`, Azure Blob error format, GCP's distinct 404 style)
- JS/source references to `s3://`, cloud SDK usage

### Step 1.2: Service Enumeration
Map which cloud services the organization uses:
- **AWS:** S3 (storage), CloudFront (CDN), EC2 (compute), Lambda (functions), API Gateway, RDS, DynamoDB, ELB
- **GCP:** Cloud Storage, Cloud Functions, App Engine, GKE, Cloud SQL, Firebase
- **Azure:** Blob Storage, App Service, Functions, AKS, SQL Database, Cosmos DB

### Step 1.3: Bucket/Container Name Discovery

Find bucket names from:
- JavaScript files (direct S3 URLs)
- Source code on GitHub
- Cached/archived pages referencing storage
- Predictable naming conventions:
  ```
  {company}
  {company}-assets, {company}-uploads, {company}-static
  {company}-backups, {company}-logs, {company}-exports
  {company}-dev, {company}-staging, {company}-prod
  {company}-public, {company}-private, {company}-internal
  {company}-docs, {company}-media, {company}-videos
  assets-{company}, static-{company}, media-{company}
  ```

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[PROVIDER] {AWS / GCP / Azure / multi}
[SERVICES] {identified services}
[BUCKETS] {candidate bucket names}
[DECISION] {Proceed / No cloud indicators — STOP}
```

---

## Phase 2: Confirmation

### Step 2.1: S3 Bucket Testing

**Listing check:**
```bash
curl https://BUCKET.s3.amazonaws.com/
# If XML listing is returned → bucket is publicly listable
```

**ACL check:**
```bash
curl https://BUCKET.s3.amazonaws.com/?acl
# Returns XML with permissions
# Look for: AllUsers or AuthenticatedUsers with READ/WRITE
```

**Write test (only if program allows):**
```bash
curl -X PUT https://BUCKET.s3.amazonaws.com/poc_test.txt -d "test"
```

**Authenticated enumeration (if you have ANY AWS credentials):**
```bash
aws s3 ls s3://BUCKET
aws s3api get-bucket-acl --bucket BUCKET
# Many buckets block anonymous but allow ANY authenticated AWS user
```

### Step 2.2: GCS Bucket Testing
```bash
# Listing
curl https://storage.googleapis.com/BUCKET/

# API-based listing
curl "https://storage.googleapis.com/storage/v1/b/BUCKET/o"

# ACL
gsutil iam get gs://BUCKET
```

### Step 2.3: Azure Blob Testing
```bash
# List container
curl "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"

# Check public access
curl "https://ACCOUNT.blob.core.windows.net/CONTAINER/file.txt"
```

### Step 2.4: Subdomain Takeover Detection
```bash
# Find dangling CNAMEs
for sub in $(cat subdomains.txt); do
  cname=$(dig +short CNAME $sub | head -1)
  [ -z "$cname" ] && continue
  
  # Check if the CNAME target is unclaimed
  response=$(curl -s -o /dev/null -w "%{http_code}" "https://$sub")
  
  # Distinctive error pages indicating takeover opportunity
  body=$(curl -s "https://$sub")
  
  if echo "$body" | grep -q "NoSuchBucket\|There isn't a GitHub Pages site here\|No such app\|The specified bucket does not exist"; then
    echo "TAKEOVER CANDIDATE: $sub → $cname"
  fi
done
```

Services vulnerable to takeover: GitHub Pages, Heroku, AWS S3/Elastic Beanstalk, Azure Websites, Fastly, Ghost, Shopify, Surge, Tumblr, WordPress.com, Zendesk, Readme.io, Bitbucket Pages.

### Step 2.5: Metadata Endpoint (via SSRF)

If [[ssrf]] is available:
- **AWS:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/` → IAM credentials
- **GCP:** `http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token` → OAuth token (requires `Metadata-Flavor: Google`)
- **Azure:** `http://169.254.169.254/metadata/identity/oauth2/token?api-version=...` → Managed identity token (requires `Metadata: true`)

### Step 2.6: Exposed Management Interfaces

Scan for exposed cloud infrastructure on non-standard ports:
- **Kubernetes Dashboard:** `/dashboard/`, `/api/v1/`, `/apis/`
- **Jenkins:** Port 8080, `/` shows "Welcome to Jenkins"
- **Elasticsearch:** Port 9200, `/` returns JSON with cluster info
- **MongoDB:** Port 27017, unauthenticated access
- **Redis:** Port 6379, test `AUTH` response
- **Docker API:** Port 2375 (unauthenticated), 2376 (TLS)
- **Kibana:** Port 5601
- **etcd:** Port 2379

**Max confirmation attempts: 15 across different cloud services.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[SERVICE] {S3 / GCS / Azure / K8s / metadata / exposed interface}
[FINDING] {listing / read / write / takeover / credentials}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Try different services / Negative verdict}
```

---

## Phase 3: Exploitation

### Level 1: Data Exposure Documentation
List accessible data types. Sample file types and sensitivity (but don't download at scale).

### Level 2: Credential Access
If metadata SSRF yielded IAM credentials → document the role and its permissions. DO NOT use credentials for further access unless explicitly authorized.

### Level 3: Subdomain Takeover
Document the dangling DNS record. Claim the resource only if program explicitly allows.

**Stop condition:** Data exposure or credential access confirmed → STOP.

---

## Things to Do
- Test predictable bucket names — most cloud misconfigs are found via simple naming
- Check BOTH anonymous AND authenticated AWS access to buckets
- Scan JS files for cloud URLs — developers hardcode bucket names frequently
- Verify dangling DNS before claiming takeover resources
- Check all cloud providers — many orgs are multi-cloud

## Things Not to Do
- Do not use exposed IAM credentials to access additional resources — document only
- Do not write to production buckets without explicit authorization
- Do not download large amounts of data — sample and document

## Cross-Skill Links
- [[ssrf]] — Required for metadata endpoint exploitation
- [[path-traversal]] — May expose cloud configuration files
