# Business Logic Flaw Patterns by Feature

## When to Use

Consult when you've mapped a workflow in Phase 1 and need ideas for what assumptions to test. Organized by feature type.

---

## E-Commerce / Payments

| Pattern | Test | Impact |
|---------|------|--------|
| Price manipulation | Change price in request body, modify cart total client-side | Free/cheap purchases |
| Negative quantity | Order -1 item → credit applied to account | Financial gain |
| Currency confusion | Change currency code (USD→JPY) in request | Arbitrage |
| Coupon stacking | Apply multiple exclusive coupons, reuse single-use coupons | Unauthorized discounts |
| Race on coupon redemption | 50 simultaneous requests to apply same coupon | Multiple uses of single-use code |
| Skip payment step | Send order confirmation request without payment | Free order |
| Modify after payment | Change order items/quantities after payment confirmed but before processing | Get different items than paid for |
| Refund abuse | Refund item → keep item → order again with refund credit | Free items |
| Gift card balance | Transfer negative amount to another card, overspend beyond balance | Balance manipulation |
| Checkout with empty cart | Process checkout when cart total is $0 due to manipulation | Free order processing |

## Authentication / Account Management

| Pattern | Test | Impact |
|---------|------|--------|
| Registration with privileged email | Register with admin@target.com, support@target.com | Impersonation, privilege |
| Email verification bypass | Skip email verification step, access features without verifying | Unverified account access |
| Password reset token reuse | Use the same reset token twice | Persistent account access |
| Password reset for other users | Initiate reset for victim, intercept or predict token | Account takeover |
| MFA bypass via fallback | Skip MFA, use backup code, use "remember device" | MFA circumvention |
| Account merge abuse | Link attacker's social account to victim's account | Account takeover |
| Rate limit on OTP | No rate limit → brute-force 4-6 digit OTP | Account takeover |
| Email change without reverification | Change email without re-entering password or confirming | Account hijack preparation |
| Session persistence after password change | Old sessions remain valid after password change | Persistent unauthorized access |

## Subscription / Billing

| Pattern | Test | Impact |
|---------|------|--------|
| Plan downgrade retains features | Downgrade from premium to free, keep premium features | Free premium access |
| Trial extension | Create new trial with same email, manipulate trial_end date | Infinite trial |
| Cancellation keeps access | Cancel subscription, retain access until "end of period" manipulation | Extended unauthorized access |
| Seat count manipulation | Add users beyond seat limit, modify seat_count in request | Unauthorized seats |
| Invoice manipulation | Modify invoice amount, change payment method to test card | Financial manipulation |

## Multi-Tenancy

| Pattern | Test | Impact |
|---------|------|--------|
| Tenant ID manipulation | Change org_id/tenant_id in request | Cross-tenant data access |
| Shared resource isolation | Access resources from another tenant via shared components | Data leak |
| Admin of one tenant → access another | Use admin privileges to access other tenant's admin panel | Cross-tenant admin access |
| Invitation cross-tenant | Accept invitation meant for one organization while in another | Unauthorized org access |

## Approval Workflows

| Pattern | Test | Impact |
|---------|------|--------|
| Self-approval | Submit request, approve own request | Authorization bypass |
| Skip approval | Directly trigger the post-approval action | Process bypass |
| Modify after approval | Change request details after approval but before execution | Unauthorized modification |
| Approval token reuse | Reuse approval tokens for different requests | Unauthorized approvals |
| Lower the approval threshold | Modify amount to below approval threshold, then increase after | Skip approval requirement |

## File/Document Management

| Pattern | Test | Impact |
|---------|------|--------|
| Share link permission escalation | Modify share link from "view" to "edit" | Unauthorized modification |
| Version manipulation | Access older versions that contained sensitive data | Historical data exposure |
| Delete permission bypass | Delete files owned by other users | Data destruction |
| Export all data | Export endpoint without per-record authorization | Mass data exfiltration |

---

## Universal Patterns (Test on EVERYTHING)

1. **Does the server validate what the frontend sends, or trust it?**
2. **What happens when you REMOVE a required field entirely?**
3. **What happens with negative numbers in ANY numeric field?**
4. **Can you reach Step N without completing Steps 1 through N-1?**
5. **Can you perform an action as User A that should only be available to User B?**
6. **Is there a race condition on any limit-enforced operation?**
