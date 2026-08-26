---
name: testing-prototype-pollution
description: JavaScript prototype pollution testing — both client-side (DOM XSS via gadgets) and server-side (RCE via config manipulation). Use when the application processes JSON input through merge/clone/deep-copy operations — identified by settings/preferences/config endpoints, endpoints accepting nested JSON objects, or Node.js backends using lodash.merge, jQuery $.extend, Object.assign variants. Covers pollution vectors, gadget identification, impact escalation, and framework-specific exploitation.
---

# Prototype Pollution Testing

Prototype pollution modifies the prototype of JavaScript's base Object, causing ALL objects in the application to inherit the polluted properties. Since JavaScript uses prototypes for method resolution (`obj.toString()` walks up to `Object.prototype.toString`), a polluted prototype affects everything.

The vulnerability requires three parts:
1. **Injection point** — where user input reaches a merge/clone operation
2. **Pollution** — setting `__proto__.x` or `constructor.prototype.x` to a value
3. **Gadget** — code that reads from the polluted property and does something useful (render HTML, execute a command, change authorization)

## Reference Files

- [gadgets.md](./gadgets.md) — Known gadgets in popular libraries (lodash, jQuery, Express, Next.js, etc.) and how to construct exploitation chains

## Mental Model

Think of JavaScript objects as having a hidden link to their PROTOTYPE. When you access `myObject.foo`:
1. JavaScript checks `myObject` directly → if found, return
2. If not found, check `myObject.__proto__` (the prototype) → if found, return
3. Continue up the chain to `Object.prototype`

If you can modify `Object.prototype.foo = "evil"`, then EVERY object that doesn't have its own `foo` property will return "evil" when you access `foo`.

**The attack surface:** Code that reads from an object property assuming it was explicitly set, not inherited. Examples:
- `if (user.isAdmin) { ... }` — if Object.prototype.isAdmin = true, EVERY user becomes admin
- `templateEngine.render(template, { ...defaultVars, ...userOptions })` — if polluted `defaultVars` prototype, template context changes
- `child_process.exec(cmd, options)` — if `options.shell` is polluted, command runs in a different shell

## Workflow

```
1. BASELINE → 2. CONFIRMATION → 3. NEGATIVE VERDICT → 4. EXPLOITATION
   (identify merge)   (pollute proto)   (declare not vuln)    (find gadget)

   Stop conditions checked at every step ↓
```

---

## Phase 1: Baseline

### Step 1.1: Identify Merge/Clone Operations

Where does the application take user JSON and merge it with internal objects?
- User preferences/settings endpoints (PUT/PATCH /api/user/settings)
- Configuration endpoints
- Profile update endpoints
- Template rendering with user-supplied variables
- API endpoints accepting nested JSON bodies

**Signal:** The endpoint accepts complex nested JSON that updates/modifies server-side state.

### Step 1.2: Merge Behavior Check
```json
Send: {"test": {"nested": "value"}}
Response: returns the saved data
```
Does the nested structure survive? If the server stores/returns nested objects → it's merging, not just copying top-level keys.

### Step 1.3: Property Filtering Check
Send an unusual property name: `{"unusual_xyz": "test"}`. Is it accepted and stored? If the server silently drops unknown fields → allowlist-based filtering (harder to exploit). If it stores anything → potentially vulnerable.

### Reasoning Checkpoint
```
[PHASE-1] Baseline
[ENDPOINT] {URL and method}
[MERGE-OPERATION] {yes — nested preserved / no}
[BACKEND] {Node.js / Python / other — affects which pollution keys work}
[DECISION] {Proceed / No merge behavior — STOP}
```

---

## Phase 2: Confirmation

### Confidence Definitions
| Level | For Prototype Pollution |
|-------|----------------------|
| HIGH | `__proto__` or `constructor.prototype` property is polluted AND affects other objects (verified by querying a different object) |
| MEDIUM | Pollution accepted in input but effect on other objects not confirmed |
| LOW | `__proto__` stripped/rejected, or no effect |

### Step 2.1: Server-Side Pollution

Test each vector:
```json
{"__proto__": {"polluted": "YES_RCE_TEST"}}
{"constructor": {"prototype": {"polluted": "YES_RCE_TEST"}}}
{"__proto__.polluted": "YES_RCE_TEST"}
{"constructor.prototype.polluted": "YES_RCE_TEST"}
```

Then make a DIFFERENT request that returns a fresh object. Check if that object has `"polluted": "YES_RCE_TEST"`:
- Query another user's profile → does it contain "polluted"?
- Access a different endpoint → does the response contain "polluted"?
- Look at any object in any response — if the pollution leaks, prototype is compromised.

### Step 2.2: Client-Side Pollution

For client-side PP, check if URL parameters or JSON input flow into client-side merge operations:
```
https://target.com/#__proto__[polluted]=YES
https://target.com/?__proto__[polluted]=YES
https://target.com/?__proto__.polluted=YES
```

After loading, check browser console:
```javascript
console.log(Object.prototype.polluted);
// If "YES" → client-side PP confirmed
```

### Step 2.3: Framework-Specific Techniques

**Express.js (qs library):**
```
?__proto__[isAdmin]=true
?constructor[prototype][isAdmin]=true
```

**JSON.parse with reviver:** Usually safe, but custom parsers may be vulnerable.

**lodash.merge/_.set:** Vulnerable in versions < 4.17.12.

**jQuery $.extend(true, ...):** Vulnerable in versions < 3.4.0.

### Step 2.4: Persistence Check

Does pollution survive across requests?
- **Per-request:** Only affects the current request — still exploitable but limited
- **Persistent (per-server-instance):** Affects ALL subsequent requests on that server instance — much higher impact
- **Persistent (across server restarts):** Would require writing to disk — rare

**Max confirmation attempts: 8 pollution vectors.**

### Reasoning Checkpoint
```
[PHASE-2] Confirmation
[VECTOR] {__proto__ / constructor.prototype / dot notation}
[SIDE] {server / client}
[POLLUTION-CONFIRMED] {yes — affects other objects / accepted but no effect / rejected}
[PERSISTENCE] {per-request / per-instance}
[CONFIDENCE] {HIGH / MEDIUM / LOW}
[DECISION] {Proceed / Negative verdict}
```

---

## Negative Verdict

### True Negative Conditions
- `__proto__` and `constructor` keys stripped/rejected
- No pollution effect on other objects
- Application uses `Object.create(null)` or safe merge libraries
- Tested both direct and dot-notation variants
- Tested both server and client sides if applicable

---

## Phase 3: Exploitation — Find Gadgets

Pollution alone isn't impact. You need a GADGET — code that reads the polluted property and does something dangerous.

### Common Server-Side Gadgets

| Polluted Property | Gadget | Impact |
|-------------------|--------|--------|
| `shell` | child_process.exec options | RCE via shell command |
| `env` | child_process.spawn options | Environment variable injection → RCE |
| `NODE_OPTIONS` | Node.js startup options | Arbitrary code execution |
| `argv0` / `argv` | Process arguments | Command injection in child processes |
| `header` / `body` | Template rendering | XSS or template injection |
| `isAdmin` / `role` | Authorization checks | Privilege escalation |

**Example RCE gadget (Node.js child_process):**
```json
{"__proto__": {"shell": "node", "argv0": "-e 'require(\"child_process\").execSync(\"id\")'"}}
```
If the application later calls `exec()` without explicit options → these polluted options are used.

### Common Client-Side Gadgets

| Polluted Property | Gadget | Impact |
|-------------------|--------|--------|
| `srcdoc`, `src` | iframe/img attributes | XSS via dynamic element creation |
| `innerHTML` | DOM manipulation | XSS |
| `href` | Link construction | Open redirect or XSS (javascript:) |
| `target` | Link behavior | Tabnabbing |

### Level 1: Demonstrate Gadget Exploitation
Identify a gadget specific to the application's dependencies. Research the libraries in `package.json`.

### Level 2: Impact
Show concrete impact: RCE on server, XSS on client, authorization bypass.

**Stop condition:** Gadget exploitation confirmed → STOP.

---

## Things to Do
- Test BOTH `__proto__` and `constructor.prototype` — some filters only block one
- Verify pollution AFFECTS other objects — set in one place, read in another
- Research the application's dependencies — known library gadgets are the fastest exploitation path
- Test both server-side and client-side vectors — they have different attack surfaces

## Things Not to Do
- Do not assume pollution is exploitable without a gadget — impact depends entirely on what reads the polluted property
- Do not pollute persistently on production without understanding the effect scope
- Do not skip client-side testing for applications with heavy JS

## Cross-Skill Links
- [[xss]] — Client-side PP leads to DOM XSS via gadgets
- [[command-injection]] — Server-side PP can achieve RCE through child_process gadgets
- [[ssti]] — Template rendering gadgets overlap with SSTI
