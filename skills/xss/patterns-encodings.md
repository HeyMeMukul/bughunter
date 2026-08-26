# Encoding Techniques Reference

## ⚠️ CRITICAL: How to Use This File

**This file contains ENCODING PATTERNS to understand, NOT random encodings to try.**

**Before using encodings:**
1. Test if the application decodes the encoding type (URL, HTML entity, Unicode)
2. Determine WHEN decoding happens — before or after filter?
3. Only encoding that's decoded AFTER filtering will work as bypass
4. Test systematically: one encoding type at a time

**Testing methodology:**
```
1. Send: test%22 (URL encoded ")
2. Check response: 
   - Shows test" → URL decoding works, test if filter bypassed
   - Shows test%22 → URL decoding not happening, try other encoding
```

**Stop Conditions:**
- After testing 4-5 encoding types for a character with no success → character is truly blocked
- Move to alternative payload structure that doesn't need that character
- Or try alternative breakout context

---

## URL Encoding

### Standard URL Encoding
| Character | Encoded |
|-----------|---------|
| `<` | `%3C` |
| `>` | `%3E` |
| `"` | `%22` |
| `'` | `%27` |
| `(` | `%28` |
| `)` | `%29` |
| `/` | `%2F` |
| `=` | `%3D` |
| space | `%20` |
| `:` | `%3A` |

### Double URL Encoding
| Character | Double Encoded |
|-----------|----------------|
| `<` | `%253C` |
| `>` | `%253E` |
| `"` | `%2522` |

---

## HTML Entity Encoding

### Named Entities
| Character | Named |
|-----------|-------|
| `<` | `&lt;` |
| `>` | `&gt;` |
| `"` | `&quot;` |
| `&` | `&amp;` |

### Decimal Entities
| Character | Decimal |
|-----------|---------|
| `<` | `&#60;` |
| `>` | `&#62;` |
| `"` | `&#34;` |
| `'` | `&#39;` |
| `(` | `&#40;` |
| `)` | `&#41;` |

### Hex Entities
| Character | Hex |
|-----------|-----|
| `<` | `&#x3c;` |
| `>` | `&#x3e;` |
| `"` | `&#x22;` |
| `(` | `&#x28;` |

---

## JavaScript Encoding

### Unicode Escapes
`alert` = `\u0061\u006c\u0065\u0072\u0074`

| Character | Unicode |
|-----------|---------|
| `a` | `\u0061` |
| `<` | `\u003c` |
| `"` | `\u0022` |

### Hex Escapes
| Character | Hex |
|-----------|-----|
| `a` | `\x61` |
| `<` | `\x3c` |

---

## Quick Reference by Blocked Character

### `<` blocked
`%3C`, `%253C`, `&#60;`, `&#x3c;`, `\u003c`

### `"` blocked  
`%22`, `%2522`, `&#34;`, `&#x22;`, `\u0022`, `&quot;`

### `'` blocked
`%27`, `%2527`, `&#39;`, `&#x27;`, `\u0027`

### `(` blocked
`%28`, `&#40;`, `&#x28;`, `\u0028`

### `)` blocked
`%29`, `&#41;`, `&#x29;`, `\u0029`

---

## Testing Methodology

1. **Test if encoding decoded:** Send `test%22`, check if response shows `test"`
2. **Test timing:** Is decoding before or after filter?
3. **Try double encoding:** If single fails, try `%2522`
4. **Context matters:** HTML entities work in HTML, not URLs
