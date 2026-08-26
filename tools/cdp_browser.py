#!/usr/bin/env python3
"""
cdp_browser.py - Chrome DevTools Protocol Tool

Bridges your manually-logged-in Chrome session with automated tooling.

USAGE:
    # Extract cookies for use with curl
    python3 cdp_browser.py extract-cookies --port 9222 --output cookies.txt

    # Capture all network requests for N seconds while you click
    python3 cdp_browser.py capture-network --port 9222 --duration 60 --output network.jsonl

    # Get all <a href> links visible on current page (after JS render)
    python3 cdp_browser.py extract-links --port 9222 --output links.txt

    # Execute custom JS in page context
    python3 cdp_browser.py exec-js --port 9222 --expression "document.title"

    # Get localStorage/sessionStorage contents
    python3 cdp_browser.py extract-storage --port 9222 --output storage.json

    # Get all forms with their action+method+fields
    python3 cdp_browser.py extract-forms --port 9222 --output forms.json

    # Take a screenshot
    python3 cdp_browser.py screenshot --port 9222 --output page.png

    # Navigate to URL (uses authenticated session)
    python3 cdp_browser.py navigate --port 9222 --url "https://target.com/admin"

    # Run full auth-context recon (combo: navigate + extract everything)
    python3 cdp_browser.py auth-recon --port 9222 --base-url "https://target.com" --output recon.json
"""

import asyncio
import json
import sys
import argparse
import urllib.request
from datetime import datetime
from pathlib import Path

try:
    import websockets
except ImportError:
    print("Installing websockets library...")
    import subprocess
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'websockets', '--break-system-packages', '-q'])
    import websockets


class CDPClient:
    """Minimal CDP client for our needs.

    Single-reader architecture: only the background _reader task may call
    self.ws.recv(). All callers either await a per-id Future (send) or pull
    from an asyncio.Queue (subscribe_events). This is required because the
    `websockets` library raises ConcurrencyError if two coroutines call
    recv() on the same connection — which is exactly what happened when
    send() and an event-collector both read directly from the socket.
    """

    def __init__(self, port=9222):
        self.port = port
        self.msg_id = 0
        self.ws = None
        self.ws_url = None
        self._pending = {}            # id -> asyncio.Future for send() responses
        self._event_queues = []       # list of asyncio.Queue for event subscribers
        self._reader_task = None
        self._reader_failed = None

    async def __aenter__(self):
        try:
            tabs = json.loads(urllib.request.urlopen(f'http://localhost:{self.port}/json').read())
        except Exception as e:
            raise RuntimeError(f"Cannot connect to Chrome on port {self.port}. Is Chrome running with --remote-debugging-port={self.port}?\nError: {e}")

        # Find first page tab (not extension/background)
        page_tabs = [t for t in tabs if t.get('type') == 'page']
        if not page_tabs:
            raise RuntimeError(f"No page tabs found on port {self.port}")

        self.ws_url = page_tabs[0]['webSocketDebuggerUrl']
        self.current_url = page_tabs[0].get('url', '')
        self.ws = await websockets.connect(self.ws_url, max_size=20*1024*1024)
        self._reader_task = asyncio.create_task(self._reader())
        return self

    async def __aexit__(self, *args):
        if self._reader_task and not self._reader_task.done():
            self._reader_task.cancel()
            try:
                await self._reader_task
            except (asyncio.CancelledError, Exception):
                pass
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass

    async def _reader(self):
        try:
            while True:
                raw = await self.ws.recv()
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                mid = msg.get('id')
                if mid is not None and mid in self._pending:
                    fut = self._pending.pop(mid)
                    if not fut.done():
                        if 'error' in msg:
                            fut.set_exception(RuntimeError(f"CDP error: {msg['error']}"))
                        else:
                            fut.set_result(msg.get('result', {}))
                elif msg.get('method'):
                    for q in self._event_queues:
                        try:
                            q.put_nowait(msg)
                        except asyncio.QueueFull:
                            pass
        except asyncio.CancelledError:
            raise
        except Exception as e:
            self._reader_failed = e
            for fut in list(self._pending.values()):
                if not fut.done():
                    fut.set_exception(RuntimeError(f"CDP reader died: {e}"))
            self._pending.clear()

    async def send(self, method, params=None):
        if self._reader_failed:
            raise RuntimeError(f"CDP reader died: {self._reader_failed}")
        self.msg_id += 1
        mid = self.msg_id
        fut = asyncio.get_event_loop().create_future()
        self._pending[mid] = fut
        await self.ws.send(json.dumps({
            'id': mid,
            'method': method,
            'params': params or {}
        }))
        return await fut

    def subscribe_events(self, maxsize=10000):
        """Return an asyncio.Queue receiving every CDP event message
        (any message with a 'method' field). Caller drains the queue;
        messages are dropped silently if it fills up."""
        q = asyncio.Queue(maxsize=maxsize)
        self._event_queues.append(q)
        return q

    async def eval_js(self, expression, return_by_value=True):
        result = await self.send('Runtime.evaluate', {
            'expression': expression,
            'returnByValue': return_by_value,
            'awaitPromise': True
        })
        return result.get('result', {}).get('value')


async def cmd_extract_cookies(args):
    """Extract cookies in Netscape format for use with curl -b"""
    async with CDPClient(args.port) as cdp:
        result = await cdp.send('Network.getCookies')
        cookies = result.get('cookies', [])
        
        if args.format == 'netscape':
            # Netscape cookie file format
            lines = ["# Netscape HTTP Cookie File"]
            for c in cookies:
                domain = c.get('domain', '')
                flag = "TRUE" if domain.startswith('.') else "FALSE"
                path = c.get('path', '/')
                secure = "TRUE" if c.get('secure') else "FALSE"
                expires = int(c.get('expires', 0)) if c.get('expires', 0) > 0 else 0
                name = c.get('name', '')
                value = c.get('value', '')
                lines.append(f"{domain}\t{flag}\t{path}\t{secure}\t{expires}\t{name}\t{value}")
            output = "\n".join(lines)
        elif args.format == 'header':
            # Cookie header format
            output = "; ".join(f"{c['name']}={c['value']}" for c in cookies)
        else:  # json
            output = json.dumps(cookies, indent=2)
        
        if args.output:
            Path(args.output).write_text(output)
            print(f"Cookies written to {args.output} ({len(cookies)} cookies)")
        else:
            print(output)


async def cmd_capture_network(args):
    """Capture all network requests for a duration"""
    async with CDPClient(args.port) as cdp:
        await cdp.send('Network.enable')
        await cdp.send('Page.enable')

        print(f"Capturing network traffic for {args.duration}s. Click around in the browser now...")

        requests = {}
        q = cdp.subscribe_events()
        end_time = asyncio.get_event_loop().time() + args.duration

        while asyncio.get_event_loop().time() < end_time:
            remaining = end_time - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                msg = await asyncio.wait_for(q.get(), timeout=min(remaining, 1.0))
            except asyncio.TimeoutError:
                continue

            method = msg.get('method', '')
            params = msg.get('params', {})

            if method == 'Network.requestWillBeSent':
                req = params.get('request', {})
                requests[params.get('requestId')] = {
                    'request_id': params.get('requestId'),
                    'method': req.get('method'),
                    'url': req.get('url'),
                    'headers': req.get('headers', {}),
                    'has_post_data': req.get('hasPostData', False),
                    'post_data': req.get('postData', ''),
                    'initiator': params.get('initiator', {}).get('type'),
                    'type': params.get('type'),
                    'timestamp': params.get('timestamp')
                }
            elif method == 'Network.responseReceived':
                resp = params.get('response', {})
                rid = params.get('requestId')
                if rid in requests:
                    requests[rid]['status'] = resp.get('status')
                    requests[rid]['response_headers'] = resp.get('headers', {})
                    requests[rid]['mime_type'] = resp.get('mimeType')
                    requests[rid]['response_size'] = resp.get('encodedDataLength', 0)
        
        # Filter to relevant types
        filtered = []
        for rid, req in requests.items():
            req_type = req.get('type', '').lower()
            url = req.get('url', '')
            # Skip noise: images, fonts, stylesheets
            if req_type in ('image', 'font', 'stylesheet', 'media'):
                continue
            if not url or url.startswith('data:') or url.startswith('blob:'):
                continue
            filtered.append(req)
        
        output = "\n".join(json.dumps(r) for r in filtered)
        
        if args.output:
            Path(args.output).write_text(output)
            print(f"Captured {len(filtered)} relevant requests (filtered from {len(requests)}) → {args.output}")
        else:
            print(output)


async def cmd_extract_links(args):
    """Extract all links from current page (after JS render)"""
    async with CDPClient(args.port) as cdp:
        links = await cdp.eval_js("""
            JSON.stringify([
                ...document.querySelectorAll('a[href]'),
                ...document.querySelectorAll('[onclick*="location"]'),
                ...document.querySelectorAll('form[action]')
            ].map(el => ({
                tag: el.tagName,
                href: el.href || el.action || '',
                text: (el.textContent || '').trim().substring(0, 100),
                onclick: el.getAttribute('onclick') || ''
            })))
        """)
        
        if args.output:
            Path(args.output).write_text(links or "[]")
            print(f"Links written to {args.output}")
        else:
            print(links)


async def cmd_exec_js(args):
    """Execute arbitrary JavaScript in page context"""
    async with CDPClient(args.port) as cdp:
        result = await cdp.eval_js(args.expression)
        if args.output:
            Path(args.output).write_text(str(result))
        else:
            print(json.dumps(result, indent=2) if not isinstance(result, str) else result)


async def cmd_extract_storage(args):
    """Get localStorage and sessionStorage contents"""
    async with CDPClient(args.port) as cdp:
        local_storage = await cdp.eval_js("""
            JSON.stringify(Object.fromEntries(
                Object.entries(localStorage)
            ))
        """)
        session_storage = await cdp.eval_js("""
            JSON.stringify(Object.fromEntries(
                Object.entries(sessionStorage)
            ))
        """)
        
        result = {
            "localStorage": json.loads(local_storage or "{}"),
            "sessionStorage": json.loads(session_storage or "{}")
        }
        
        output = json.dumps(result, indent=2)
        if args.output:
            Path(args.output).write_text(output)
            print(f"Storage written to {args.output}")
        else:
            print(output)


async def cmd_extract_forms(args):
    """Extract all forms with action, method, and field names"""
    async with CDPClient(args.port) as cdp:
        forms = await cdp.eval_js("""
            JSON.stringify(Array.from(document.querySelectorAll('form')).map(f => ({
                action: f.action || '',
                method: (f.method || 'GET').toUpperCase(),
                enctype: f.enctype || '',
                fields: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                    name: i.name || '',
                    type: i.type || i.tagName.toLowerCase(),
                    value: i.type === 'password' ? '[REDACTED]' : (i.value || '').substring(0, 50),
                    required: i.required || false,
                    hidden: i.type === 'hidden'
                }))
            })))
        """)
        
        if args.output:
            Path(args.output).write_text(forms or "[]")
            print(f"Forms written to {args.output}")
        else:
            print(forms)


async def cmd_screenshot(args):
    """Take a screenshot of the current page"""
    import base64
    async with CDPClient(args.port) as cdp:
        result = await cdp.send('Page.captureScreenshot', {'format': 'png'})
        data = base64.b64decode(result.get('data', ''))
        Path(args.output).write_bytes(data)
        print(f"Screenshot saved to {args.output}")


async def cmd_navigate(args):
    """Navigate to a URL using the authenticated session"""
    async with CDPClient(args.port) as cdp:
        await cdp.send('Page.enable')
        await cdp.send('Page.navigate', {'url': args.url})
        # Wait for load
        await asyncio.sleep(args.wait or 2)
        title = await cdp.eval_js("document.title")
        current = await cdp.eval_js("window.location.href")
        print(f"Navigated to: {current}")
        print(f"Title: {title}")


async def cmd_auth_recon(args):
    """Full authenticated recon: navigate, extract everything"""
    output_dir = Path(args.output_dir or "auth_recon_output")
    output_dir.mkdir(parents=True, exist_ok=True)
    
    async with CDPClient(args.port) as cdp:
        await cdp.send('Page.enable')
        await cdp.send('Network.enable')
        
        # Start network capture
        captured_requests = {}
        capture_task = asyncio.create_task(_collect_network(cdp, captured_requests))
        
        urls_to_visit = [args.base_url]
        visited = set()
        max_pages = args.max_pages or 20
        
        all_links = set()
        all_forms = []
        all_storage = {}
        
        while urls_to_visit and len(visited) < max_pages:
            url = urls_to_visit.pop(0)
            if url in visited:
                continue
            
            print(f"[{len(visited)+1}/{max_pages}] Visiting: {url}")
            
            try:
                await cdp.send('Page.navigate', {'url': url})
                await asyncio.sleep(2)  # Let it render
                visited.add(url)
                
                # Extract links
                links_json = await cdp.eval_js("""
                    JSON.stringify(Array.from(document.querySelectorAll('a[href]')).map(a => a.href))
                """)
                page_links = json.loads(links_json or "[]")
                
                # Filter to same domain
                from urllib.parse import urlparse
                base_host = urlparse(args.base_url).netloc
                for link in page_links:
                    if base_host in link and link not in visited:
                        all_links.add(link)
                        if link not in urls_to_visit and len(urls_to_visit) < max_pages * 2:
                            urls_to_visit.append(link)
                
                # Extract forms on this page
                forms_json = await cdp.eval_js("""
                    JSON.stringify(Array.from(document.querySelectorAll('form')).map(f => ({
                        page: window.location.href,
                        action: f.action || '',
                        method: (f.method || 'GET').toUpperCase(),
                        fields: Array.from(f.querySelectorAll('input, select, textarea')).map(i => ({
                            name: i.name, type: i.type
                        }))
                    })))
                """)
                page_forms = json.loads(forms_json or "[]")
                all_forms.extend(page_forms)
                
            except Exception as e:
                print(f"   Error on {url}: {e}")
                continue
        
        # Get storage from final page
        ls = await cdp.eval_js("JSON.stringify(Object.fromEntries(Object.entries(localStorage)))")
        ss = await cdp.eval_js("JSON.stringify(Object.fromEntries(Object.entries(sessionStorage)))")
        
        # Stop network capture
        capture_task.cancel()
        try:
            await capture_task
        except asyncio.CancelledError:
            pass
        
        # Save results
        result = {
            "meta": {
                "captured_at": datetime.utcnow().isoformat() + "Z",
                "pages_visited": len(visited),
                "base_url": args.base_url
            },
            "visited_pages": sorted(visited),
            "discovered_links": sorted(all_links),
            "forms": all_forms,
            "localStorage_keys": list(json.loads(ls or "{}").keys()),
            "sessionStorage_keys": list(json.loads(ss or "{}").keys()),
            "network_requests": [r for r in captured_requests.values() 
                                if r.get('type', '').lower() not in ('image', 'font', 'stylesheet')]
        }
        
        output_file = output_dir / "auth_recon.json"
        output_file.write_text(json.dumps(result, indent=2))
        print(f"\nAuth recon complete:")
        print(f"  Pages visited:     {len(visited)}")
        print(f"  Links discovered:  {len(all_links)}")
        print(f"  Forms found:       {len(all_forms)}")
        print(f"  Network requests:  {len(result['network_requests'])}")
        print(f"  Output:            {output_file}")


async def _collect_network(cdp, store):
    """Background task: drain CDP event queue and record network requests."""
    q = cdp.subscribe_events()
    try:
        while True:
            msg = await q.get()
            method = msg.get('method')
            if method == 'Network.requestWillBeSent':
                params = msg.get('params', {})
                req = params.get('request', {})
                rid = params.get('requestId')
                store[rid] = {
                    'request_id': rid,
                    'method': req.get('method'),
                    'url': req.get('url'),
                    'type': params.get('type'),
                    'has_post_data': req.get('hasPostData', False)
                }
            elif method == 'Network.responseReceived':
                params = msg.get('params', {})
                rid = params.get('requestId')
                if rid in store:
                    store[rid]['status'] = params.get('response', {}).get('status')
    except asyncio.CancelledError:
        pass


def main():
    parser = argparse.ArgumentParser(description="CDP Browser Tool", formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = parser.add_subparsers(dest='cmd', required=True)
    
    # extract-cookies
    p = sub.add_parser('extract-cookies', help='Extract cookies')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--output', help='Output file')
    p.add_argument('--format', choices=['netscape', 'header', 'json'], default='netscape')
    
    # capture-network
    p = sub.add_parser('capture-network', help='Capture network requests')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--duration', type=int, default=30)
    p.add_argument('--output', help='Output file (JSONL)')
    
    # extract-links
    p = sub.add_parser('extract-links', help='Extract links from current page')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--output', help='Output file')
    
    # exec-js
    p = sub.add_parser('exec-js', help='Execute JavaScript')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--expression', required=True)
    p.add_argument('--output', help='Output file')
    
    # extract-storage
    p = sub.add_parser('extract-storage', help='Get localStorage/sessionStorage')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--output', help='Output file')
    
    # extract-forms
    p = sub.add_parser('extract-forms', help='Extract all forms')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--output', help='Output file')
    
    # screenshot
    p = sub.add_parser('screenshot', help='Take screenshot')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--output', required=True)
    
    # navigate
    p = sub.add_parser('navigate', help='Navigate to URL')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--url', required=True)
    p.add_argument('--wait', type=int, default=2)
    
    # auth-recon (the big one)
    p = sub.add_parser('auth-recon', help='Full authenticated reconnaissance')
    p.add_argument('--port', type=int, default=9222)
    p.add_argument('--base-url', required=True)
    p.add_argument('--max-pages', type=int, default=20)
    p.add_argument('--output-dir', help='Output directory')
    
    args = parser.parse_args()
    
    cmd_map = {
        'extract-cookies': cmd_extract_cookies,
        'capture-network': cmd_capture_network,
        'extract-links': cmd_extract_links,
        'exec-js': cmd_exec_js,
        'extract-storage': cmd_extract_storage,
        'extract-forms': cmd_extract_forms,
        'screenshot': cmd_screenshot,
        'navigate': cmd_navigate,
        'auth-recon': cmd_auth_recon,
    }
    
    asyncio.run(cmd_map[args.cmd](args))


if __name__ == '__main__':
    main()
