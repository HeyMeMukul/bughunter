#!/usr/bin/env bash
# operator_ping.sh — LOUD attention alarm for the human operator.
#
# Usage:
#   ./tools/operator_ping.sh ["message"] [repeats]              # beep N times, then return
#   ./tools/operator_ping.sh ["message"] loop [interval_sec]    # KEEP BEEPING every interval until killed
#
# Standing framework order: whenever the Lead hits a hard gate that needs a
# human in the loop (CAPTCHA solve, approval, credentials, scope decision...),
# run this script in loop mode in the background, state exactly what is needed,
# and keep hunting everything else in the meantime. Never sit silent.
set -u

MSG="${1:-OPERATOR NEEDED}"
MODE="${2:-3}"
INTERVAL="${3:-120}"
WAV="/tmp/operator_alarm.wav"

banner() {
  echo ""
  echo "🔔🔔🔔  $MSG  🔔🔔🔔"
  echo ""
}

make_wav() {
  # Loud two-tone alarm WAV (python3, stdlib only). Rebuilt if missing.
  [ -f "$WAV" ] && return 0
  python3 - "$WAV" <<'PYEOF'
import math, struct, sys, wave
path = sys.argv[1]
rate = 44100
tone = b""
# 3 wails of 880Hz -> 660Hz, 0.35s each half = ~2.1s alarm
for _ in range(3):
    for freq in (880.0, 660.0):
        n = int(rate * 0.35)
        for i in range(n):
            s = math.sin(2 * math.pi * freq * i / rate)
            tone += struct.pack("<h", int(32767 * 0.9 * s))
with wave.open(path, "wb") as w:
    w.setnchannels(1)
    w.setsampwidth(2)
    w.setframerate(rate)
    w.writeframes(tone)
print("alarm wav written:", path)
PYEOF
}

ring_once() {
  if command -v ffplay >/dev/null 2>&1 && [ -f "$WAV" ]; then
    timeout 15 ffplay -nodisp -autoexit -volume 100 -loglevel quiet "$WAV" 2>/dev/null || true
  else
    echo "(no audio player found — terminal bell only)"
  fi
  for _ in 1 2 3; do printf '\a'; sleep 0.3; done
  banner
}

make_wav

if [ "$MODE" = "loop" ]; then
  echo "🔔 LOOP MODE: beeping every ${INTERVAL}s until killed (PID $$). Message: $MSG"
  while true; do
    ring_once
    sleep "$INTERVAL"
  done
else
  for ((i = 1; i <= MODE; i++)); do
    ring_once
  done
  echo "Repeats played: $MODE | wav: $WAV"
fi
