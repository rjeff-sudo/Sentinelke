# ExamGuard — Network Traffic Monitor for Exam Integrity

## One Line Pitch
A lightweight network monitor that sits on the institution WiFi,
maps every exam machine to a physical desk, and flags any device
that contacts an AI service during exam hours — in real time.

---

## What This Is NOT
- Not an exam platform
- Not a replacement for the existing exam website
- Does not interfere with the exam system in any way
- Does not block any traffic
- Does not touch any machine on the network

---

## What This IS
A read-only network monitor with one job:
- Watch DNS queries and TCP connections on the institution WiFi
- Flag any exam machine that contacts a known AI service
- Show the invigilator exactly which desk, in real time

---

## The Environment
- Institution owned machines, students have no sudo access
- No VPN installation possible (no sudo)
- No phones in exam room (physically separated)
- All machines on institution WiFi
- Students use Chrome or Firefox only
- Exam platform is an existing external website (not touched)

---

## Core Components

### 1. Go Network Monitor
Runs on a laptop or server connected to institution WiFi.
Does three things only:
- Captures DNS queries from all machines on the network
- Monitors TCP connections to known AI IP ranges
- Sends flagged events to the dashboard in real time

### 2. Invigilator Dashboard (PHP)
One page. Two modes:

**Setup Mode (before exam starts)**
- Invigilator opens dashboard
- Sees a visual grid of desks exactly as they appear in the room
- Clicks each desk and assigns:
  - Student name
  - Machine MAC address (auto-discovered via ARP)
  - Machine IP

**Live Mode (during exam)**
- Same desk grid now shows live status per desk
- Green = clean
- Red = flagged (AI site accessed)
- Shows domain accessed and exact timestamp
- Invigilator sees which physical desk to walk to immediately

---

## How the Desk Grid Works
```
┌─────────────────────────────────────────────────────────┐
│                 EXAM ROOM — LIVE VIEW                   │
│                 Web Dev Fundamentals                    │
│                 10:30 — 12:30                           │
├───────────┬───────────┬───────────┬───────────┬─────────┤
│  DESK 1   │  DESK 2   │  DESK 3   │  DESK 4   │ DESK 5  │
│ Alice W.  │ Brian O.  │ Carol M.  │ David K.  │ Eve N.  │
│ .41       │ .42       │ .43       │ .44       │ .45     │
│           │           │           │           │         │
│  ✅ Clean │  ✅ Clean │ 🚨 FLAG  │  ✅ Clean │✅ Clean │
│           │           │chatgpt.com│           │         │
│           │           │ 10:34:22  │           │         │
├───────────┴───────────┴───────────┴───────────┴─────────┤
│  DESK 6   │  DESK 7   │  DESK 8   │  DESK 9   │ DESK 10 │
│ Frank M.  │ Grace A.  │ Henry K.  │ Irene W.  │ James O.│
│ .46       │ .47       │ .48       │ .49       │ .50     │
│           │           │           │           │         │
│  ✅ Clean │  ✅ Clean │  ✅ Clean │  ✅ Clean │✅ Clean │
└───────────┴───────────┴───────────┴───────────┴─────────┘
```

Grid layout is configured by the invigilator to match
the exact physical arrangement of desks in the room.

---

## What Happens When a Flag Fires
```
10:34am — Carol on Desk 3 opens new tab, types chatgpt.com

10:34am — DNS query leaves her machine before page loads:
          192.168.1.43 → "what is chatgpt.com?"

10:34am — Go monitor catches it:
          MAC: 11:22:33 → IP: .43 → chatgpt.com → 10:34:22

10:34am — Dashboard updates instantly:
          Desk 3 turns red
          Shows: chatgpt.com — 10:34:22

10:34am — Invigilator walks to Desk 3
          Carol has not received the answer yet
```

---

## Evidence Integrity

Student clears browser data after exam — does not matter:
```
Browser history:      CLEARED — student controls this
DNS query log:        PRESERVED — your server controls this
TCP connection log:   PRESERVED — your server controls this
ARP mapping:          PRESERVED — your server controls this
```

---

## AI Watchlist
```go
var AIWatchlist = []string{
    "chatgpt.com",
    "chat.openai.com",
    "openai.com",
    "gemini.google.com",
    "claude.ai",
    "anthropic.com",
    "copilot.microsoft.com",
    "bing.com",
    "perplexity.ai",
    "you.com",
    "character.ai",
    "huggingface.co",
    "poe.com",
    "phind.com",
    "blackboxai.com",
}
```
List is editable — invigilator can add new AI tools
as they emerge without touching the monitor code.

---

## Post Exam Report

After exam ends, dashboard generates a simple report:
```
EXAM SESSION REPORT
Exam:    Web Development Fundamentals
Date:    2026-03-12
Period:  10:30 — 12:30

FLAGGED INCIDENTS
─────────────────────────────────────────────────
Desk 3  Carol Muthoni   chatgpt.com    10:34:22
Desk 3  Carol Muthoni   openai.com     10:34:23
─────────────────────────────────────────────────
Total flags: 2
Clean desks: 9 of 10

FULL CONNECTION LOG
─────────────────────────────────────────────────
10:30:01  Desk 1  Alice W.    exam-site.co.ke
10:30:02  Desk 2  Brian O.    exam-site.co.ke
10:30:03  Desk 3  Carol M.    exam-site.co.ke
10:34:22  Desk 3  Carol M.    chatgpt.com       ← FLAG
10:34:23  Desk 3  Carol M.    openai.com        ← FLAG
...
```

Exportable as PDF for disciplinary process.

---

## Tech Stack
| Component        | Technology          |
|------------------|---------------------|
| Network Monitor  | Go (gopacket)       |
| Dashboard        | PHP                 |
| Database         | PostgreSQL          |
| Deployment       | Single laptop on LAN|

---

## Build Phases

### Phase 1 — Go Monitor
- ARP discovery of all machines on network
- DNS query capture and watchlist matching
- TCP connection monitoring to AI IP ranges
- REST API endpoint to push events to dashboard

### Phase 2 — Invigilator Dashboard
- Visual desk grid (configurable layout)
- MAC to desk to student assignment (setup mode)
- Live status per desk (monitor mode)
- Flag display with domain and timestamp

### Phase 3 — Reporting
- Post exam audit log per session
- Per student incident report
- PDF export for evidence

---

## Deployment
```
One laptop running:
├── Go monitor binary    ← watching the network
├── PHP dashboard        ← invigilator opens in browser
└── PostgreSQL           ← storing all logs

Connected to institution WiFi
No installation on exam machines
No changes to exam website
No changes to institution network
Plug in and run
```

---

## Notes
- Designed: March 2026
- Does not interfere with existing exam platform in any way
- First deployment: institution's own exam environment
- Builds on same Go networking stack as SentinelKE
- Reference conversation saved in Claude.ai chat history