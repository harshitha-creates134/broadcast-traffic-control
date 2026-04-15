# 📡 SDN Broadcast Traffic Control
### Orange Level Project – Computer Networks (UE24CS252B) | PES University

---

## Problem Statement

Uncontrolled broadcast traffic (broadcast storms) can saturate network links and degrade performance for all hosts in a broadcast domain. Traditional networks have no fine-grained mechanism to detect or limit per-host broadcast rates.

This project implements an **SDN-based Broadcast Traffic Control** system using **Mininet** and the **Ryu OpenFlow 1.3 controller** that:

- **Detects** broadcast frames (dst = `ff:ff:ff:ff:ff:ff`) via `packet_in` events
- **Limits flooding** by tracking per-host broadcast rates using a sliding time window
- **Installs selective forwarding rules** — allowing legitimate ARP/DHCP broadcasts while blocking storm traffic with DROP flow rules
- **Evaluates improvement** via before/after packet counts, controller logs, and `broadcast_log.csv`

---

## Topology

```
    h1 (10.0.1.1)     h2 (10.0.1.2)
         \                  /
          s1 ────────── s2
         /                  \
    h3 (10.0.1.3)     h4 (10.0.1.4)
```

- 2 OVS switches, 4 hosts, all in subnet `10.0.1.0/24`
- TCLink with configurable bandwidth (default 10 Mbps) and delay (2ms host, 1ms inter-switch)
- Broadcasts must traverse the inter-switch link to reach all hosts — making control effective and measurable

---

## Flow Rule Design

| Priority | Match Fields | Action | Hard Timeout | Purpose |
|----------|-------------|--------|-------------|---------|
| 0 | Any | → Controller | Permanent | Table-miss default |
| 5 | `eth_src=<host>` + `eth_dst=broadcast` | **DROP** | 60s | Block storm offender |
| 5 | `in_port + eth_src + eth_dst=broadcast` | → FLOOD | 5s | Allow legitimate burst |
| 1 | `in_port + eth_src + eth_dst` (unicast) | → Learned port | idle=30s, hard=120s | Unicast forwarding |

> **Note:** Priority 5 > Priority 1 > Priority 0 — DROP rules always win over flood/unicast.

---

## Controller Logic

```
packet_in received
       │
       ├─ Is broadcast? (dst == ff:ff:ff:ff:ff:ff)
       │       │
       │       ├─ Count broadcasts from src in last 10s window
       │       │
       │       ├─ count >= THRESHOLD (10)?
       │       │       YES → Install DROP rule (priority 5, hard_timeout=60s)
       │       │               Log block to CSV
       │       │
       │       └─ count < THRESHOLD?
       │               YES → Install short FLOOD rule (priority 5, hard_timeout=5s)
       │                       Forward packet out
       │
       └─ Unicast?
               │
               ├─ Learn MAC → port
               └─ Install forwarding rule (priority 1)
```

**Tunable parameters** (top of `broadcast_controller.py`):

| Parameter | Default | Description |
|-----------|---------|-------------|
| `BROADCAST_THRESHOLD` | 10 | Max broadcasts per host per window |
| `COUNT_WINDOW` | 10s | Sliding window for rate counting |
| `BLOCK_DURATION` | 60s | How long the DROP rule lasts |
| `FLOOD_HARD_TIMEOUT` | 5s | Lifetime of selective FLOOD rules |
| `STATS_INTERVAL` | 10s | Metrics report frequency |

---

## Setup & Execution

### Prerequisites
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install mininet openvswitch-switch iperf wireshark tcpdump -y
pip3 install ryu
```

### Step 1 – Clean previous state
```bash
sudo mn -c
```

### Step 2 – Start Ryu Controller (Terminal 1)
```bash
ryu-manager broadcast_controller.py --observe-links
```

### Step 3 – Launch Topology (Terminal 2)
```bash
sudo python3 topology.py --bw 10 --scenario all
```

Or run individual scenarios:
```bash
sudo python3 topology.py --scenario 1   # Normal broadcast
sudo python3 topology.py --scenario 2   # Broadcast storm + blocking
sudo python3 topology.py --scenario 3   # Evaluation (before vs. after)
```

---

## Test Scenarios

### Scenario 1 – Normal Broadcast (below threshold)
Each host sends 5 broadcast pings — well below the threshold of 10.
```bash
mininet> h1 ping -b -c 5 -i 0.2 10.0.1.255
```
**Expected:** Controller logs `ALLOWED` for each. Selective FLOOD rules installed. All hosts receive pings.

### Scenario 2 – Broadcast Storm (exceeds threshold)
h1 sends 50 rapid broadcast pings.
```bash
mininet> h1 ping -b -c 50 -i 0.05 10.0.1.255
```
**Expected:** First 10 allowed → controller installs **DROP rule** → remaining 40 dropped at switch (never reach controller or other hosts).

**Verify DROP rule installed:**
```bash
mininet> sh ovs-ofctl dump-flows s1
# Look for: priority=5, eth_dst=ff:ff:ff:ff:ff:ff → actions= (empty = DROP)
```

**Verify unicast still works (broadcast block must NOT affect unicast):**
```bash
mininet> h2 ping -c 4 10.0.1.1
# Expected: 0% packet loss
```

### Scenario 3 – Evaluation
Compares packets received at h2 during a controlled burst vs. a storm:

| Phase | Sent | Received at h2 | Notes |
|-------|------|---------------|-------|
| A: Normal (8 pings) | 8 | ~8 | All allowed |
| B: Storm (30 pings) | 30 | ~10 | ~20 blocked |
| **Reduction** | | | **~67% fewer floods** |

---

## Expected Controller Output

```
10:15:02 [INFO]  [BCAST] ALLOWED  src=00:00:00:00:00:01  dpid=0000000000000001  count=3/10
10:15:03 [INFO]  [BCAST] ALLOWED  src=00:00:00:00:00:01  dpid=0000000000000001  count=10/10
10:15:03 [WARNING] [BCAST] RATE LIMIT EXCEEDED – DROP rule installed
                   src=00:00:00:00:00:01  dpid=0000000000000001  count=11/10  blocked for 60s
─────────────────────────────────────────────────────────────
  BROADCAST CONTROL METRICS REPORT
─────────────────────────────────────────────────────────────
  Total broadcast pkts seen : 61
  Allowed broadcasts        : 10
  Blocked broadcasts        : 51  (83.6%)
  Total unicast pkts        : 28
  Active block rules        : 1
─────────────────────────────────────────────────────────────
```

---

## broadcast_log.csv (auto-generated)
```csv
timestamp,total_bcast,allowed_bcast,blocked_bcast,total_unicast,active_blocks
10:15:10,10,10,0,8,0
10:15:20,61,10,51,28,1
10:15:30,61,10,51,32,0
```

---

## Repository Structure
```
├── broadcast_controller.py   # Ryu controller: detect, limit, log broadcasts
├── topology.py               # Mininet topology + 3 automated test scenarios
├── broadcast_log.csv         # Auto-generated metrics log (runtime)
└── README.md                 # This file
```

---

## Validation Checklist

| Test | Command | Expected | Pass Condition |
|------|---------|----------|---------------|
| Connectivity | `pingall` | 0% loss | All hosts reachable |
| Allow normal | 5 broadcast pings | `ALLOWED` in controller log | Flood rules installed |
| Block storm | 50 rapid pings | DROP rule in flow table | `actions=` empty |
| Unicast unaffected | `h2 ping h1` | 0% loss | Unicast flows unblocked |
| Metrics log | Check CSV | New row every 10s | `blocked_bcast > 0` after storm |
| Block expiry | Wait 60s | DROP rule removed | `dump-flows` shows no rule |

---

## References
1. Mininet Overview – https://mininet.org/overview/
2. Ryu SDN Framework – https://ryu.readthedocs.io/
3. OpenFlow 1.3 Specification – https://opennetworking.org/
4. Broadcast Storm Control – IEEE 802.1D
5. Open vSwitch Docs – https://docs.openvswitch.org/
6. Mininet Walkthrough – https://mininet.org/walkthrough/
7. Ryu GitHub – https://github.com/faucetsdn/ryu

---

*Individual Project | PES University | Computer Networks UE24CS252B*
