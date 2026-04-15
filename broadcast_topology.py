#!/usr/bin/env python3
"""
Broadcast Traffic Control – Mininet Topology & Test Script
===========================================================
Project: Orange Level – SDN Mininet Simulation
Course:  Computer Networks – UE24CS252B
PES University

Topology (used for all scenarios):

         h1          h2
          \          /
           s1 ─── s2
          /          \
         h3          h4

  • 4 hosts across 2 switches (linear inter-switch link)
  • All hosts in the same subnet: 10.0.1.x/24
  • Link bandwidth: configurable via --bw (default 10 Mbps)

Test Scenarios
--------------
Scenario 1 – Normal Broadcast (ARP simulation)
    Each host sends a small burst of broadcast pings (arping).
    Expected: broadcasts flood normally, controller ALLOWS them.

Scenario 2 – Excessive Broadcast Storm
    One host (h1) fires a rapid stream of broadcast pings far exceeding
    the controller threshold.
    Expected: controller detects storm, installs DROP rule, broadcasts stop.

Scenario 3 – Post-Control Evaluation
    After the block period, verify h1 can broadcast again (rule expired)
    while h2–h4 unicast continues unaffected.

Usage:
    # Terminal 1: start controller
    ryu-manager broadcast_controller.py --observe-links

    # Terminal 2: run this script
    sudo python3 topology.py [--bw 10] [--scenario all|1|2|3]
"""

import sys
import argparse
import time
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.log import setLogLevel, info, warn
from mininet.cli import CLI


# ─────────────────────────────────────────────────────
# Topology Definition
# ─────────────────────────────────────────────────────

class BroadcastTopo(Topo):
    """
    Two-switch topology with 4 hosts.

         h1 ─── s1 ─── s2 ─── h2
                 |              |
                h3             h4

    This topology is ideal for broadcast control because:
      - Broadcasts must cross the inter-switch link to reach all hosts
      - It creates a measurable "broadcast domain" to evaluate control
      - The inter-switch link is a natural choke point for monitoring
    """
    def build(self, bw=10):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        h1 = self.addHost('h1', ip='10.0.1.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.1.2/24', mac='00:00:00:00:00:02')
        h3 = self.addHost('h3', ip='10.0.1.3/24', mac='00:00:00:00:00:03')
        h4 = self.addHost('h4', ip='10.0.1.4/24', mac='00:00:00:00:00:04')

        # Host-to-switch links
        self.addLink(h1, s1, bw=bw, delay='2ms')
        self.addLink(h3, s1, bw=bw, delay='2ms')
        # Inter-switch link
        self.addLink(s1, s2, bw=bw, delay='1ms')
        # Switch-to-host links
        self.addLink(h2, s2, bw=bw, delay='2ms')
        self.addLink(h4, s2, bw=bw, delay='2ms')


# ─────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────

def show_flow_tables(net):
    info("\n╔══════════════════════════════════════╗\n")
    info("║        FLOW TABLE DUMP               ║\n")
    info("╚══════════════════════════════════════╝\n")
    for sw in net.switches:
        info(f"\n── Switch: {sw.name} ──\n")
        info(sw.cmd(f'ovs-ofctl dump-flows {sw.name}') + "\n")


def sep(label=""):
    info(f"\n{'─'*58}\n")
    if label:
        info(f"  {label}\n")
        info(f"{'─'*58}\n")


# ─────────────────────────────────────────────────────
# Scenario 1 – Normal Broadcast (below threshold)
# ─────────────────────────────────────────────────────

def scenario1_normal_broadcast(net):
    """
    Each host sends 5 broadcast pings → well below the threshold (10).
    Expected: controller allows all; flow table shows selective FLOOD rules.
    """
    sep("SCENARIO 1 – Normal Broadcast (below threshold)")
    info("  Each host sends 5 broadcast pings. Threshold = 10.\n")
    info("  Expected: ALL broadcasts ALLOWED by controller.\n\n")

    for hname in ['h1', 'h2', 'h3', 'h4']:
        h = net.get(hname)
        info(f"  [{hname}] Sending 5 broadcast pings...\n")
        # ping the broadcast address
        result = h.cmd('ping -b -c 5 -i 0.2 10.0.1.255 2>&1')
        info(result + "\n")
        time.sleep(1)

    info("\n  [INFO] Flow table after normal broadcast:\n")
    show_flow_tables(net)


# ─────────────────────────────────────────────────────
# Scenario 2 – Broadcast Storm (exceeds threshold)
# ─────────────────────────────────────────────────────

def scenario2_broadcast_storm(net):
    """
    h1 sends a rapid burst of 50 broadcast pings in quick succession.
    Expected:
      - First 10 are ALLOWED (threshold)
      - Controller installs DROP rule on the switch
      - Remaining broadcasts are silently dropped at the switch (no packet_in)
    """
    sep("SCENARIO 2 – Broadcast Storm from h1")
    info("  h1 sends 50 rapid broadcast pings (10 allowed, 40 blocked).\n")
    info("  Expected: controller installs DROP rule after threshold.\n\n")

    h1 = net.get('h1')

    # Rapid broadcast storm
    info("  [h1] Launching broadcast storm (50 pings @ 0.05s interval)...\n")
    result = h1.cmd('ping -b -c 50 -i 0.05 10.0.1.255 2>&1')
    info(result + "\n")
    time.sleep(2)

    info("\n  [INFO] Flow table AFTER storm – look for DROP rule (no actions):\n")
    show_flow_tables(net)

    # Verify unicast still works (broadcast control should not affect unicast)
    sep("SCENARIO 2b – Verify unicast unaffected after broadcast block")
    h2 = net.get('h2')
    info("  [h2 → h1] Unicast ping test (must succeed despite h1 being broadcast-blocked):\n")
    result = h2.cmd('ping -c 4 10.0.1.1')
    info(result + "\n")


# ─────────────────────────────────────────────────────
# Scenario 3 – Post-Control Evaluation
# ─────────────────────────────────────────────────────

def scenario3_post_control(net):
    """
    Compare broadcast packet counts with and without the controller's control.
    Uses tcpdump to count packets captured on h2 during a broadcast burst from h3.

    Also measures the improvement: how many packets reach h2 vs. without control.
    """
    sep("SCENARIO 3 – Post-Control Evaluation (before vs. after)")
    h2 = net.get('h2')
    h3 = net.get('h3')

    # Phase A: Measure BEFORE control kicks in (first 8 pings, under threshold)
    info("  [Phase A] h3 sends 8 broadcast pings (below threshold = allowed).\n")
    info("  Counting packets received at h2 using tcpdump...\n")

    h2.cmd('tcpdump -i h2-eth0 broadcast -c 100 -w /tmp/phase_a.pcap &')
    time.sleep(0.5)
    h3.cmd('ping -b -c 8 -i 0.2 10.0.1.255 2>&1')
    time.sleep(2)
    h2.cmd('pkill tcpdump 2>/dev/null')
    count_a = h2.cmd("tcpdump -r /tmp/phase_a.pcap 2>/dev/null | wc -l").strip()
    info(f"  [Phase A] Broadcast packets received at h2: {count_a}\n")

    time.sleep(1)

    # Phase B: Flood beyond threshold → trigger block
    info("\n  [Phase B] h3 sends 30 rapid broadcasts (exceeds threshold → block).\n")
    h2.cmd('tcpdump -i h2-eth0 broadcast -c 100 -w /tmp/phase_b.pcap &')
    time.sleep(0.5)
    h3.cmd('ping -b -c 30 -i 0.05 10.0.1.255 2>&1')
    time.sleep(2)
    h2.cmd('pkill tcpdump 2>/dev/null')
    count_b = h2.cmd("tcpdump -r /tmp/phase_b.pcap 2>/dev/null | wc -l").strip()
    info(f"  [Phase B] Broadcast packets received at h2: {count_b}\n")

    # Evaluation summary
    sep("EVALUATION SUMMARY")
    try:
        ca = int(count_a)
        cb = int(count_b)
        total_sent_b = 30
        blocked = max(0, total_sent_b - cb)
        pct_reduction = (blocked / total_sent_b * 100) if total_sent_b else 0
        info(f"  Broadcasts sent (Phase A):          8  → received at h2: {ca}\n")
        info(f"  Broadcasts sent (Phase B storm):    30 → received at h2: {cb}\n")
        info(f"  Estimated blocked by controller:    {blocked}\n")
        info(f"  Broadcast reduction:                {pct_reduction:.1f}%%\n")
    except ValueError:
        info("  (Could not parse tcpdump counts – check manually)\n")

    # Final flow table
    show_flow_tables(net)


# ─────────────────────────────────────────────────────
# Main Runner
# ─────────────────────────────────────────────────────

def run(bw=10, scenario='all', controller_ip='127.0.0.1', controller_port=6633):
    setLogLevel('info')

    info("\n" + "═"*58 + "\n")
    info("  BROADCAST TRAFFIC CONTROL – MININET SIMULATION\n")
    info("  Topology: 2-switch, 4-host (h1-h4)\n")
    info("  Link BW: %d Mbps\n" % bw)
    info("═"*58 + "\n\n")

    topo = BroadcastTopo(bw=bw)
    net  = Mininet(
        topo=topo,
        switch=OVSKernelSwitch,
        controller=None,
        link=TCLink,
        autoSetMacs=False
    )
    net.addController('c0',
                      controller=RemoteController,
                      ip=controller_ip,
                      port=controller_port)
    net.start()

    info("[INFO] Waiting for controller connection...\n")
    time.sleep(3)

    # Enable broadcast forwarding on hosts (needed for ping -b)
    for h in net.hosts:
        h.cmd('sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=0 2>/dev/null')

    # Initial connectivity test
    sep("Initial Connectivity (pingall)")
    net.pingAll()
    time.sleep(1)

    # Run selected scenarios
    if scenario in ('all', '1'):
        scenario1_normal_broadcast(net)
    if scenario in ('all', '2'):
        scenario2_broadcast_storm(net)
    if scenario in ('all', '3'):
        scenario3_post_control(net)

    info("\n[INFO] Automated tests complete. Opening Mininet CLI.\n")
    info("[INFO] Useful commands:\n")
    info("         h1 ping -b -c 20 -i 0.05 10.0.1.255   (trigger storm)\n")
    info("         sh ovs-ofctl dump-flows s1             (view flow table)\n")
    info("         h2 ping -c 4 10.0.1.1                 (test unicast)\n\n")
    CLI(net)
    net.stop()
    info("[INFO] Network stopped.\n")


# ─────────────────────────────────────────────────────
# Entry Point
# ─────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description='Broadcast Traffic Control – Mininet')
    p.add_argument('--bw',       type=int, default=10,
                   help='Link bandwidth in Mbps (default: 10)')
    p.add_argument('--scenario', choices=['all', '1', '2', '3'], default='all',
                   help='Test scenario to run (default: all)')
    p.add_argument('--controller-ip',   default='127.0.0.1')
    p.add_argument('--controller-port', type=int, default=6633)
    return p.parse_args()


if __name__ == '__main__':
    args = parse_args()
    run(bw=args.bw, scenario=args.scenario,
        controller_ip=args.controller_ip,
        controller_port=args.controller_port)
