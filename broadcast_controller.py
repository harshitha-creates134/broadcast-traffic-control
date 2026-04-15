"""
Broadcast Traffic Control – Ryu SDN Controller
===============================================
Project: Orange Level – SDN Mininet Simulation
Course:  Computer Networks – UE24CS252B
PES University

Description:
    This Ryu controller detects and controls excessive broadcast traffic by:

    1. DETECTION
       - Intercepts every packet_in event
       - Identifies broadcast frames (dst MAC == ff:ff:ff:ff:ff:ff)
       - Counts broadcast packets per source host (MAC address)
       - Maintains a sliding time-window counter per (dpid, src_mac)

    2. LIMITING FLOODING
       - Allows the first BROADCAST_THRESHOLD broadcasts per host per window
       - Once threshold is exceeded the controller installs a DROP rule for
         that (src_mac, broadcast_dst) match → no more flooding from that host
         for the duration of BLOCK_DURATION seconds

    3. SELECTIVE FORWARDING
       - For legitimate unicast traffic the controller acts as a learning switch
       - Installs match-action forwarding rules (in_port + eth_dst → out_port)
       - Unicast flows use idle_timeout=30 / hard_timeout=120

    4. EVALUATION METRICS
       - Every STATS_INTERVAL seconds the controller prints a report:
           * Total broadcast packets seen
           * Blocked broadcasts (dropped by installed rule)
           * Allowed broadcasts
           * Per-host broadcast rate
       - All metrics are also written to broadcast_log.csv

Flow Rule Summary
-----------------
Priority  Match                           Action          Timeout
0         (any)                           → Controller    permanent
5         eth_dst=ff:ff:ff:ff:ff:ff       → FLOOD         hard=FLOOD_HARD
           + eth_src=<offending MAC>       → DROP          hard=BLOCK_DURATION
1         in_port + eth_dst (unicast)     → out_port      idle=30, hard=120
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (CONFIG_DISPATCHER, MAIN_DISPATCHER,
                                     DEAD_DISPATCHER, set_ev_cls)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp
from ryu.lib import hub
import time
import logging

# ─────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)

# ─────────────────────────────────────────────────────
# Tunable Parameters
# ─────────────────────────────────────────────────────
BROADCAST_THRESHOLD = 10    # Max broadcasts allowed per host per window
COUNT_WINDOW        = 10    # Seconds: sliding window for counting
BLOCK_DURATION      = 60    # Seconds: how long to block an offending host
FLOOD_HARD_TIMEOUT  = 5     # Seconds: selective flood rule lifetime
STATS_INTERVAL      = 10    # Seconds: how often to print the metrics report


class BroadcastController(app_manager.RyuApp):
    """
    SDN controller that detects, limits, and logs broadcast traffic.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BroadcastController, self).__init__(*args, **kwargs)

        # MAC learning table   {dpid: {mac: port}}
        self.mac_to_port = {}

        # Broadcast counters   {(dpid, src_mac): [(timestamp), ...]}
        #   We store a list of timestamps; entries older than COUNT_WINDOW are pruned
        self.bcast_timestamps = {}

        # Blocked hosts        {(dpid, src_mac): block_until_timestamp}
        self.blocked_hosts = {}

        # Registered datapaths {dpid: datapath}
        self.datapaths = {}

        # Global counters (lifetime)
        self.total_bcast    = 0
        self.blocked_bcast  = 0
        self.allowed_bcast  = 0
        self.total_unicast  = 0

        # CSV log
        self.log_file = open("broadcast_log.csv", "w")
        self.log_file.write(
            "timestamp,total_bcast,allowed_bcast,blocked_bcast,"
            "total_unicast,active_blocks\n"
        )
        self.log_file.flush()

        # Background stats thread
        self.stats_thread = hub.spawn(self._stats_loop)

        self.logger.info("╔══════════════════════════════════════════════════╗")
        self.logger.info("║      Broadcast Traffic Control – Started         ║")
        self.logger.info("║  Threshold : %d bcast/host per %ds window         ║",
                         BROADCAST_THRESHOLD, COUNT_WINDOW)
        self.logger.info("║  Block time: %ds  │  Stats every: %ds             ║",
                         BLOCK_DURATION, STATS_INTERVAL)
        self.logger.info("╚══════════════════════════════════════════════════╝")

    # ─────────────────────────────────────────────────
    # Switch Handshake
    # ─────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Install table-miss flow on switch connect."""
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, priority=0, match=match, actions=actions)
        self.logger.info("[SW %016x] Connected – table-miss flow installed.", datapath.id)

    # ─────────────────────────────────────────────────
    # Datapath Registry
    # ─────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
            self.logger.info("[SW %016x] Registered.", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(dp.id, None)
            self.logger.info("[SW %016x] Disconnected.", dp.id)

    # ─────────────────────────────────────────────────
    # Packet-In Handler  (core logic)
    # ─────────────────────────────────────────────────
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        # ── MAC Learning ──
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # ── Broadcast path ──
        if dst == 'ff:ff:ff:ff:ff:ff':
            self._handle_broadcast(datapath, msg, in_port, src, pkt)
            return

        # ── Unicast path ──
        self.total_unicast += 1
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, priority=1, match=match, actions=actions,
                           idle_timeout=30, hard_timeout=120)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(datapath=datapath,
                                   buffer_id=msg.buffer_id,
                                   in_port=in_port,
                                   actions=actions,
                                   data=data)
        datapath.send_msg(out)

    # ─────────────────────────────────────────────────
    # Broadcast Handler
    # ─────────────────────────────────────────────────
    def _handle_broadcast(self, datapath, msg, in_port, src_mac, pkt):
        """
        Decide whether to allow or block this broadcast frame.

        Algorithm:
          1. Prune timestamps older than COUNT_WINDOW
          2. Count how many broadcasts this src sent in the window
          3. If count >= BROADCAST_THRESHOLD → install DROP rule, log block
          4. Else → install selective FLOOD rule, forward packet
        """
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
        dpid    = datapath.id
        now     = time.time()

        self.total_bcast += 1

        key = (dpid, src_mac)

        # Prune old timestamps
        self.bcast_timestamps.setdefault(key, [])
        self.bcast_timestamps[key] = [
            t for t in self.bcast_timestamps[key]
            if now - t < COUNT_WINDOW
        ]
        # Add current timestamp
        self.bcast_timestamps[key].append(now)
        count = len(self.bcast_timestamps[key])

        # Check if already blocked
        if key in self.blocked_hosts and now < self.blocked_hosts[key]:
            self.blocked_bcast += 1
            self.logger.warning(
                "[BCAST] BLOCKED  src=%s  dpid=%016x  count=%d",
                src_mac, dpid, count
            )
            # Drop silently – rule already installed
            return

        # Exceeded threshold → install DROP rule
        if count >= BROADCAST_THRESHOLD:
            self.blocked_bcast += 1
            self.blocked_hosts[key] = now + BLOCK_DURATION

            match = parser.OFPMatch(
                eth_src=src_mac,
                eth_dst='ff:ff:ff:ff:ff:ff'
            )
            # Priority 5, no actions = DROP
            self._add_flow(datapath, priority=5, match=match, actions=[],
                           hard_timeout=BLOCK_DURATION)

            self.logger.warning(
                "[BCAST] RATE LIMIT EXCEEDED – DROP rule installed  "
                "src=%s  dpid=%016x  count=%d/%d  blocked for %ds",
                src_mac, dpid, count, BROADCAST_THRESHOLD, BLOCK_DURATION
            )
            return

        # Under threshold → allow selective flood
        self.allowed_bcast += 1
        self.logger.info(
            "[BCAST] ALLOWED  src=%s  dpid=%016x  count=%d/%d",
            src_mac, dpid, count, BROADCAST_THRESHOLD
        )

        # Install a short-lived selective FLOOD rule (proactive for next packets)
        match = parser.OFPMatch(
            in_port=in_port,
            eth_src=src_mac,
            eth_dst='ff:ff:ff:ff:ff:ff'
        )
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._add_flow(datapath, priority=5, match=match, actions=actions,
                       hard_timeout=FLOOD_HARD_TIMEOUT)

        # Forward current packet
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out  = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    # ─────────────────────────────────────────────────
    # Helper: Add Flow Rule
    # ─────────────────────────────────────────────────
    def _add_flow(self, datapath, priority, match, actions,
                  idle_timeout=0, hard_timeout=0):
        """Install an OpenFlow flow rule."""
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod  = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(mod)

    # ─────────────────────────────────────────────────
    # Background Stats Loop
    # ─────────────────────────────────────────────────
    def _stats_loop(self):
        """Print metrics every STATS_INTERVAL seconds and append to CSV."""
        while True:
            hub.sleep(STATS_INTERVAL)
            now           = time.time()
            active_blocks = sum(
                1 for until in self.blocked_hosts.values() if now < until
            )
            pct_blocked = (
                (self.blocked_bcast / self.total_bcast * 100)
                if self.total_bcast else 0.0
            )

            self.logger.info("─" * 60)
            self.logger.info("  BROADCAST CONTROL METRICS REPORT")
            self.logger.info("─" * 60)
            self.logger.info("  Total broadcast pkts seen : %d", self.total_bcast)
            self.logger.info("  Allowed broadcasts        : %d", self.allowed_bcast)
            self.logger.info("  Blocked broadcasts        : %d  (%.1f%%)",
                             self.blocked_bcast, pct_blocked)
            self.logger.info("  Total unicast pkts        : %d", self.total_unicast)
            self.logger.info("  Active block rules        : %d", active_blocks)
            self.logger.info("─" * 60)

            # CSV
            self.log_file.write("%s,%d,%d,%d,%d,%d\n" % (
                time.strftime("%H:%M:%S"),
                self.total_bcast, self.allowed_bcast,
                self.blocked_bcast, self.total_unicast, active_blocks
            ))
            self.log_file.flush()

    def close(self):
        self.log_file.close()
        self.logger.info("Controller stopped. Log saved to broadcast_log.csv")
