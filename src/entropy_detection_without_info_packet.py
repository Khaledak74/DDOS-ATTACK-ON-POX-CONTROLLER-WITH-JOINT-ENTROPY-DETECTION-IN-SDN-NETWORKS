from pox.core import core
import pox.openflow.libopenflow_01 as of
import math
from collections import defaultdict
from pox.lib.recoco import Timer

log = core.getLogger()

class JointEntropyDDOSMitigation:
    def __init__(self, interval=5):
        self.ip_pair_counts = defaultdict(int)  # Track (src_ip, dst_ip) occurrences
        self.total_packets = 0  # Total packets processed
        self.entropy_threshold = 6.5  # Adjust based on attack behavior

        # Start periodic entropy checks
        Timer(interval, self._calculate_entropy, recurring=True)
        core.openflow.addListeners(self)

    def _handle_packet_in(self, event):
        """
        Handles incoming packets, updating (src_ip, dst_ip) distributions.
        """
        packet = event.parsed
        if not packet:
            return

        ip = packet.find('ipv4')
        if ip:
            self.ip_pair_counts[(ip.srcip, ip.dstip)] += 1
            self.total_packets += 1

    def _calculate_entropy(self):
        """
        Computes and logs joint entropy.
        """
        if self.total_packets == 0:  # Avoid division by zero
            log.info("No packets received, entropy remains 0.0")
            return

        # Calculate joint entropy
        joint_entropy = 0
        for count in self.ip_pair_counts.values():
            probability = count / float(self.total_packets)
            if probability > 0:  # Prevent log(0) error
                joint_entropy -= probability * math.log(probability, 2)

        log.info("Joint Entropy: {:.4f}".format(joint_entropy))

        # DDoS Detection Condition
        if joint_entropy > self.entropy_threshold:
            log.warning("DDoS Alert! High Joint Entropy: {:.4f}".format(joint_entropy))
        else:
            log.info("Normal Traffic: Joint Entropy is {:.4f}".format(joint_entropy))

        # Reset counts for next period
        self.ip_pair_counts.clear()
        self.total_packets = 0

def launch():
    """
    Entry point for POX module.
    """
    log.info("Starting Joint Entropy-Based DDoS Detection...")
    instance = JointEntropyDDOSMitigation()
    core.openflow.addListenerByName("PacketIn", instance._handle_packet_in)

