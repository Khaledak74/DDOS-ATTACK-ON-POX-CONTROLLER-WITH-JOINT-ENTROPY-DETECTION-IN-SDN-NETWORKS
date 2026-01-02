from pox.core import core
import pox.openflow.libopenflow_01 as of
import math
from collections import defaultdict
from pox.lib.recoco import Timer

log = core.getLogger()

class JointEntropyDDOSDetection:
    def __init__(self, interval=5):
        """
        Initializes joint entropy-based DDoS detection.
        """
        self.src_ip_counts = defaultdict(int)  # Track occurrences of src_ip
        self.dst_ip_counts = defaultdict(int)  # Track occurrences of dst_ip
        self.ip_pair_counts = defaultdict(int) # Track (src_ip, dst_ip) occurrences
        self.total_packets = 0  # Total packets processed
        self.entropy_threshold = 6.5  # Adjust based on attack behavior

        # Start periodic entropy calculations
        Timer(interval, self._calculate_entropy, recurring=True)
        core.openflow.addListeners(self)

    def _handle_packet_in(self, event):
        """
        Handles incoming packets, updating distributions of src_ip, dst_ip, and (src_ip, dst_ip).
        """
        packet = event.parsed
        if not packet:
            return

        ip = packet.find('ipv4')
        if ip:
            src_ip = str(ip.srcip)
            dst_ip = str(ip.dstip)

            # Update counts
            self.src_ip_counts[src_ip] += 1
            self.dst_ip_counts[dst_ip] += 1
            self.ip_pair_counts[(src_ip, dst_ip)] += 1
            self.total_packets += 1

    def _calculate_entropy(self):
        """
        Computes and logs Shannon entropy for source IPs, destination IPs, and Joint Entropy.
        """
        if self.total_packets == 0:  # Avoid division by zero
            log.info("No packets received, entropy remains 0.0")
            return

        # Compute entropies
        src_entropy = self._calculate_shannon_entropy(self.src_ip_counts)
        dst_entropy = self._calculate_shannon_entropy(self.dst_ip_counts)
        joint_entropy = self._calculate_shannon_entropy(self.ip_pair_counts)

        log.info("Source IP Entropy: {:.4f} | Destination IP Entropy: {:.4f} | Joint Entropy: {:.4f}".format(
            src_entropy, dst_entropy, joint_entropy))

        # DDoS Detection Condition
        if joint_entropy > self.entropy_threshold:
            log.warning("DDoS Alert! High Joint Entropy: {:.4f}".format(joint_entropy))
        else:
            log.info("Normal Traffic: Joint Entropy is {:.4f}".format(joint_entropy))

        # Reset counts for next period
        self.src_ip_counts.clear()
        self.dst_ip_counts.clear()
        self.ip_pair_counts.clear()
        self.total_packets = 0

    def _calculate_shannon_entropy(self, counts):
        """
        Computes Shannon entropy given a dictionary of counts.
        """
        total = sum(counts.values())

        if total == 0:  # No packets received, return entropy 0
            return 0

        entropy = -sum((count / float(total)) * math.log(count / float(total), 2)
                       for count in counts.values() if count > 0)

        return entropy

def launch():
    """
    Entry point for POX module.
    """
    log.info("Starting Joint Entropy-Based DDoS Detection...")
    instance = JointEntropyDDOSDetection()
    core.openflow.addListenerByName("PacketIn", instance._handle_packet_in)

