import socket
import subprocess
import platform
import time
from icmplib import ping as icmp_ping

class Connectivity:
    def __init__(self, timeout=2.0):
        self.timeout = timeout

    def check_port(self, host, port):
        """Check if a TCP port is open."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, socket.error):
            return False

    def ping(self, host, count=3):
        """Cross-platform ping using icmplib (best) or system ping (fallback)."""
        try:
            # icmplib provides a clean pythonic way
            result = icmp_ping(host, count=count, timeout=self.timeout)
            return {
                "avg_rtt": result.avg_rtt,
                "min_rtt": result.min_rtt,
                "max_rtt": result.max_rtt,
                "packet_loss": result.packet_loss,
                "is_alive": result.is_alive
            }
        except Exception as e:
            # Fallback to system ping if icmplib fails (e.g. permission issues on linux)
            return self._system_ping(host, count)

    def _system_ping(self, host, count):
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, str(count), host]
        
        try:
            start_time = time.time()
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            end_time = time.time()
            
            # Simple heuristic for success
            is_alive = "ttl=" in output.lower() or "time=" in output.lower()
            return {
                "avg_rtt": (end_time - start_time) * 1000 / count if is_alive else 0,
                "is_alive": is_alive,
                "fallback": True
            }
        except:
            return {"is_alive": False, "fallback": True}

    def traceroute(self, host, max_hops=30):
        """Simple traceroute implementation (or system call)."""
        # Traceroute is complex to implement purely in Python without raw sockets (permissions)
        # So we'll wrap the system tool
        cmd = ["tracert", "-d", "-h", str(max_hops), host] if platform.system().lower() == 'windows' else ["traceroute", "-n", "-m", str(max_hops), host]
        
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, universal_newlines=True)
            return output
        except:
            return "Traceroute failed"
