import dns.resolver
import dns.query
import dns.message
import dns.rcode
import dns.exception
import time

class DNSEngine:
    def __init__(self, timeout=2.0):
        self.timeout = timeout

    def query(self, server, domain, record_type="A"):
        """Perform a DNS query against a specific server."""
        try:
            query = dns.message.make_query(domain, record_type)
            start_time = time.time()
            response = dns.query.udp(query, server, timeout=self.timeout)
            end_time = time.time()
            
            latency = (end_time - start_time) * 1000 # ms
            status = dns.rcode.to_text(response.rcode())
            
            answers = []
            if response.answer:
                for rrset in response.answer:
                    for rr in rrset:
                        answers.append(rr.to_text())
            
            return {
                "status": status,
                "latency": latency,
                "answers": sorted(answers),
                "full_response": response.to_text()
            }
        except dns.exception.Timeout:
            return {"status": "TIMEOUT", "latency": self.timeout * 1000, "answers": []}
        except Exception as e:
            return {"status": f"ERROR: {str(e)}", "latency": 0, "answers": []}

    def check_dnssec(self, server, domain):
        """Check if a domain is DNSSEC signed on a server."""
        try:
            query = dns.message.make_query(domain, "SOA", want_dnssec=True)
            response = dns.query.udp(query, server, timeout=self.timeout)
            
            for rrset in response.answer:
                if rrset.rdtype == dns.rdatatype.RRSIG:
                    return True
            return False
        except:
            return False

    def check_recursion(self, server):
        """Check if recursion is available on the server."""
        try:
            query = dns.message.make_query("google.com", "A")
            response = dns.query.udp(query, server, timeout=self.timeout)
            return bool(response.flags & dns.flags.RA)
        except:
            return False

    def query_version(self, server):
        """Query the BIND version (version.bind CH TXT)."""
        try:
            query = dns.message.make_query("version.bind", "TXT", rdclass=dns.rclass.CH)
            response = dns.query.udp(query, server, timeout=self.timeout)
            if response.answer:
                return response.answer[0][0].to_text().strip('"')
            return "UNKNOWN/HIDDEN"
        except:
            return "ERROR/TIMEOUT"

    def check_dot(self, server):
        """Check if server supports DNS over TLS (DoT) on port 853."""
        try:
            query = dns.message.make_query("google.com", "A")
            # This is a basic handshake check
            dns.query.tls(query, server, timeout=self.timeout)
            return True
        except:
            return False

    def check_doh(self, server):
        """Check if server supports DNS over HTTPS (DoH) via RFC8484."""
        import requests
        import base64
        try:
            # Query for google.com A record in wire format
            query = dns.message.make_query("google.com", "A")
            wire_query = query.to_wire()
            url = f"https://{server}/dns-query"
            
            headers = {
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message"
            }
            
            response = requests.post(url, data=wire_query, headers=headers, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                # Verify it's a valid DNS message
                dns.message.from_wire(response.content)
                return True
            return False
        except:
            return False
