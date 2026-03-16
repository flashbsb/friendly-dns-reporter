import dns.resolver
import dns.query
import dns.message
import dns.rcode
import dns.exception
import dns.flags
import dns.zone
import dns.edns
import time
import socket

class DNSEngine:
    def __init__(self, timeout=2.0, tries=1):
        self.timeout = timeout
        self.tries = tries

    def query(self, server, domain, record_type="A", rd=True, cd=False, use_edns=False):
        """Perform a DNS query with sophisticated options."""
        last_exception = None
        for attempt in range(self.tries):
            try:
                # Prepare message
                query = dns.message.make_query(domain, record_type)
                query_size = len(query.to_wire())
                
                # Recursion Desired (RD) - default True
                if not rd: query.flags &= ~dns.flags.RD
                
                # Checking Disabled (CD) - default False
                if cd: query.flags |= dns.flags.CD
                
                # EDNS0 Options (+bufsize=1232 +nsid)
                if use_edns:
                    # NSID is Option 3
                    options = [dns.edns.GenericOption(3, b'')] 
                    query.use_edns(edns=0, payload=1232, options=options)

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

                # Also capture authority section (important for SOA/referrals)
                authority = []
                if response.authority:
                    for rrset in response.authority:
                        for rr in rrset:
                            authority.append(rr.to_text())
                
                # Extract NSID if present
                nsid = None
                if response.edns == 0:
                    for opt in response.options:
                        if opt.otype == 3:
                            if hasattr(opt, 'nsid'):
                                nsid = opt.nsid.decode('utf-8', errors='ignore')
                            elif hasattr(opt, 'data'):
                                nsid = opt.data.decode('utf-8', errors='ignore')
                            else:
                                nsid = str(opt)

                # Extract TTL from answer
                ttl = 0
                if response.answer:
                    ttl = response.answer[0].ttl

                return {
                    "status": status,
                    "latency": latency,
                    "protocol": "udp",
                    "query_size": query_size,
                    "response_size": len(response.to_wire()),
                    "flags": dns.flags.to_text(response.flags).split(),
                    "aa": bool(response.flags & dns.flags.AA),
                    "tc": bool(response.flags & dns.flags.TC), # Truncated
                    "answer_count": sum(len(rrset) for rrset in response.answer) if response.answer else 0,
                    "authority_count": sum(len(rrset) for rrset in response.authority) if response.authority else 0,
                    "answers": answers,
                    "authority": authority,
                    "nsid": nsid,
                    "ttl": ttl,
                    "full_response": response.to_text()
                }
            except dns.exception.Timeout as e:
                last_exception = e
                continue # Retry
            except Exception as e:
                return {"status": f"ERROR: {str(e)}", "latency": None, "answers": [], "authority": [], "protocol": "udp"}
        
        return {"status": "TIMEOUT", "latency": self.timeout * 1000, "answers": [], "authority": [], "protocol": "udp"}

    def _response_meta(self, response, protocol="udp", extra=None):
        meta = {
            "protocol": protocol,
            "rcode": dns.rcode.to_text(response.rcode()),
            "flags": dns.flags.to_text(response.flags).split(),
            "response_size": len(response.to_wire()) if response else None,
            "authority_count": sum(len(rrset) for rrset in response.authority) if response and response.authority else 0,
            "answer_count": sum(len(rrset) for rrset in response.answer) if response and response.answer else 0,
            "aa": bool(response.flags & dns.flags.AA) if response else None,
            "tc": bool(response.flags & dns.flags.TC) if response else None,
        }
        if extra:
            meta.update(extra)
        return meta

    def check_axfr(self, server, zone):
        """Check if Zone Transfer (AXFR) is allowed."""
        start = time.time()
        try:
            # AXFR usually requires TCP
            z = dns.zone.from_xfr(dns.query.xfr(server, zone, timeout=self.timeout))
            latency = (time.time() - start) * 1000
            return True, f"VULNERABLE: {len(z.nodes)} nodes leaked", latency
        except dns.exception.Timeout:
            return False, "TIMEOUT", self.timeout * 1000
        except Exception as e:
            return False, str(e), None

    def check_dnssec(self, server):
        """Check whether a server returns DNSSEC data. This is not a validation test."""
        start = time.time()
        try:
            # We query the root zone (.) to be independent of user domains
            query = dns.message.make_query(".", "DNSKEY", want_dnssec=True)
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            has_dnskey = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer)
            has_rrsig = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer)
            if has_dnskey and has_rrsig:
                return True, latency, self._response_meta(response, extra={"query_type": "DNSKEY", "want_dnssec": True, "query_size": query_size})
            return False, latency, self._response_meta(response, extra={"query_type": "DNSKEY", "want_dnssec": True, "query_size": query_size})
        except dns.exception.Timeout:
            return None, self.timeout * 1000, {"protocol": "udp", "failure_reason": "timeout"}
        except:
            return False, None, {"protocol": "udp", "failure_reason": "error"}

    def check_open_resolver(self, server):
        """Check if server appears to provide public recursion using third-party recursion."""
        start = time.time()
        try:
            # A public recursion test must request recursion.
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000

            rcode = response.rcode()
            recursion_available = bool(response.flags & dns.flags.RA)

            if recursion_available and rcode in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                return "OPEN", latency, self._response_meta(response, extra={"ra": recursion_available, "query_size": query_size})

            if rcode == dns.rcode.REFUSED:
                return "REFUSED", latency, self._response_meta(response, extra={"ra": recursion_available, "query_size": query_size})

            if not recursion_available:
                return "NO_RECURSION", latency, self._response_meta(response, extra={"ra": recursion_available, "query_size": query_size})

            if rcode == dns.rcode.SERVFAIL:
                return "SERVFAIL", latency, self._response_meta(response, extra={"ra": recursion_available, "query_size": query_size})

            return dns.rcode.to_text(rcode), latency, self._response_meta(response, extra={"ra": recursion_available, "query_size": query_size})
                
        except dns.exception.Timeout:
            return "TIMEOUT", self.timeout * 1000, {"protocol": "udp", "failure_reason": "timeout"}
        except:
            return "ERROR", None, {"protocol": "udp", "failure_reason": "error"}

    def check_edns0(self, server):
        """Check if server supports EDNS0 and large UDP payloads. Returns (True/False/None, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            # Request a 4096 buffer size
            query.use_edns(edns=0, payload=4096)
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            # Check if response retains EDNS0
            if response.edns == 0:
                return True, latency, self._response_meta(response, extra={"edns": response.edns, "payload": 4096, "query_size": query_size})
            return False, latency, self._response_meta(response, extra={"edns": response.edns, "payload": 4096, "query_size": query_size})
        except dns.exception.Timeout:
            return None, self.timeout * 1000, {"protocol": "udp", "failure_reason": "timeout"}
        except:
            return False, None, {"protocol": "udp", "failure_reason": "error"}

    def check_recursion(self, server):
        """Check if recursion is available. Returns (True/False/None, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            recursion_available = bool(response.flags & dns.flags.RA)
            return recursion_available, latency, self._response_meta(response, extra={"ra": recursion_available, "query_size": query_size})
        except dns.exception.Timeout:
            return None, self.timeout * 1000, {"protocol": "udp", "failure_reason": "timeout"}
        except:
            return False, None, {"protocol": "udp", "failure_reason": "error"}

    def query_version(self, server):
        """Query the BIND version. Returns (string/HIDDEN/None, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("version.bind", "TXT", rdclass=dns.rclass.CH)
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            if response.answer:
                return response.answer[0][0].to_text().strip('"'), latency, self._response_meta(response, extra={"query_class": "CH", "query_name": "version.bind", "query_size": query_size})
            return "HIDDEN", latency, self._response_meta(response, extra={"query_class": "CH", "query_name": "version.bind", "query_size": query_size})
        except dns.exception.Timeout:
            return None, self.timeout * 1000, {"protocol": "udp", "failure_reason": "timeout", "query_class": "CH"}
        except:
            return "HIDDEN", None, {"protocol": "udp", "failure_reason": "error", "query_class": "CH"}

    def check_dot(self, server):
        """Check if server supports DoT. Returns (StatusString, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.tls(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return "OK", latency, self._response_meta(response, protocol="tls", extra={"port": 853, "query_size": query_size})
        except dns.exception.Timeout:
            return "TIMEOUT", self.timeout * 1000, {"protocol": "tls", "port": 853, "failure_reason": "timeout"}
        except:
            return "FAIL", None, {"protocol": "tls", "port": 853, "failure_reason": "error"}

    def check_doh(self, server):
        """Check if server supports DoH. Returns (StatusString, latency)."""
        import requests
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            wire_query = query.to_wire()
            url = f"https://{server}/dns-query"
            headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
            
            response = requests.post(url, data=wire_query, headers=headers, timeout=self.timeout, verify=False)
            latency = (time.time() - start) * 1000
            if response.status_code == 200:
                try:
                    dns_response = dns.message.from_wire(response.content)
                    meta = self._response_meta(dns_response, protocol="https", extra={"port": 443, "http_status": response.status_code, "query_size": len(wire_query)})
                except Exception:
                    meta = {"protocol": "https", "port": 443, "http_status": response.status_code, "response_size": len(response.content), "query_size": len(wire_query)}
                return "OK", latency, meta
            return "FAIL", latency, {"protocol": "https", "port": 443, "http_status": response.status_code, "response_size": len(response.content), "query_size": len(wire_query)}
        except requests.exceptions.Timeout:
            return "TIMEOUT", self.timeout * 1000, {"protocol": "https", "port": 443, "failure_reason": "timeout"}
        except:
            return "FAIL", None, {"protocol": "https", "port": 443, "failure_reason": "error"}

    def check_tcp(self, server):
        """Perform a real DNS query over TCP. Returns (StatusString, latency)."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.tcp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return "OK", latency, self._response_meta(response, protocol="tcp", extra={"port": 53, "query_size": query_size})
        except dns.exception.Timeout:
            return "TIMEOUT", self.timeout * 1000, {"protocol": "tcp", "port": 53, "failure_reason": "timeout"}
        except:
            return "FAIL", None, {"protocol": "tcp", "port": 53, "failure_reason": "error"}

    def check_udp(self, server):
        """Perform a direct DNS query over UDP to measure DNS service responsiveness."""
        start = time.time()
        try:
            query = dns.message.make_query("google.com", "A")
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            return "OK", latency, self._response_meta(response, protocol="udp", extra={"port": 53, "query_size": query_size})
        except dns.exception.Timeout:
            return "TIMEOUT", self.timeout * 1000, {"protocol": "udp", "port": 53, "failure_reason": "timeout"}
        except:
            return "FAIL", None, {"protocol": "udp", "port": 53, "failure_reason": "error"}

    def check_zone_dnssec(self, server, domain):
        """Verify if a specific zone is signed (contains DNSKEY and RRSIG)."""
        start = time.time()
        try:
            query = dns.message.make_query(domain, "DNSKEY", want_dnssec=True)
            query_size = len(query.to_wire())
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            has_dnskey = any(rrset.rdtype == dns.rdatatype.DNSKEY for rrset in response.answer)
            has_rrsig = any(rrset.rdtype == dns.rdatatype.RRSIG for rrset in response.answer)
            
            return has_dnskey and has_rrsig, latency, self._response_meta(response, extra={"query_type": "DNSKEY", "want_dnssec": True, "query_size": query_size})
        except dns.exception.Timeout:
            return None, self.timeout * 1000, {"protocol": "udp", "failure_reason": "timeout"}
        except:
            return False, None, {"protocol": "udp", "failure_reason": "error"}

    def analyze_soa_timers(self, refresh, retry, expire, minimum):
        """Validate SOA timers against RFC 1912 best practices."""
        # RFC 1912 / Common Best Practices:
        # Refresh: 20 min to 12 hours (1200 - 43200)
        # Retry: 2 min to 2 hours (120 - 7200)
        # Expire: 2 to 4 weeks (1209600 - 2419200)
        # Min TTL: 3 min to 1 day (180 - 86400)
        
        issues = []
        if not (1200 <= refresh <= 43200): issues.append(f"Refresh({refresh}) out of RFC range")
        if not (120 <= retry <= 7200): issues.append(f"Retry({retry}) out of RFC range")
        if retry >= refresh: issues.append("Retry >= Refresh")
        if not (1209600 <= expire <= 2419200): issues.append(f"Expire({expire}) out of RFC range")
        if not (180 <= minimum <= 86400): issues.append(f"MinTTL({minimum}) out of RFC range")
        
        return len(issues) == 0, issues

    def check_web_risk(self, server):
        """Check if ports 80 or 443 are open on the DNS server (Web Exposure Risk)."""
        risks = []
        timings = {}
        for port in [80, 443]:
            start = time.time()
            try:
                with socket.create_connection((server, port), timeout=1.0):
                    risks.append(port)
                    timings[port] = (time.time() - start) * 1000
            except:
                timings[port] = None
                continue
        return risks, timings

    def resolve_chain(self, server, target, rtype, rd=True):
        """Verify if a CNAME or MX target actually resolves to an IP (Dangling DNS check)."""
        try:
            # Check for both IPv4 and IPv6 resolution
            has_ip = False
            latencies = []
            for family in ["A", "AAAA"]:
                res = self.query(server, target, family, rd=rd)
                if res.get("latency"):
                    latencies.append(res["latency"])
                if res['status'] == "NOERROR" and res['answers']:
                    has_ip = True
                    break
                if res['status'] == "NXDOMAIN":
                    return False, "NXDOMAIN (Dangling!)", (sum(latencies) / len(latencies)) if latencies else None
            
            if has_ip:
                return True, "RESOLVES", (sum(latencies) / len(latencies)) if latencies else None
            return False, "NO ADDRESS RECORDS FOUND", (sum(latencies) / len(latencies)) if latencies else None
        except:
            return False, "ERROR", None

    def check_port_25(self, server):
        """Check if SMTP port 25 is open on a target (MX Reachability)."""
        start = time.time()
        try:
            with socket.create_connection((server, 25), timeout=2.0):
                latency = (time.time() - start) * 1000
                return True, latency
        except:
            return False, None

    def detect_wildcard(self, server, domain, rd=True):
        """Check if zone has a wildcard entry by querying a random sub-subdomain."""
        import random
        import string
        rand_prefix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
        test_domain = f"{rand_prefix}.{domain}"
        try:
            res = self.query(server, test_domain, "A", rd=rd)
            if res['status'] == "NOERROR" and res['answers']:
                return True, res['answers'], res.get("latency")
            return False, None, res.get("latency")
        except:
            return False, None, None

    def check_ecs_support(self, server):
        """Check if server respects/handles EDNS Client Subnet (ECS)."""
        # ECS is Option 8. We send a dummy subnet (1.2.3.0/24)
        # Note: Many servers don't reflect ECS back unless they have a reason, 
        # but we check if the response contains the option or if it's handled.
        start = time.time()
        try:
            from dns.edns import GenericOption
            # Option 8: Family 1 (IPv4), Source 24, Scope 0, Address 1.2.3.0
            ecs_data = b'\x00\x01\x18\x00\x01\x02\x03' 
            options = [GenericOption(8, ecs_data)]
            query = dns.message.make_query("google.com", "A")
            query.use_edns(edns=0, payload=1232, options=options)
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            # If server returns ECS option, it's a strong SIGN of support
            for opt in response.options:
                if opt.otype == 8: return True, latency
            return False, latency
        except:
            return False, None

    def check_qname_minimization(self, server, rd=True):
        """Heuristic check for QNAME minimization via qnamemintest.internet.nl."""
        try:
            res_txt = self.query(server, "qnamemintest.internet.nl", "TXT", rd=rd)
            for ans in res_txt['answers']:
                if "HOORAY" in ans.upper(): return True, res_txt.get("latency")
            return False, res_txt.get("latency")
        except:
            return False, None

    def check_dns_cookies(self, server):
        """Check for DNS Cookies (RFC 7873) support."""
        start = time.time()
        try:
            # Request cookie (Option 10)
            from dns.edns import GenericOption
            import os
            client_cookie = os.urandom(8)
            options = [GenericOption(10, client_cookie)]
            query = dns.message.make_query(".", "SOA")
            query.use_edns(edns=0, payload=1232, options=options)
            response = dns.query.udp(query, server, timeout=self.timeout)
            latency = (time.time() - start) * 1000
            
            for opt in response.options:
                if opt.otype == 10: return True, latency
            return False, latency
        except:
            return False, None

    def validate_caa(self, server, domain, rd=True):
        """Check for CAA records (Certificate Authority Authorization)."""
        try:
            res = self.query(server, domain, "CAA", rd=rd)
            if res['status'] == "NOERROR" and res['answers']:
                return True, res['answers'], res.get("latency"), {
                    "protocol": res.get("protocol"),
                    "rcode": res.get("status"),
                    "flags": res.get("flags"),
                    "query_size": res.get("query_size"),
                    "response_size": res.get("response_size"),
                    "authority_count": res.get("authority_count"),
                    "answer_count": res.get("answer_count"),
                    "aa": res.get("aa"),
                    "tc": res.get("tc"),
                }
            return False, [], res.get("latency"), {
                "protocol": res.get("protocol"),
                "rcode": res.get("status"),
                "flags": res.get("flags"),
                "query_size": res.get("query_size"),
                "response_size": res.get("response_size"),
                "authority_count": res.get("authority_count"),
                "answer_count": res.get("answer_count"),
                "aa": res.get("aa"),
                "tc": res.get("tc"),
            }
        except:
            return False, [], None, {"protocol": "udp", "failure_reason": "error"}
