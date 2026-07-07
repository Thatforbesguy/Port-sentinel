"""
Risk Classification Engine.

This module is the "brain" of the vulnerability scanner.  It takes raw nmap
output (open port + service name) and assigns a risk level with a human-
readable explanation of *why* that finding matters.

Why this matters for Security+ (Domain 2 — Threats, Vulnerabilities, and
Mitigation):
    A real SOC analyst doesn't just list open ports — they explain the risk.
    "Port 23 is open" means nothing to a manager; "Telnet transmits
    credentials in plaintext and should be replaced with SSH" is actionable.
    Every entry in RISK_RULES is written to demonstrate that reasoning.

How it works:
    1.  The scanner finds open ports and identifies the service via nmap.
    2.  This engine looks up each port in RISK_RULES.
    3.  If a rule exists, it returns that rule's risk level and description.
    4.  If no rule exists, it returns a generic "Info" level finding — because
        an open port we don't recognize isn't necessarily dangerous, but it
        should still be reported.
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Risk rule definitions
# ---------------------------------------------------------------------------
# Each key is a TCP port number.
# Each value is a dict with:
#   - service:     Canonical service name (used if nmap doesn't report one).
#   - risk_level:  "Critical" | "High" | "Medium" | "Low" | "Info"
#   - description: Plain-English security reasoning.
#
# The descriptions are intentionally written at a "SOC analyst briefing"
# level — clear enough for a non-technical reader, but technically precise
# enough to demonstrate Security+ domain knowledge.
# ---------------------------------------------------------------------------

RISK_RULES: dict[int, dict] = {

    # ------------------------------------------------------------------
    # CRITICAL — these services should almost never be exposed
    # ------------------------------------------------------------------
    23: {
        "service": "Telnet",
        "risk_level": "Critical",
        "description": (
            "Telnet transmits all data — including usernames and passwords — "
            "in plaintext. Any attacker on the same network segment can "
            "capture credentials with a packet sniffer. Telnet should be "
            "disabled and replaced with SSH."
        ),
    },
    445: {
        "service": "SMB",
        "risk_level": "Critical",
        "description": (
            "SMB (Server Message Block) has been the target of multiple "
            "devastating exploits, including EternalBlue (CVE-2017-0144) "
            "which powered the WannaCry ransomware outbreak. Exposing port "
            "445 to a network allows file-share enumeration, credential "
            "relay attacks, and lateral movement. SMB should be restricted "
            "to trusted hosts via firewall rules and kept fully patched."
        ),
    },
    3389: {
        "service": "RDP",
        "risk_level": "Critical",
        "description": (
            "Remote Desktop Protocol is one of the most commonly brute-"
            "forced services on the internet. It has also been affected by "
            "critical vulnerabilities such as BlueKeep (CVE-2019-0708), "
            "which allows unauthenticated remote code execution. RDP "
            "should be placed behind a VPN or secured with Network Level "
            "Authentication (NLA) and strong passwords."
        ),
    },
    1433: {
        "service": "MS-SQL",
        "risk_level": "Critical",
        "description": (
            "Microsoft SQL Server exposed on the network allows attackers "
            "to attempt authentication brute-force or exploit known "
            "vulnerabilities (e.g. the 'sa' account with a weak password). "
            "Database ports should never be directly accessible from "
            "untrusted networks — use firewall rules to restrict access to "
            "application servers only."
        ),
    },
    3306: {
        "service": "MySQL",
        "risk_level": "Critical",
        "description": (
            "MySQL exposed on the network is a high-value target. Default "
            "installations sometimes allow root login without a password. "
            "Attackers can enumerate databases, extract sensitive data, or "
            "leverage SQL injection from a compromised web application. "
            "Bind MySQL to 127.0.0.1 unless remote access is required, "
            "and enforce strong authentication."
        ),
    },
    5432: {
        "service": "PostgreSQL",
        "risk_level": "Critical",
        "description": (
            "PostgreSQL exposed to the network risks unauthorized data "
            "access. Misconfigured pg_hba.conf files can allow connections "
            "from any host. Like all databases, PostgreSQL should be "
            "firewalled to accept connections only from known application "
            "servers."
        ),
    },

    2375: {
        "service": "Docker",
        "risk_level": "Critical",
        "description": (
            "Unprotected Docker daemon APIs allow attackers to spin up "
            "containers, mount the host system's root filesystem, and achieve "
            "full remote code execution (RCE) on the host. Secure the API with "
            "TLS client certificates or bind it to localhost only."
        ),
    },
    2376: {
        "service": "Docker-TLS",
        "risk_level": "Critical",
        "description": (
            "While encrypted, the Docker daemon API is exposed. If mutual TLS "
            "(mTLS) is not properly configured, an attacker could still "
            "interact with the daemon to achieve container escape and host "
            "compromise. Ensure strong authentication is enforced."
        ),
    },
    10250: {
        "service": "Kubelet",
        "risk_level": "Critical",
        "description": (
            "The Kubernetes Kubelet API allows for command execution inside "
            "containers. If exposed and unauthenticated, it can lead to "
            "complete cluster compromise. Restrict access and ensure anonymous "
            "authentication is disabled."
        ),
    },
    8500: {
        "service": "Consul",
        "risk_level": "Critical",
        "description": (
            "Consul provides service discovery and key-value storage. If "
            "exposed without authentication, attackers can read/write KV "
            "entries or register malicious services with health checks that "
            "execute arbitrary commands on the server."
        ),
    },
    502: {
        "service": "Modbus",
        "risk_level": "Critical",
        "description": (
            "Modbus is an industrial control protocol (SCADA/ICS) that lacks "
            "authentication by default. An exposed Modbus port allows anyone "
            "to read or write registers on a PLC, potentially causing "
            "physical infrastructure damage. Isolate on a strict OT network."
        ),
    },

    # ------------------------------------------------------------------
    # HIGH — risky services that need attention
    # ------------------------------------------------------------------
    21: {
        "service": "FTP",
        "risk_level": "High",
        "description": (
            "FTP transmits credentials and file data in plaintext, making "
            "it vulnerable to credential sniffing. Many FTP servers also "
            "allow anonymous access by default. Replace FTP with SFTP "
            "(SSH File Transfer Protocol) or FTPS (FTP over TLS)."
        ),
    },
    25: {
        "service": "SMTP",
        "risk_level": "High",
        "description": (
            "An open SMTP relay can be abused to send spam or phishing "
            "emails, which may get the server's IP blacklisted. Ensure "
            "SMTP requires authentication and is configured to reject "
            "relay from untrusted sources."
        ),
    },
    135: {
        "service": "MS-RPC",
        "risk_level": "High",
        "description": (
            "Microsoft RPC endpoint mapper has been the target of numerous "
            "remote code execution exploits (e.g. MS03-026, used by the "
            "Blaster worm). It should not be exposed beyond the local "
            "network segment and should be filtered by host-based firewalls."
        ),
    },
    139: {
        "service": "NetBIOS",
        "risk_level": "High",
        "description": (
            "NetBIOS Session Service enables file and printer sharing on "
            "older Windows networks. It leaks system information (computer "
            "name, domain, logged-in users) and can be used for lateral "
            "movement. Disable NetBIOS over TCP/IP if SMB direct (port 445) "
            "is available."
        ),
    },
    161: {
        "service": "SNMP",
        "risk_level": "High",
        "description": (
            "SNMP v1/v2c use community strings transmitted in plaintext "
            "(default: 'public'/'private'). An attacker with read access "
            "can enumerate the entire device configuration; with write "
            "access they can reconfigure it. Upgrade to SNMPv3 with "
            "authentication and encryption."
        ),
    },
    5900: {
        "service": "VNC",
        "risk_level": "High",
        "description": (
            "VNC provides remote desktop access and many implementations "
            "use weak or no authentication by default. Unencrypted VNC "
            "sessions can be captured. Use SSH tunneling or a VPN to "
            "secure VNC, and enforce strong passwords."
        ),
    },
    6379: {
        "service": "Redis",
        "risk_level": "High",
        "description": (
            "Redis, by default, does not require authentication and binds "
            "to all interfaces. An exposed Redis instance can be used to "
            "read/write arbitrary data, or even achieve remote code "
            "execution via crafted commands (CONFIG SET). Always require "
            "a password and bind to 127.0.0.1."
        ),
    },
    27017: {
        "service": "MongoDB",
        "risk_level": "High",
        "description": (
            "MongoDB has historically shipped with no authentication "
            "enabled by default. Thousands of exposed MongoDB instances "
            "have been ransomed. Enable authentication, bind to localhost, "
            "and use firewall rules to restrict access."
        ),
    },
    11211: {
        "service": "Memcached",
        "risk_level": "High",
        "description": (
            "Memcached exposed to the network can be abused for DDoS "
            "amplification attacks (amplification factor of up to 51,000x). "
            "It also has no built-in authentication, so cached data can be "
            "read or flushed by anyone. Bind to 127.0.0.1."
        ),
    },

    389: {
        "service": "LDAP",
        "risk_level": "High",
        "description": (
            "Lightweight Directory Access Protocol (LDAP) transmits queries "
            "and credentials in plaintext. Attackers can sniff traffic to "
            "steal passwords or enumerate users and groups. LDAP should be "
            "disabled in favor of LDAPS or LDAP with StartTLS."
        ),
    },
    9200: {
        "service": "Elasticsearch",
        "risk_level": "High",
        "description": (
            "Elasticsearch databases are frequently targeted by automated "
            "ransomware bots when bound to untrusted interfaces without "
            "authentication. Attackers can read, modify, or delete massive "
            "amounts of data. Bind to 127.0.0.1 and enable security features."
        ),
    },
    5985: {
        "service": "WinRM",
        "risk_level": "High",
        "description": (
            "Windows Remote Management (WinRM) over HTTP allows remote "
            "administration. It is subject to brute-forcing, password-spraying, "
            "and lateral movement within corporate networks. It should be "
            "heavily firewalled and restricted to dedicated admin subnets."
        ),
    },
    5986: {
        "service": "WinRM-HTTPS",
        "risk_level": "High",
        "description": (
            "Windows Remote Management (WinRM) over HTTPS provides encryption "
            "but still exposes remote administrative access. It remains a "
            "prime target for credential attacks and lateral movement. Restrict "
            "access using network firewalls."
        ),
    },
    1723: {
        "service": "PPTP",
        "risk_level": "High",
        "description": (
            "Point-to-Point Tunneling Protocol (PPTP) is a deprecated VPN "
            "protocol. Its authentication (MS-CHAPv2) is cryptographically "
            "broken and can be cracked easily to intercept VPN traffic. "
            "Replace with OpenVPN, L2TP/IPsec, or WireGuard."
        ),
    },

    # ------------------------------------------------------------------
    # MEDIUM — generally okay but worth reviewing
    # ------------------------------------------------------------------
    22: {
        "service": "SSH",
        "risk_level": "Medium",
        "description": (
            "SSH is the recommended secure remote access protocol, but "
            "exposed SSH services are frequent brute-force targets. Ensure "
            "password authentication is disabled in favor of key-based "
            "auth, and consider using fail2ban or similar rate-limiting. "
            "Outdated OpenSSH versions may be vulnerable (e.g. regreSSHion, "
            "CVE-2024-6387)."
        ),
    },
    53: {
        "service": "DNS",
        "risk_level": "Medium",
        "description": (
            "An open DNS resolver can be abused for DNS amplification DDoS "
            "attacks. If this is an internal DNS server, ensure it does not "
            "respond to queries from external networks. Also check that "
            "zone transfers (AXFR) are restricted to authorized secondaries."
        ),
    },
    80: {
        "service": "HTTP",
        "risk_level": "Medium",
        "description": (
            "HTTP serves web content without encryption. Any data "
            "transmitted — including session cookies and form submissions — "
            "can be intercepted. Migrate to HTTPS (port 443) and configure "
            "HTTP to redirect to HTTPS automatically."
        ),
    },
    110: {
        "service": "POP3",
        "risk_level": "Medium",
        "description": (
            "POP3 retrieves email over an unencrypted connection. "
            "Credentials and email contents are transmitted in plaintext. "
            "Use POP3S (port 995) with TLS encryption instead."
        ),
    },
    143: {
        "service": "IMAP",
        "risk_level": "Medium",
        "description": (
            "IMAP retrieves email over an unencrypted connection. "
            "Credentials and email contents are transmitted in plaintext. "
            "Use IMAPS (port 993) with TLS encryption instead."
        ),
    },
    8080: {
        "service": "HTTP-Alt",
        "risk_level": "Medium",
        "description": (
            "Port 8080 is commonly used for development web servers, "
            "proxy servers, or administrative panels. These often lack "
            "the hardening applied to production services on port 80/443. "
            "Verify this service is intentional and properly secured."
        ),
    },
    8443: {
        "service": "HTTPS-Alt",
        "risk_level": "Medium",
        "description": (
            "Port 8443 is an alternate HTTPS port frequently used for "
            "management interfaces (e.g. VMware, Tomcat admin). While "
            "encrypted, these admin panels may expose sensitive "
            "configuration capabilities. Restrict access to authorized "
            "administrators."
        ),
    },
    2049: {
        "service": "NFS",
        "risk_level": "Medium",
        "description": (
            "Network File System (NFS) shares, if misconfigured, can "
            "allow unauthorized hosts to mount and read/write file systems. "
            "Ensure exports are restricted to specific IPs and use NFSv4 "
            "with Kerberos authentication where possible."
        ),
    },

    1900: {
        "service": "UPnP",
        "risk_level": "Medium",
        "description": (
            "Universal Plug and Play (UPnP) is often enabled on local routers "
            "and IoT devices. It is vulnerable to SSDP amplification DDoS "
            "attacks and can sometimes be manipulated to expose internal "
            "devices to the internet. UPnP should generally be disabled."
        ),
    },
    5060: {
        "service": "SIP",
        "risk_level": "Medium",
        "description": (
            "Session Initiation Protocol (SIP) is used for VoIP. Exposed SIP "
            "ports are frequent targets of SIP scanning, toll fraud, and "
            "authentication brute-forcing. Ensure strong credentials and rate "
            "limiting are applied."
        ),
    },
    9100: {
        "service": "JetDirect",
        "risk_level": "Medium",
        "description": (
            "Port 9100 is used for RAW network printing. Printer ports are "
            "usually unauthenticated and can be abused to capture print jobs, "
            "spam the printer, or manipulate device firmware. Isolate printers "
            "on dedicated VLANs."
        ),
    },
    111: {
        "service": "RPCbind",
        "risk_level": "Medium",
        "description": (
            "RPCbind (Portmapper) maps RPC services to network ports. It can "
            "leak system metadata about available services and can be abused "
            "in UDP amplification attacks. Filter access to trusted hosts."
        ),
    },

    # ------------------------------------------------------------------
    # LOW — generally secure, but still worth noting
    # ------------------------------------------------------------------
    443: {
        "service": "HTTPS",
        "risk_level": "Low",
        "description": (
            "HTTPS provides encrypted web communication. While generally "
            "secure, verify that the TLS configuration uses modern "
            "protocols (TLS 1.2+) and strong cipher suites. Weak "
            "configurations may be vulnerable to downgrade attacks."
        ),
    },
    993: {
        "service": "IMAPS",
        "risk_level": "Low",
        "description": (
            "IMAPS is the TLS-encrypted version of IMAP. This is the "
            "recommended configuration for email retrieval. Verify the "
            "TLS certificate is valid and protocols are up to date."
        ),
    },
    995: {
        "service": "POP3S",
        "risk_level": "Low",
        "description": (
            "POP3S is the TLS-encrypted version of POP3. This is the "
            "recommended configuration. Verify TLS certificate validity."
        ),
    },
    587: {
        "service": "SMTP-Submission",
        "risk_level": "Low",
        "description": (
            "Port 587 is the standard mail submission port, which "
            "typically requires authentication and supports STARTTLS. "
            "This is the recommended way to send email. Ensure STARTTLS "
            "is enforced (not optional)."
        ),
    },
    636: {
        "service": "LDAPS",
        "risk_level": "Low",
        "description": (
            "LDAPS is the secure, TLS-encrypted version of LDAP. While "
            "generally secure against sniffing, ensure the TLS certificate "
            "is valid and strong cipher suites are enforced."
        ),
    },
    2222: {
        "service": "SSH-Alt",
        "risk_level": "Low",
        "description": (
            "Port 2222 is a frequently used alternate port for SSH. Moving "
            "SSH to a non-standard port reduces log noise from automated "
            "scanners, but does not replace the need for key-based "
            "authentication and proper hardening."
        ),
    },
}


def classify_port(port: int, service_name: str) -> dict:
    """
    Classify a single open port and return a risk assessment.

    Parameters
    ----------
    port : int
        The TCP port number found open by nmap.
    service_name : str
        The service name reported by nmap (e.g. "ssh", "http").
        Used as a fallback display name if the port isn't in our rules.

    Returns
    -------
    dict
        A dictionary with keys: port, service, status, risk_level,
        description — matching the Vulnerability schema.
    """
    if port in RISK_RULES:
        rule = RISK_RULES[port]
        return {
            "port": port,
            "service": rule["service"],
            "status": "Open",
            "risk_level": rule["risk_level"],
            "description": rule["description"],
        }

    # Unknown port — still report it, but at "Info" level.
    # An open port we don't have a rule for isn't necessarily dangerous,
    # but a SOC analyst would still want to see it for visibility.
    return {
        "port": port,
        "service": service_name.upper() if service_name else f"UNKNOWN ({port})",
        "status": "Open",
        "risk_level": "Info",
        "description": (
            f"Port {port} ({service_name or 'unknown service'}) is open. "
            f"No specific risk rule is defined for this port. Review "
            f"whether this service is expected and necessary."
        ),
    }
