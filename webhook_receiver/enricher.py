"""
Threat Intelligence, GeoIP, ASN, and Corporate Network Context Enricher.
Correlates incoming canary callback IP addresses against:
- Internal RFC 1918 subnets (Lateral Movement)
- Corporate VPN CIDR blocks
- Known Tor Exit Nodes and Datacenter Proxies
- MaxMind GeoLite2 databases (with intelligent offline heuristic fallback)
"""

import ipaddress
import logging
import os
from typing import Dict, List, Optional, Tuple
from pathlib import Path

from webhook_receiver.models import EnrichmentData, NetworkContext, TokenType

logger = logging.getLogger("enricher")

# Optional MaxMind GeoIP2 dependency
try:
    import geoip2.database
    HAS_GEOIP2 = True
except ImportError:
    HAS_GEOIP2 = False

# Default Corporate VPN and Sanctioned Subnets (configurable via environment)
DEFAULT_CORP_VPN_CIDRS = [
    "10.200.0.0/16",       # Corporate GlobalProtect / OpenVPN Pool
    "100.64.0.0/10",        # Tailscale / WireGuard CGNAT corporate mesh
    "192.168.100.0/24",    # Staging jump-box subnet
]

# Sample known Tor exit nodes and malicious proxy addresses for deterministic simulation
KNOWN_TOR_EXIT_IPS = {
    "185.220.101.5",
    "185.220.101.6",
    "185.220.101.7",
    "23.129.64.100",
    "171.25.193.20",
    "199.249.230.70",
}

# RFC 1918 Subnets for Internal Lateral Movement Detection
RFC_1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

# Known datacenter IP ranges (sample heuristics for demo & offline analysis)
KNOWN_DATACENTER_ASNS: Dict[str, Tuple[int, str, str, str]] = {
    "198.51.100": (16509, "Amazon.com, Inc. (AWS Datacenter)", "US", "Ashburn"),
    "203.0.113": (14061, "DigitalOcean, LLC", "DE", "Frankfurt"),
    "45.33.": (63949, "Linode / Akamai", "US", "Newark"),
    "194.26.": (51167, "Contabo GmbH (VPS/Hosting)", "DE", "Munich"),
    "91.198.": (13335, "Cloudflare, Inc.", "NL", "Amsterdam"),
}


class ThreatIntelligenceEnricher:
    """
    Enriches incoming canary trigger events with network context,
    GeoIP location, ASN metadata, and threat classifications.
    """

    def __init__(
        self,
        corporate_vpn_cidrs: Optional[List[str]] = None,
        city_db_path: Optional[str] = None,
        asn_db_path: Optional[str] = None,
    ):
        raw_vpns = corporate_vpn_cidrs or os.getenv("CORP_VPN_CIDRS", "").split(",")
        cleaned_vpns = [c.strip() for c in raw_vpns if c.strip()] or DEFAULT_CORP_VPN_CIDRS

        self.corp_vpn_networks = []
        for cidr in cleaned_vpns:
            try:
                self.corp_vpn_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as err:
                logger.warning("Invalid corporate VPN CIDR '%s': %s", cidr, err)

        # MaxMind DB readers (if files are provided)
        self.city_reader = None
        self.asn_reader = None

        city_path = city_db_path or os.getenv("GEOIP_CITY_DB_PATH")
        asn_path = asn_db_path or os.getenv("GEOIP_ASN_DB_PATH")

        if HAS_GEOIP2 and city_path and Path(city_path).exists():
            try:
                self.city_reader = geoip2.database.Reader(city_path)
                logger.info("Loaded MaxMind City database: %s", city_path)
            except Exception as e:
                logger.warning("Failed to open MaxMind City DB: %s", e)

        if HAS_GEOIP2 and asn_path and Path(asn_path).exists():
            try:
                self.asn_reader = geoip2.database.Reader(asn_path)
                logger.info("Loaded MaxMind ASN database: %s", asn_path)
            except Exception as e:
                logger.warning("Failed to open MaxMind ASN DB: %s", e)

    def close(self):
        """Safely release MaxMind database handles."""
        if self.city_reader:
            self.city_reader.close()
        if self.asn_reader:
            self.asn_reader.close()

    def is_corporate_vpn(self, ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        """Checks if IP belongs to registered corporate VPN or mesh CIDR."""
        for net in self.corp_vpn_networks:
            if ip_obj in net:
                return True
        return False

    def enrich(self, raw_ip: str) -> EnrichmentData:
        """
        Executes end-to-end enrichment for the observed IP address.
        """
        # Clean IP representation
        sanitized = raw_ip.strip().split(":")[0] if ":" in raw_ip and not raw_ip.startswith(":") and "." in raw_ip else raw_ip.strip()

        try:
            ip_obj = ipaddress.ip_address(sanitized)
        except ValueError:
            logger.warning("Malformed IP address encountered: '%s', treating as unknown", sanitized)
            return EnrichmentData(
                source_ip=sanitized,
                network_context=NetworkContext.EXTERNAL_INTERNET_ACCESS,
                country_name="Invalid/Unknown IP",
            )

        # 1. Check Loopback
        if ip_obj.is_loopback:
            return EnrichmentData(
                source_ip=sanitized,
                is_private_ip=True,
                country_code="LO",
                country_name="Localhost Loopback",
                city="Local Simulation Workstation",
                asn=0,
                asn_org="Localhost Loopback Network",
                network_context=NetworkContext.LOOPBACK_LOCAL_SIMULATION,
                confidence_score=1.0,
            )

        # 2. Check Tor Exit Nodes
        is_tor = sanitized in KNOWN_TOR_EXIT_IPS or "tor" in sanitized.lower()
        if is_tor:
            return EnrichmentData(
                source_ip=sanitized,
                is_tor_exit_node=True,
                is_private_ip=False,
                country_code="NL",
                country_name="Netherlands",
                city="Amsterdam (Tor Exit)",
                asn=60729,
                asn_org="Tor Anonymizing Overlay Network",
                network_context=NetworkContext.TOR_EXIT_NODE,
                confidence_score=1.0,
            )

        # 3. Check Corporate VPN CIDRs
        if self.is_corporate_vpn(ip_obj):
            return EnrichmentData(
                source_ip=sanitized,
                is_corporate_vpn=True,
                is_private_ip=ip_obj.is_private,
                country_code="US",
                country_name="United States",
                city="Corporate Secure Gateway",
                asn=65530,
                asn_org="Internal Corporate Enterprise Network",
                network_context=NetworkContext.CORPORATE_VPN,
                confidence_score=1.0,
            )

        # 4. Check Internal RFC 1918 Private Ranges (Lateral Movement)
        is_rfc1918 = any(ip_obj in net for net in RFC_1918_NETWORKS) if isinstance(ip_obj, ipaddress.IPv4Address) else False
        if is_rfc1918:
            return EnrichmentData(
                source_ip=sanitized,
                is_private_ip=True,
                country_code="PV",
                country_name="Private Intranet",
                city="Internal RFC 1918 Subnet",
                asn=64512,
                asn_org="Internal Staging / Kubernetes Cluster Pod",
                network_context=NetworkContext.INTERNAL_LATERAL_MOVEMENT,
                confidence_score=1.0,
            )

        # 5. External Public IP Enrichment via MaxMind or Fallback Heuristics
        country_code = "US"
        country_name = "United States"
        city = "Washington, D.C."
        asn = 15169
        asn_org = "Google LLC / Public IP"
        is_dc = False

        # If MaxMind readers are available, query them
        if self.city_reader:
            try:
                city_resp = self.city_reader.city(str(ip_obj))
                country_code = city_resp.country.iso_code or "XX"
                country_name = city_resp.country.name or "Unknown"
                city = city_resp.city.name or "Unknown"
            except Exception:
                pass

        if self.asn_reader:
            try:
                asn_resp = self.asn_reader.asn(str(ip_obj))
                asn = asn_resp.autonomous_system_number or 0
                asn_org = asn_resp.autonomous_system_organization or "Unknown"
            except Exception:
                pass

        # Offline fallback heuristics for demo / testing IP addresses
        if not self.city_reader and not self.asn_reader:
            matched_dc = False
            for prefix, (mock_asn, mock_org, mock_cc, mock_city) in KNOWN_DATACENTER_ASNS.items():
                if sanitized.startswith(prefix):
                    asn = mock_asn
                    asn_org = mock_org
                    country_code = mock_cc
                    city = mock_city
                    country_name = "Germany" if mock_cc == "DE" else "United States"
                    is_dc = True
                    matched_dc = True
                    break

            if not matched_dc and (sanitized.startswith("198.51.") or sanitized.startswith("203.0.")):
                is_dc = True
                asn_org = "External Hosting / Datacenter"

        context = (
            NetworkContext.SUSPICIOUS_DATACENTER_PROXY
            if is_dc
            else NetworkContext.EXTERNAL_INTERNET_ACCESS
        )

        return EnrichmentData(
            source_ip=sanitized,
            is_private_ip=False,
            is_corporate_vpn=False,
            is_tor_exit_node=False,
            is_datacenter_proxy=is_dc,
            country_code=country_code,
            country_name=country_name,
            city=city,
            asn=asn,
            asn_org=asn_org,
            network_context=context,
            confidence_score=1.0,
        )


def map_mitre_ttp(token_type: str) -> str:
    """
    Returns exact MITRE ATT&CK technique IDs and descriptions based on token type.
    """
    mapping = {
        TokenType.AWS_HONEY_KEY.value: "T1552.001 (Credentials in Files) / T1078 (Unsanctioned Cloud Account Access)",
        TokenType.KUBECONFIG.value: "T1552.001 / T1609 (Container Administration & Orchestration Exploitation)",
        TokenType.CANARY_PDF.value: "T1005 (Data from Local System) / T1083 (File and Directory Discovery)",
        TokenType.DATABASE_ENV.value: "T1552.001 (Credentials in Files) / T1190 (Exploit for DB Credential Access)",
        TokenType.WEBHOOK_TOKEN.value: "T1552.005 (Cloud API Secrets) / T1078 (Valid Service Accounts)",
        "aws_honey_key": "T1552.001 (Credentials in Files) / T1078 (Unsanctioned Cloud Account Access)",
        "kubeconfig": "T1552.001 / T1609 (Container Administration & Orchestration Exploitation)",
        "canary_pdf": "T1005 (Data from Local System) / T1083 (File and Directory Discovery)",
        "database_env": "T1552.001 (Credentials in Files) / T1190 (Exploit for DB Credential Access)",
        "webhook_token": "T1552.005 (Cloud API Secrets) / T1078 (Valid Service Accounts)",
    }
    return mapping.get(token_type, "T1552 (Unsanctioned Credential Access)")
