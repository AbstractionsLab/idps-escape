"""
Manager-side enrichment for geoip_detection's web-access log path.
"""
from __future__ import annotations

import re

from geoip import geo_lookup

RX_RSYSLOG = re.compile(r"^\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(?:nginx|apache):\s+(?P<rest>.*)$")
RX_IPV6_MAPPED = re.compile(r"^::ffff:(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+")
RX_HOST_PORT_IP = re.compile(r"^\S+:\d+\s+(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[")
RX_DOMAIN_IP = re.compile(r"^\S+\.\S+\s+(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[")
RX_TWO_IPS = re.compile(r"^\S+\s+(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[")
RX_SINGLE_IP = re.compile(r"^(?P<srcip>\d{1,3}(?:\.\d{1,3}){3})\s+\S+\s+\S+\s+\[")

PRIVATE_PREFIXES = (
    "10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
)


def is_private_ip(ip: str) -> bool:
    return any(ip.startswith(p) for p in PRIVATE_PREFIXES)


def extract_srcip(full_log: str):
    m = RX_RSYSLOG.match(full_log)
    rest = m.group("rest") if m else full_log
    for rx in (RX_IPV6_MAPPED, RX_HOST_PORT_IP, RX_DOMAIN_IP, RX_TWO_IPS, RX_SINGLE_IP):
        m = rx.match(rest)
        if m:
            return m.group("srcip")
    return None


def format_web_radar_tail(country: str, region: str, city: str, lat, lon) -> str:
    return f' RADAR country="{country}" region="{region}" city="{city}" lat="{lat if lat is not None else ""}" lon="{lon if lon is not None else ""}"'


def enrich_web_access(city_reader, asn_reader, full_log: str) -> str | None:
    if '"' not in full_log or "HTTP/" not in full_log:
        return None

    srcip = extract_srcip(full_log)
    if not srcip or is_private_ip(srcip):
        return None

    country, region, city, lat, lon, _asn = geo_lookup(city_reader, asn_reader, srcip)
    return format_web_radar_tail(country, region, city, lat, lon)