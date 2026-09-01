"""
Stateless GeoIP / ASN lookup.
"""
from __future__ import annotations


def geo_lookup(city_reader, asn_reader, ip: str):
    """
    Returns (country, region, city, lat, lon, asn).

    country: ISO country code, e.g. "US" (not the full name -- that's what
             ApacheLogWatcher/geoip_detection uses; suspicious_login has
             always used iso_code, confirmed against the live decoder output).
    region:  first subdivision's English name, or "".
    city:    English city name, or "".
    lat/lon: floats, or None if unavailable.
    asn:     stringified ASN number, or "" if unavailable.
    """
    country = region = city = ""
    lat = lon = None
    asn = ""

    try:
        c = city_reader.get(ip) or {}
        country = (c.get("country") or {}).get("iso_code") or ""
        subs = c.get("subdivisions") or []
        if subs and isinstance(subs, list):
            region = (subs[0].get("names") or {}).get("en") or ""
        city = ((c.get("city") or {}).get("names") or {}).get("en") or ""
        loc = c.get("location") or {}
        lat = loc.get("latitude")
        lon = loc.get("longitude")
    except Exception:
        pass

    try:
        a = asn_reader.get(ip) or {}
        asn = str(a.get("autonomous_system_number") or "")
    except Exception:
        pass

    return country, region, city, lat, lon, asn