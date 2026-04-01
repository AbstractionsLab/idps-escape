import sys
import types
import logging
import importlib.util
import importlib.machinery
import re
from pathlib import Path


class DummyWatchedFileHandler(logging.Handler):

    def __init__(self, path):
        super().__init__()
        self.path = path
        self.messages = []
        self._radar_path = path

    def emit(self, record):
        self.messages.append(record.getMessage())


class FakeMaxMindReader:
    def __init__(self, mapping):
        self.mapping = mapping

    def get(self, ip):
        return self.mapping.get(ip)

    def close(self):
        pass


def load_module(monkeypatch):
    fake_maxminddb = types.ModuleType("maxminddb")
    fake_maxminddb.open_database = lambda path: FakeMaxMindReader({})
    monkeypatch.setitem(sys.modules, "maxminddb", fake_maxminddb)

    import logging.handlers
    monkeypatch.setattr(logging.handlers, "WatchedFileHandler", DummyWatchedFileHandler)

    repo_root = Path(__file__).resolve().parents[2]
    script_path = repo_root / "radar-helper" / "radar-helper.py"
    assert script_path.exists(), f"Script not found at: {script_path}"

    loader = importlib.machinery.SourceFileLoader("radar_helper_under_test", str(script_path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _get_dummy_handler(watcher):
    return next(h for h in watcher.logger.handlers if isinstance(h, DummyWatchedFileHandler))


def _radar_lines(handler: DummyWatchedFileHandler):
    return [m for m in handler.messages if "RADAR outcome" in m]


def _radar_apache_lines(handler: DummyWatchedFileHandler):
    return [m for m in handler.messages if 'RADAR country="' in m]


def test_haversine_km_basic(monkeypatch):
    mod = load_module(monkeypatch)
    d = mod.AuthLogWatcher.haversine_km(0.0, 0.0, 0.0, 1.0)
    assert 110.0 < d < 112.5


def test_handle_line_skips_non_matching(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(mod.RADAR_LOG, in_path="/tmp/in", out_path="/tmp/out")
    w.city_reader = FakeMaxMindReader({})
    w.asn_reader = FakeMaxMindReader({})

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    w.handle_line("this is not a syslog line")
    assert _radar_lines(handler) == []


def test_handle_line_success_enrichment(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(mod.RADAR_LOG, in_path="/tmp/in", out_path="/tmp/out")
    w.city_reader = FakeMaxMindReader({
        "1.2.3.4": {
            "country": {"iso_code": "DE"},
            "subdivisions": [{"names": {"en": "Bavaria"}}],
            "city": {"names": {"en": "Munich"}},
            "location": {"latitude": 48.137, "longitude": 11.575},
        }
    })
    w.asn_reader = FakeMaxMindReader({
        "1.2.3.4": {"autonomous_system_number": 12345}
    })

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = "Jan 6 08:00:00 host sshd[123]: Accepted password for test from 1.2.3.4 port 5555 ssh2"
    w.handle_line(line)

    msgs = _radar_lines(handler)
    assert len(msgs) == 1
    out = msgs[-1]

    assert "RADAR outcome='success'" in out
    assert "country='DE'" in out
    assert "region='Bavaria'" in out
    assert "city='Munich'" in out
    assert "asn='12345'" in out
    assert "asn_placeholder_flag='false'" in out
    assert "asn_novelty_i='1'" in out
    assert "country_change_i='0'" in out


def test_country_change_indicator(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(mod.RADAR_LOG, in_path="/tmp/in", out_path="/tmp/out")

    w.city_reader = FakeMaxMindReader({
        "1.2.3.4": {
            "country": {"iso_code": "DE"},
            "subdivisions": [{"names": {"en": "Bavaria"}}],
            "city": {"names": {"en": "Munich"}},
            "location": {"latitude": 48.137, "longitude": 11.575},
        },
        "5.6.7.8": {
            "country": {"iso_code": "FR"},
            "subdivisions": [{"names": {"en": "Île-de-France"}}],
            "city": {"names": {"en": "Paris"}},
            "location": {"latitude": 48.8566, "longitude": 2.3522},
        }
    })
    w.asn_reader = FakeMaxMindReader({
        "1.2.3.4": {"autonomous_system_number": 111},
        "5.6.7.8": {"autonomous_system_number": 222},
    })

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line1 = "Jan 6 08:00:00 host sshd[123]: Accepted password for test from 1.2.3.4 port 5555 ssh2"
    w.handle_line(line1)

    line2 = "Jan 6 08:01:40 host sshd[124]: Accepted password for test from 5.6.7.8 port 5555 ssh2"
    w.handle_line(line2)

    msgs = _radar_lines(handler)
    assert len(msgs) == 2

    assert "country_change_i='0'" in msgs[0]
    assert "country_change_i='1'" in msgs[1]


def test_velocity_calculation(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(mod.RADAR_LOG, in_path="/tmp/in", out_path="/tmp/out")
    w.city_reader = FakeMaxMindReader({
        "1.1.1.1": {
            "country": {"iso_code": "AA"},
            "subdivisions": [{"names": {"en": "R1"}}],
            "city": {"names": {"en": "C1"}},
            "location": {"latitude": 0.0, "longitude": 0.0},
        },
        "2.2.2.2": {
            "country": {"iso_code": "AA"},
            "subdivisions": [{"names": {"en": "R1"}}],
            "city": {"names": {"en": "C2"}},
            "location": {"latitude": 0.0, "longitude": 50.0},
        },
    })
    w.asn_reader = FakeMaxMindReader({
        "1.1.1.1": {"autonomous_system_number": 1},
        "2.2.2.2": {"autonomous_system_number": 1},
    })

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line1 = "Jan 6 08:00:00 host sshd[123]: Accepted password for test from 1.1.1.1 port 5555 ssh2"
    line2 = "Jan 6 09:00:00 host sshd[124]: Accepted password for test from 2.2.2.2 port 5555 ssh2"

    w.handle_line(line1)
    w.handle_line(line2)

    msgs = _radar_lines(handler)
    assert len(msgs) == 2
    m = re.search(r"geo_velocity_kmh='([^']+)'", msgs[-1])
    assert m is not None
    velocity = float(m.group(1))

    assert velocity > 900.0


def test_country_change_only_tracks_per_user(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(mod.RADAR_LOG, in_path="/tmp/in", out_path="/tmp/out")
    w.city_reader = FakeMaxMindReader({
        "1.2.3.4": {
            "country": {"iso_code": "DE"},
            "subdivisions": [{"names": {"en": "Bavaria"}}],
            "city": {"names": {"en": "Munich"}},
            "location": {"latitude": 48.137, "longitude": 11.575},
        },
        "5.6.7.8": {
            "country": {"iso_code": "FR"},
            "subdivisions": [{"names": {"en": "Île-de-France"}}],
            "city": {"names": {"en": "Paris"}},
            "location": {"latitude": 48.8566, "longitude": 2.3522},
        }
    })
    w.asn_reader = FakeMaxMindReader({
        "1.2.3.4": {"autonomous_system_number": 111},
        "5.6.7.8": {"autonomous_system_number": 222},
    })

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    w.handle_line("Jan 6 08:00:00 host sshd[1]: Accepted password for alice from 1.2.3.4 port 22 ssh2")
    w.handle_line("Jan 6 09:00:00 host sshd[2]: Accepted password for bob from 5.6.7.8 port 22 ssh2")

    msgs = _radar_lines(handler)
    assert len(msgs) == 2
    assert "country_change_i='0'" in msgs[1]


def test_asn_novelty_is_per_user_not_global(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(mod.RADAR_LOG, in_path="/tmp/in", out_path="/tmp/out")
    w.city_reader = FakeMaxMindReader({
        "1.2.3.4": {
            "country": {"iso_code": "DE"},
            "subdivisions": [{"names": {"en": "Bavaria"}}],
            "city": {"names": {"en": "Munich"}},
            "location": {"latitude": 48.137, "longitude": 11.575},
        }
    })
    w.asn_reader = FakeMaxMindReader({
        "1.2.3.4": {"autonomous_system_number": 12345}
    })

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    w.handle_line("Jan 6 08:00:00 host sshd[1]: Accepted password for alice from 1.2.3.4 port 22 ssh2")
    w.handle_line("Jan 6 09:00:00 host sshd[2]: Accepted password for bob from 1.2.3.4 port 22 ssh2")

    msgs = _radar_lines(handler)
    assert len(msgs) == 2
    assert "asn_novelty_i='1'" in msgs[0]
    assert "asn_novelty_i='1'" in msgs[1]


def test_asn_placeholder_flag_when_missing(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(mod.RADAR_LOG, in_path="/tmp/in", out_path="/tmp/out")
    w.city_reader = FakeMaxMindReader({
        "9.9.9.9": {
            "country": {"iso_code": "US"},
            "subdivisions": [{"names": {"en": "CA"}}],
            "city": {"names": {"en": "LA"}},
            "location": {"latitude": 34.05, "longitude": -118.24},
        }
    })
    w.asn_reader = FakeMaxMindReader({
        "9.9.9.9": {}
    })

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = "Jan 6 08:00:00 host sshd[123]: Failed password for test from 9.9.9.9 port 5555 ssh2"
    w.handle_line(line)

    msgs = _radar_lines(handler)
    assert len(msgs) == 1
    out = msgs[-1]

    assert "RADAR outcome='failure'" in out
    assert "asn=''" in out
    assert "asn_placeholder_flag='true'" in out
    assert "asn_novelty_i='0'" in out


_BRAZIL_GEO = {
    "country": {"names": {"en": "Brazil"}},
    "subdivisions": [{"names": {"en": "Parana"}}],
    "city": {"names": {"en": "Curitiba"}},
    "location": {"latitude": -25.5026, "longitude": -49.2908},
}


def _make_apache_watcher(mod, geo_mapping):
    w = mod.ApacheLogWatcher(mod.RADAR_LOG, in_path="/tmp/in", out_path="/tmp/out")
    w.city_reader = FakeMaxMindReader(geo_mapping)
    return w


def test_apache_skips_line_without_http(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"1.2.3.4": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    w.handle_line("1.2.3.4 - - [24/Mar/2026:10:00:00 +0100] no protocol here")
    assert _radar_apache_lines(handler) == []


def test_apache_skips_line_without_quote(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"1.2.3.4": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    w.handle_line("1.2.3.4 - - [24/Mar/2026:10:00:00 +0100] GET /index HTTP/1.1 200 512")
    assert _radar_apache_lines(handler) == []


def test_apache_skips_private_ip(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    for private_ip in ("192.168.1.10", "10.0.0.5", "172.16.0.1", "127.0.0.1"):
        line = f'{private_ip} - - [24/Mar/2026:10:00:00 +0100] "GET /index HTTP/1.1" 200 512 "-" "curl/7.68.0"'
        w.handle_line(line)

    assert _radar_apache_lines(handler) == []


def test_apache_single_ip_enrichment(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"187.88.104.81": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = '187.88.104.81 - - [12/Mar/2026:11:17:54 +0100] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/7.68.0"'
    w.handle_line(line)

    msgs = _radar_apache_lines(handler)
    assert len(msgs) == 1
    out = msgs[0]
    assert 'RADAR country="Brazil"' in out
    assert 'region="Parana"' in out
    assert 'city="Curitiba"' in out
    assert 'lat="-25.5026"' in out
    assert 'lon="-49.2908"' in out
    assert out.startswith(line)


def test_apache_host_port_ip_format(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"187.88.104.81": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = 'nextcloud.com:443 187.88.104.81 - - [12/Mar/2026:11:18:38 +0100] "GET /ocs/v2.php HTTP/1.1" 404 6871 "-" "Mozilla/5.0"'
    w.handle_line(line)

    msgs = _radar_apache_lines(handler)
    assert len(msgs) == 1
    assert 'RADAR country="Brazil"' in msgs[0]


def test_apache_domain_ip_format(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"187.88.104.81": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = 'domain.com 187.88.104.81 - - [12/Mar/2026:11:18:38 +0100] "GET /url HTTP/1.1" 200 512 "-" "curl/7.68.0"'
    w.handle_line(line)

    msgs = _radar_apache_lines(handler)
    assert len(msgs) == 1
    assert 'RADAR country="Brazil"' in msgs[0]


def test_apache_two_ip_format(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"187.88.104.81": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = '10.10.10.1 187.88.104.81 - - [12/Mar/2026:11:18:38 +0100] "GET /url HTTP/1.1" 200 512 "-" "curl/7.68.0"'
    w.handle_line(line)

    msgs = _radar_apache_lines(handler)
    assert len(msgs) == 1
    assert 'RADAR country="Brazil"' in msgs[0]


def test_apache_ipv6_mapped_format(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"187.88.104.81": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = '::ffff:187.88.104.81 - - [12/Mar/2026:11:18:38 +0100] "GET /url HTTP/1.1" 200 512 "-" "curl/7.68.0"'
    w.handle_line(line)

    msgs = _radar_apache_lines(handler)
    assert len(msgs) == 1
    assert 'RADAR country="Brazil"' in msgs[0]


def test_apache_rsyslog_prefix_stripped(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"187.88.104.81": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = 'Jan 11 10:13:05 web01 nginx: 187.88.104.81 - - [11/Jan/2026:10:13:05 +0100] "GET /url HTTP/1.1" 200 512 "-" "curl/7.68.0"'
    w.handle_line(line)

    msgs = _radar_apache_lines(handler)
    assert len(msgs) == 1
    assert 'RADAR country="Brazil"' in msgs[0]


def test_apache_output_uses_double_quotes(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {"187.88.104.81": _BRAZIL_GEO})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = '187.88.104.81 - - [12/Mar/2026:11:17:54 +0100] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/7.68.0"'
    w.handle_line(line)

    msgs = _radar_apache_lines(handler)
    assert len(msgs) == 1
    out = msgs[0]
    assert 'RADAR country="Brazil"' in out
    assert "RADAR country='Brazil'" not in out


def test_apache_unknown_ip_produces_empty_fields(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {})
    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line = '8.8.8.8 - - [12/Mar/2026:11:17:54 +0100] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/7.68.0"'
    w.handle_line(line)

    msgs = _radar_apache_lines(handler)
    assert len(msgs) == 1
    out = msgs[0]
    assert 'RADAR country=""' in out
    assert 'city=""' in out


def test_apache_extract_srcip_priority_order(monkeypatch):
    mod = load_module(monkeypatch)
    w = _make_apache_watcher(mod, {})

    ip, _ = w.extract_srcip('nextcloud.com:443 187.88.104.81 - - [ts] "GET / HTTP/1.1" 200 0')
    assert ip == "187.88.104.81"

    ip, _ = w.extract_srcip('1.2.3.4 - - [ts] "GET / HTTP/1.1" 200 0')
    assert ip == "1.2.3.4"

    ip, _ = w.extract_srcip("no ip here at all")
    assert ip is None