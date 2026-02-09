import sys
import types
import logging
import importlib.util
import importlib.machinery
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


def test_haversine_km_basic(monkeypatch):
    mod = load_module(monkeypatch)
    d = mod.haversine_km(0.0, 0.0, 0.0, 1.0)
    assert 110.0 < d < 112.5


def test_handle_line_skips_non_matching(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(in_path="/tmp/in", out_path="/tmp/out")
    w.city_reader = FakeMaxMindReader({})
    w.asn_reader = FakeMaxMindReader({})

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    w.handle_line("this is not a syslog line")
    assert _radar_lines(handler) == []


def test_handle_line_success_enrichment(monkeypatch):
    mod = load_module(monkeypatch)

    monkeypatch.setattr(mod.time, "time", lambda: 1000.0)

    w = mod.AuthLogWatcher(in_path="/tmp/in", out_path="/tmp/out")
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

    w = mod.AuthLogWatcher(in_path="/tmp/in", out_path="/tmp/out")

    t = {"now": 1000.0}
    monkeypatch.setattr(mod.time, "time", lambda: t["now"])

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

    t["now"] = 1100.0
    line2 = "Jan 6 08:01:40 host sshd[124]: Accepted password for test from 5.6.7.8 port 5555 ssh2"
    w.handle_line(line2)

    msgs = _radar_lines(handler)
    assert len(msgs) == 2

    assert "country_change_i='0'" in msgs[0]
    assert "country_change_i='1'" in msgs[1]


def test_velocity_is_capped(monkeypatch):
    mod = load_module(monkeypatch)

    w = mod.AuthLogWatcher(in_path="/tmp/in", out_path="/tmp/out")
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

    t = {"now": 1000.0}
    monkeypatch.setattr(mod.time, "time", lambda: t["now"])

    handler = _get_dummy_handler(w)
    handler.messages.clear()

    line1 = "Jan 6 08:00:00 host sshd[123]: Accepted password for test from 1.1.1.1 port 5555 ssh2"
    line2 = "Jan 6 09:00:00 host sshd[124]: Accepted password for test from 2.2.2.2 port 5555 ssh2"

    w.handle_line(line1)
    t["now"] += 3600.0
    w.handle_line(line2)

    msgs = _radar_lines(handler)
    assert len(msgs) == 2
    out2 = msgs[-1]

    assert "geo_velocity_kmh='2000.000'" in out2


def test_asn_placeholder_flag_when_missing(monkeypatch):
    mod = load_module(monkeypatch)

    monkeypatch.setattr(mod.time, "time", lambda: 1000.0)

    w = mod.AuthLogWatcher(in_path="/tmp/in", out_path="/tmp/out")
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