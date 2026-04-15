#!/usr/bin/env python3
import time
import subprocess
from pathlib import Path

from common import load_config, get_scenario_simulate


def _int(v, default):
    try:
        return int(v)
    except Exception:
        return default


def _float(v, default):
    try:
        return float(v)
    except Exception:
        return default


def _ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def _append_bytes(file_path: Path, bytes_to_add: int, chunk: int = 1024 * 1024) -> None:
    remaining = bytes_to_add
    buf = b"0" * min(chunk, remaining)
    with file_path.open("ab", buffering=0) as f:
        while remaining > 0:
            n = min(len(buf), remaining)
            f.write(buf[:n])
            remaining -= n


def _schedule_cleanup(file_path: Path, cleanup_minutes: int) -> None:
    if cleanup_minutes <= 0:
        return
    seconds = cleanup_minutes * 60
    fp = str(file_path)
    cmd = f"(sleep {seconds}; rm -f '{fp}') >/dev/null 2>&1 &"
    subprocess.Popen(["sh", "-lc", cmd], close_fds=True)


def main() -> None:
    cfg = load_config()
    lv = get_scenario_simulate(cfg, "log_volume")

    base_dir = Path(str(lv.get("target_dir", "/var/log")))
    filename = str(lv.get("spike_filename", "ratf_log_volume_spike.log"))
    spike_file = base_dir / filename

    steps = _int(lv.get("steps", 6), 6)
    start_bytes = _int(lv.get("start_bytes", 5 * 1024 * 1024), 5 * 1024 * 1024)
    growth_factor = _float(lv.get("growth_factor", 2.0), 2.0)
    sleep_seconds = _float(lv.get("sleep_seconds", 2.0), 2.0)
    max_total_bytes = _int(lv.get("max_total_bytes", 512 * 1024 * 1024), 512 * 1024 * 1024)
    max_step_bytes = _int(lv.get("max_step_bytes", 256 * 1024 * 1024), 256 * 1024 * 1024)
    write_chunk_bytes = _int(lv.get("write_chunk_bytes", 1024 * 1024), 1024 * 1024)
    cleanup_minutes = _int(lv.get("cleanup_minutes", 0), 0)

    print("Simulating log_volume (real growth) ...")
    print(f"Target dir: {base_dir}")
    print(f"Spike file: {spike_file}")

    _ensure_dir(base_dir)
    if not spike_file.exists():
        spike_file.touch()

    total_written = 0

    for i in range(steps):
        desired_add = int(start_bytes * (growth_factor ** i))
        add_bytes = min(desired_add, max_step_bytes)

        if total_written + add_bytes > max_total_bytes:
            add_bytes = max_total_bytes - total_written
        if add_bytes <= 0:
            break

        print(f"Step {i+1}/{steps}: appending {add_bytes} bytes")
        _append_bytes(spike_file, add_bytes, chunk=write_chunk_bytes)
        total_written += add_bytes

        size_now = spike_file.stat().st_size
        print(f"Spike file size now: {size_now} bytes")

        time.sleep(sleep_seconds)

    print(f"log_volume simulation completed. Total appended: {total_written} bytes")
    print(f"Spike artifact: {spike_file}")

    if cleanup_minutes > 0:
        _schedule_cleanup(spike_file, cleanup_minutes)
        print(f"Cleanup scheduled in {cleanup_minutes} minute(s): {spike_file}")


if __name__ == "__main__":
    main()