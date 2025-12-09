#!/usr/bin/env python3
from __future__ import annotations
import hashlib
import os
from datetime import datetime, timezone
from typing import Dict, Tuple, List, Optional

WAZUH_LOCATION = "/var/log/audit/audit.log"

def _to_uid(user: str) -> int:
    h = int(hashlib.sha256(user.encode()).hexdigest(), 16)
    return 1000 + (h % 30000)

def _pick_comm_exe(filename: str) -> Tuple[str, str]:
    ext = os.path.splitext(filename)[1].lower()
    if ext in (".txt", ".md"):               return ("bash", "/usr/bin/bash")
    if ext in (".doc", ".docx", ".pdf"):     return ("libreoffice", "/usr/bin/soffice")
    if ext in (".jpg", ".jpeg", ".png"):     return ("bash", "/usr/bin/bash")
    if ext in (".sh", ".py"):                return ("bash", "/usr/bin/bash")
    return ("bash", "/usr/bin/bash")

def _mk_audit_epoch(dt_utc: datetime) -> str:
    return f"{dt_utc.timestamp():.3f}"

def _mk_seq(row_id: str, iso_ts: str) -> int:
    return int(hashlib.md5((row_id + iso_ts).encode()).hexdigest(), 16) % 900000 + 10000

def _mk_path(user: str, filename: str) -> str:
    return f"/home/{user}/Documents/{filename}"

def convert_row_to_wazuh_docs(
    row: Dict[str, str],
    shifted_local: datetime,
    agent_name: Optional[str] = None,
) -> Tuple[Dict, Dict]:
    """
    Convert one CSV row (id,date,user,pc,filename,content) into TWO docs:
      1) SYSCALL (openat + O_CREAT)
      2) PATH (file create target)
    Docs mimic Wazuh 'wazuh-archives-*' auditd events.
    """
    user = (row.get("user") or "user").strip()
    host = agent_name or (row.get("pc") or "").strip() or None
    filename = (row.get("filename") or "file.txt").strip()

    uid_num = _to_uid(user)
    gid_num = uid_num

    dt_utc = shifted_local.replace(tzinfo=timezone.utc)
    iso_ts = dt_utc.isoformat()
    audit_ts = _mk_audit_epoch(dt_utc)
    seq = _mk_seq(row.get("id", ""), iso_ts)

    comm, exe = _pick_comm_exe(filename)
    file_path = _mk_path(user, filename)

    syscall_full = (
        f'type=SYSCALL msg=audit({audit_ts}:{seq}): arch=c000003e syscall=257 success=yes exit=3 '
        f'a0=ffffff9c a1=7ffdeadbeef a2=241 a3=1b6 items=2 ppid=2000 pid=2001 '
        f'auid={uid_num} uid={uid_num} gid={gid_num} euid={uid_num} suid={uid_num} fsuid={uid_num} '
        f'egid={gid_num} sgid={gid_num} fsgid={gid_num} tty=pts0 ses=1 comm="{comm}" exe="{exe}" '
        f'subj=unconfined key="file_create" ARCH=x86_64 SYSCALL=openat AUID="{user}" UID="{user}" '
        f'GID="{user}" EUID="{user}" SUID="{user}" FSUID="{user}" EGID="{user}" SGID="{user}" FSGID="{user}"'
    )
    path_full = (
        f'type=PATH msg=audit({audit_ts}:{seq}): item=1 name="{file_path}" inode=1441821 dev=fc:02 '
        f'mode=0100644 ouid={uid_num} ogid={gid_num} rdev=00:00 nametype=CREATE '
        f'cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0 OUID="{user}" OGID="{user}"'
    )

    base_agent = {"name": host} if host else None

    syscall_doc = {
        "@timestamp": iso_ts,
        "decoder": {"name": "auditd"},
        "location": WAZUH_LOCATION,
        "agent": base_agent,
        "data": {
            "type": "SYSCALL",
            "arch": "c000003e",
            "syscall": "openat",
            "success": "yes",
            "exit": "3",
            "ppid": "2000",
            "pid": "2001",
            "auid": str(uid_num),
            "uid": str(uid_num),
            "gid": str(gid_num),
            "euid": str(uid_num),
            "tty": "pts0",
            "ses": "1",
            "comm": comm,
            "exe": exe,
            "key": "file_create",
            "AUID": user, "UID": user, "GID": user,
            "EUID": user, "SUID": user, "FSUID": user,
            "EGID": user, "SGID": user, "FSGID": user
        },
        "full_log": syscall_full
    }

    path_doc = {
        "@timestamp": iso_ts,
        "decoder": {"name": "auditd"},
        "location": WAZUH_LOCATION,
        "agent": base_agent,
        "data": {
            "type": "PATH",
            "item": "1",
            "name": file_path,
            "inode": "1441821",
            "dev": "fc:02",
            "mode": "0100644",
            "ouid": str(uid_num),
            "ogid": str(gid_num),
            "rdev": "00:00",
            "nametype": "CREATE",
            "cap_fp": "0", "cap_fi": "0", "cap_fe": "0",
            "cap_fver": "0", "cap_frootid": "0",
            "OUID": user, "OGID": user
        },
        "full_log": path_full
    }

    return syscall_doc, path_doc
