"""Draft visibility rows (spec §2.2) from each step's concrete process-creation artifacts.

For a CALDERA-style step the executor itself is a concrete Sysmon EID 1: powershell.exe
(executors psh/pwsh) or cmd.exe (cmd) with the step's command on the command line. Each
command line that starts with a known Windows tool also launches that tool as a child
process: a second concrete EID 1. Both mappers tag these synthesized events.
  visible_sysmon = y        the extended mapper tags an artifact with the step's own tactic
                   partial  artifacts exist (EID 1) but are tagged with another tactic, or untagged
                   n        no Windows executor command (nothing runs on the endpoint)
  drift_tactic   = the step's tactic if y; else the first tagged child-tool artifact's tactic,
                   else the executor's; else "—"
Only process creation is modelled. Registry, file, network and process-access artifacts are
not synthesized, so this under-states visibility. It is a DRAFT for Jack's review (CLAUDE.md
human gate), never a final label.
"""
from __future__ import annotations

import re

import pandas as pd

from ctit.eval.plans import Step
from ctit.map.coverage import brims_tag
from ctit.map.extended import tag as extended_tag

EXECUTOR_IMAGE = {
    "psh": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "psh,pwsh": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    "pwsh": r"C:\Program Files\PowerShell\7\pwsh.exe",
    "cmd": r"C:\Windows\System32\cmd.exe",
}
# The process that launches each step (CALDERA agent, Pupy, PoshC2, ...) and its exact
# wrapper flags differ between executions and are not part of the step, so the synthesized
# executor has no ParentImage and a minimal command line: only the step's own command can
# drive a rule match. (An earlier draft used a placeholder agent in C:\Users\Public, which
# set off a public-folder-parent rule on every step.)
TOOLS = {
    "arp", "at", "bitsadmin", "certutil", "cmd", "cmdkey", "cscript", "dsquery", "esentutl",
    "findstr", "forfiles", "hostname", "icacls", "ipconfig", "klist", "mshta", "nbtstat", "net",
    "net1", "netsh", "netstat", "nltest", "nslookup", "ping", "powershell", "qwinsta", "quser",
    "reg", "regsvr32", "route", "rundll32", "sc", "schtasks", "systeminfo", "takeown", "tasklist",
    "vssadmin", "wevtutil", "whoami", "wmic", "wscript", "xcopy", "robocopy", "expand", "makecab",
    "msiexec", "mstsc", "ntdsutil", "wusa", "attrib", "auditpol", "gpresult", "tree",
}
_TOKEN = re.compile(r"""^[&\s"']*([A-Za-z0-9_.\\:-]+?)(?:\.exe)?["']?(?:\s|$)""", re.IGNORECASE)


def artifacts(step: Step) -> list[dict]:
    """Synthesized Sysmon EID 1 events for one step (executor first, then child tools)."""
    if step.executor not in EXECUTOR_IMAGE or not step.command.strip():
        return []
    exe = EXECUTOR_IMAGE[step.executor]
    flat = " ".join(line.strip() for line in step.command.splitlines() if line.strip())
    shell = "powershell.exe " if "powershell" in exe.lower() or "pwsh" in exe.lower() else "cmd.exe /c "
    events = [{"Image": exe, "ParentImage": None, "CommandLine": shell + flat, "artifact": "executor"}]
    for line in step.command.splitlines():
        for part in re.split(r"[;|]|&&", line):
            m = _TOKEN.match(part)
            if m and m.group(1).split("\\")[-1].lower() in TOOLS:
                tool = m.group(1).split("\\")[-1].lower()
                events.append({"Image": rf"C:\Windows\System32\{tool}.exe", "ParentImage": exe,
                               "CommandLine": part.strip(), "artifact": f"child:{tool}"})
    return events


def _frame(rows: list[dict]) -> pd.DataFrame:
    df = pd.DataFrame(rows)
    df["_timestamp"] = pd.Timestamp("2020-01-01", tz="UTC") + pd.to_timedelta(range(len(df)), unit="s")
    df["Hostname"] = "victim"
    df["source"] = "sysmon"
    df["EventID"] = 1
    df["Channel"] = "Microsoft-Windows-Sysmon/Operational"
    df["UtcTime"] = df["_timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S.000")
    return df


def draft_rows(steps: list[Step], rules: list[dict] | None = None) -> pd.DataFrame:
    rows, events = [], []
    for s in steps:
        for e in artifacts(s):
            events.append({**e, "step_index": s.index})
    tagged_ext = tagged_brims = None
    if events:
        df = _frame(events)
        tagged_ext = extended_tag(df.drop(columns=["artifact", "step_index"]), rules)
        tagged_brims = brims_tag(df.drop(columns=["artifact", "step_index"]))
        df["ext_tactic"] = tagged_ext["tactic"].values
        df["ext_rule"] = tagged_ext["rule_id"].values
        # brims_tag re-sorts by host/ts; ts is unique per event here, so align on it.
        b = tagged_brims.set_index("ts")["tactic"]
        df["brims_tactic"] = df["_timestamp"].map(b).values
    for s in steps:
        ev = df[df["step_index"] == s.index] if events else pd.DataFrame()
        ext = [t for t in ev.get("ext_tactic", []) if t]
        brims = [t for t in ev.get("brims_tactic", []) if t]
        if ev.empty:
            vis, drift_tactic = "n", "—"
            why = "No Windows executor command: nothing runs on the endpoint."
        elif s.tactic in ext:
            vis, drift_tactic = "y", s.tactic
            hit = ev[ev["ext_tactic"] == s.tactic].iloc[0]
            why = f"EID 1 ({hit['artifact']}) tagged {s.tactic} by Sigma rule {hit['ext_rule']}."
        elif ext:
            # Child tools are the step's own action; the executor shell is common to every step.
            tagged = ev[ev["ext_tactic"] != ""]
            first = tagged.sort_values("artifact", key=lambda a: a.eq("executor"), kind="stable").iloc[0]
            vis, drift_tactic = "partial", first["ext_tactic"]
            why = (f"EID 1 ({first['artifact']}) tagged {first['ext_tactic']} (rule {first['ext_rule']}), "
                   f"not the step's {s.tactic}.")
        else:
            vis, drift_tactic = "partial", "—"
            why = "EID 1 exists but no Sigma rule tags it; nothing injected."
        rows.append({
            "step_id": s.step_id, "ability_id": s.ability_id, "name": s.name, "technique": s.technique,
            "plan_tactic": s.tactic, "expected_sysmon_events": "1" if not ev.empty else "",
            "visible_sysmon": vis, "expected_zeek_logs": "", "visible_zeek": "pending",
            "drift_tactic": drift_tactic, "brims_tactic": brims[0] if brims else "—",
            "n_artifacts": int(len(ev)),
            "rationale": why + " DRAFT: process creation only; registry/file/network/process-access "
                         "artifacts not modelled. Zeek pending WP14.",
        })
    return pd.DataFrame(rows)
