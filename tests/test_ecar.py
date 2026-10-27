"""Raw eCAR -> host-day columns with pid (B6). Synthetic records only."""
import gzip
import json

import pandas as pd

from ctit.eval import optc_redteam
from ctit.ingest import ecar, optc

H = "SysClient0201.systemia.com"


def _r(obj, action, ts, pid, ppid=400, actor="A", objid="O", **props):
    return {"object": obj, "action": action, "timestamp": ts, "hostname": H, "pid": pid, "ppid": ppid,
            "actorID": actor, "objectID": objid, "principal": "SYSTEMIACOM\\zleazer", "properties": props}


RECS = [
    _r("PROCESS", "CREATE", "2019-09-23T11:23:54.100-04:00", 1284, actor="P", objid="C",
       image_path="\\Device\\HarddiskVolume1\\Windows\\System32\\cmd.exe", command_line="cmd.exe /c whoami",
       parent_image_path="\\Device\\HarddiskVolume1\\Windows\\explorer.exe"),
    _r("FILE", "READ", "2019-09-23T11:23:54.200-04:00", 1284, actor="C", image_path="cmd.exe"),
    _r("PROCESS", "OPEN", "2019-09-23T11:23:54.300-04:00", 1284, actor="C", objid="C", image_path="cmd.exe"),
    _r("REGISTRY", "ADD", "2019-09-23T11:23:55-04:00", 1284, actor="C", image_path="cmd.exe",
       key="\\REGISTRY\\MACHINE\\SOFTWARE\\X", value="v"),
    _r("FLOW", "START", "2019-09-23T11:23:56-04:00", 999, actor="Z",
       image_path="\\Device\\HarddiskVolume1\\x.exe", dest_ip="1.2.3.4", dest_port="443", l4protocol="6"),
    _r("USER_SESSION", "RDP", "2019-09-23T11:23:57-04:00", -1, actor="S", image_path="System"),
]


def test_convert_mapping_pid_and_resolution():
    rows = list(ecar.convert(RECS, ecar.ProcessTable(), stats := __import__("collections").Counter()))
    assert [r["event_id"] for r in rows] == [1, 10, 12, 3, 4624]
    assert stats["FILE/READ:dropped"] == 1
    create, opn, reg, flow, rdp = rows
    assert create["pid"] == 1284 and create["ppid"] == 400 and create["cmdline"] == "cmd.exe /c whoami"
    # bare image on a non-create row resolves through the actor's UUID (the created process C)
    assert opn["image"] == "cmd.exe" and opn["image_resolved"].endswith("\\cmd.exe")
    assert opn["target_image"].endswith("\\cmd.exe")
    assert reg["target_object"].endswith("\\X\\v") and reg["registry_event_type"] == ""
    assert flow["protocol"] == "tcp" and flow["dest_port"] == "443"
    assert rdp["logon_type"] == 10 and rdp["pid"] is None


def test_convert_file_reads_through_optc_and_labels(tmp_path):
    src = tmp_path / "sysclient0201.json.gz"
    with gzip.open(src, "wt") as f:
        f.writelines(json.dumps(r) + "\n" for r in RECS)
    out = tmp_path / "SysClient0201.systemia.com.parquet"
    s = ecar.convert_file(src, out, chunk=2)
    assert s["rows"] == 5 and s["event_ids"] == {1: 1, 3: 1, 10: 1, 12: 1, 4624: 1}
    df = pd.read_parquet(out)
    assert str(df["ts"].dt.tz) == "UTC" and df["ts"].iloc[0] == pd.Timestamp("2019-09-23T15:23:54.1Z")
    frame, _ = optc.to_frame(df, restore_bare=True, carry=("pid",))
    frame = frame.rename(columns={"pid": "ProcessId"})
    labels = pd.DataFrame({"host": ["sysclient0201"], "pid": [1284],
                           "start": [pd.Timestamp("2019-09-23T15:23:54Z")],
                           "end": [pd.Timestamp("2019-09-23T15:23:55Z")]})
    flag = optc_redteam.label_events(frame, labels)
    by_eid = dict(zip(frame["EventID"], flag))
    assert by_eid[1] and by_eid[10] and by_eid[12] and not by_eid[3] and not by_eid[4624]
