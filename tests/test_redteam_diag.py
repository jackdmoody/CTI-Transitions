"""B6 diagnostic classes on synthetic labels and process trees."""
import pandas as pd

from ctit.experiments import redteam_diag as d

T = lambda s: pd.Timestamp(f"2019-09-23T{s}Z")  # noqa: E731
LABELS = pd.DataFrame({"pid": [100], "start": [T("10:00")], "end": [T("11:00")]})
CREATES = pd.DataFrame({"ts": [T("10:10"), T("10:20"), T("12:00"), T("09:00")],
                        "pid": [200, 300, 200, 400], "ppid": [100, 200, 999, 100]})


def test_descendants_follow_the_tree_inside_the_interval():
    got = d.descendants(CREATES, LABELS)
    assert sorted(got["pid"]) == [200, 300]  # 400 was created by 100 before its label interval


def test_classes():
    tagged = pd.DataFrame({
        "ts": [T(x).tz_convert(None) for x in ("10:30", "11:30", "10:40", "12:30", "10:50", "13:00")],
        "pid": [100, 100, 300, 200, 555, 555],
        "malicious": [True, False, False, False, False, False]})
    cls = d.classify(tagged, LABELS, CREATES, pd.Timedelta("4h"))
    assert list(cls) == ["malicious", "labelled_pid_outside_interval", "descendant",
                         "elsewhere",  # pid 200 was re-created at 12:00 by an unlabelled parent
                         "inside_label_time", "elsewhere"]
