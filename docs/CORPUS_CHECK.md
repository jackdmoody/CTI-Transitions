# Corpus check: open benign Windows corpus for W2

Started 2026-10-26 19:34 EDT, finished 21:35 EDT. Disk free at start: 439 GiB. Power: AC throughout (never on battery). Addenda 1, 2 and 4 from Jack are folded in.
Purpose: measure candidate open corpora (Splunk BOTS v1/v2/v3, DARPA OpTC) against the pass criteria below and recommend one. This doc does not switch the corpus or change the spec.

Pass criteria: ≥25 Windows hosts with Sysmon (or eCAR process events) with real volume; ≥2 roles with ≥5 hosts each; ≥2 days benign or a clean pre-attack window; license allows releasing derived artifacts.

Every number below comes from the data on this machine unless marked otherwise.

## Results (finished 2026-10-26)

### 1. Original criteria (≥25 Windows Sysmon hosts, ≥2 roles with ≥5 hosts, ≥2 benign days, license)

| corpus | Windows hosts w/ Sysmon (or eCAR) | w/ Security | median events/host (Sysmon/eCAR) | days | clean hosts after attack exclusion | roles with ≥5 hosts | passes? |
|---|---|---|---|---|---|---|---|
| BOTSv1 | 3 with process-level Sysmon (1,760 incl. EID-3-only hosts) | 1,760 | 282 (all) / 50k–130k (the 3) | 29 (2 for the 3 Sysmon hosts) | not determined | not determined (1,759 `*srv` + 1 `*desk` by name) | **no** |
| BOTSv2 | 8 | 9 | 145,978 (31 days) | 31, but one replayed day (see Phase 3) | 0 hosts never touched; 16–17 benign days per host, all one replayed day | 1 (7 `wrk-*` workstations) | **no** |
| BOTSv3 | 8 | 9 | 607.5 | 0.27 (6.5 h on 2018-08-20) | not determined | 1 (8 `*-L` laptops) | **no** |
| OpTC (local conversion) | 473 (eCAR) | — (eCAR has a few 4624/4672) | 2.73M rows/host-day (22 Sep) | 4 benign (19–22 Sep) | 446 never-targeted hosts | not determined (hostnames carry no role) | **hosts/days yes; roles not determined; format mismatch (Addenda 1–2)** |

License: BOTS v1/v2/v3 are CC0 1.0 (LICENSE file in each archive); OpTC is public domain ("Distribution A", DARPA README); ATLASv2 terms not checked this session.

### 2. Revised criteria (Addendum 4: pooled baseline; benign window counts; roles informational)

Window = DRIFT session (`sessionize_host`, τ fitted per host on the benign time used, clamped to DRIFT's [30 s, 12 h]). Scorable = ≥2 tagged events (spec §3; fewer are skipped). Extended mapper, frozen v2. For OpTC, the 719-rule shared subset on normalized values.

| corpus | benign time used | DRIFT sessions | scorable sessions (≥2 tagged) | ≥500 (1% FPR)? | ≥5,000 (0.1% FPR)? | realism (dataset's own docs) |
|---|---|---|---|---|---|---|
| **OpTC** | 446 never-targeted hosts × 19–22 Sep | **2,883** (median 3 per host over 4 days; τ = 30 s on most hosts) | ≈ all: 50/50 sampled host-day sessions scorable (22 Sep) | **yes** (2,883) | **no** | README is silent on how benign activity was generated. STRATA-E notes find scripted range-management on 40/40 sampled hosts. |
| **ATLASv2** | 2 hosts × 5 benign days (15–19 Jul 2022) | 11,130 (Sysmon) / 30 (Sysmon+Security) | **15** / 9 | no | no | **Real users:** "two researchers use the victim machines as their primary work stations" (ATLASv2 paper, arXiv:2401.01341). |
| **BOTSv2** | 8 Sysmon hosts × 16–17 non-attack days | 145,197 (Sysmon) / 156,691 (+Security) | **0** / 587 (451 on the DC, mercury) — all on one day replayed ~16× | no (Sysmon); +Security 587 raw, ~37 distinct | no | No benign-generation doc. Data: one fixed day replayed (Phase 3). |
| **BOTSv3** | 8 laptops × 6.5 h (attack window **not** excluded: not determined) | 620 (Sysmon) / 226 (+Security) | **12** / 26 | no | no | No benign-generation doc. |

Appendix variant (spec: fixed windows of 8 tagged events), for comparison:
- ATLASv2: 10 (Sysmon).
- BOTSv3: 9 (Sysmon).
- BOTSv2: 1,021 (Sysmon) and 23,845 (+Security), but ÷~16 for distinct content.
- OpTC: 19,074 on the 50-host sample day, from 152,766 tagged events.

On OpTC, ~99% of those tags come from the two eCAR artifacts in Addenda 1–2.

**Why the scorable counts are so low on the Sysmon corpora:**
- **Few tags:** the frozen extended mapper tags 1e-4 to 1e-3 of benign Sysmon events.
- **Short sessions:** τ hits DRIFT's 30 s floor, so sessions are short (BOTSv2: 482k Sysmon events in 145k sessions).
- **Result:** few sessions hold 2 tagged events.
- **OpTC is the opposite:** the eCAR stream is so dense that a host-day is one session, and artifacts tag every one.

Neither regime gives windows like BRiMS's. This is a property of window definition × mapper × corpus, not something a different corpus alone fixes; see the recommendation.

## Method notes

- **BOTSv1:** read from the official json-by-sourcetype exports. Every event keeps `_raw`. Host = Splunk `host` field. Time = Splunk `_time`, converted from MDT to UTC.
- **BOTSv2/v3, no Splunk:** `ctit/ingest/bots.py:iter_journal` decodes each bucket's `rawdata/journal.gz`. The format was reverse-engineered here: string-table opcodes for host/source/sourcetype, a state opcode that selects the active host/source/sourcetype and the event base time, then event records. It is checked against Splunk's own metadata: for **every** BOTSv3 bucket (17 of 17, including one `DISABLED-` bucket of 2 events), the decoded per-host event counts equal `Hosts.data` exactly. So per-sourcetype host attribution and event times come straight from the journal and are reliable. Event time = the journal's base time (UTC epoch seconds).
- Scratch scripts that produced the numbers live in the session scratchpad, not the repo. The reusable part is `ctit/ingest/bots.py`, tested in `tests/test_ingest_bots.py` on a synthetic journal and synthetic records.

## Phase 1: BOTSv1

Files: `data/bots/v1/botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz` (145 MB) and `botsv1.WinEventLog-Security.json.gz` (1.6 GB). Span for both: 2016-08-01 00:00 to 2016-08-28 23:59 UTC (29 calendar days in MDT).

| sourcetype | events | distinct hosts | events/host min / median / max |
|---|---|---|---|
| XmlWinEventLog Sysmon | 830,389 | 1,760 | 220 / 282 / 130,353 |
| WinEventLog:Security | 14,218,920 | 1,760 | 3,369 / 7,076 / 147,729 |

- **Sysmon EventCode distribution:** 3: 659,112; 7: 168,374; 2: 1,434; 1: 767; 5: 684; 6: 18.
- **Security EventCode top 20:** 4703: 4,315,911; 4689: 3,647,027; 4688: 3,642,895; 4634: 579,743; 4624: 579,580; 4672: 538,547; 4656: 441,429; 4674: 235,422; 4670: 67,070; 5140: 63,859; 5145: 55,023; 4673: 38,584; 4985: 6,742; 4776: 2,384; 4664: 1,993; 4648: 1,206; 4799: 542; 4611: 412; 4616: 216; 4801: 214.
- **The 1,760 hosts split into two very different populations.**
  - 3 hosts have full Sysmon: we8105desk (130k events), we1149srv (90k), we9041srv (50k). They are the only hosts with Sysmon EventCode 1 or 7. Their Sysmon covers exactly 2 days, 2016-08-10 and 2016-08-24.
  - The other 1,757 hosts (all named `weNNNNsrv`; the full set is 1,759 `*srv` + 1 `*desk`) have **only Sysmon EventCode 3** (network connect), about 20 events per day across all 29 days. Their top (image, destination) pairs are the same across hosts: dns.exe, System, svchost.exe and lsass.exe to 192.168.250.20/.100.
  - In Security, all 1,760 hosts log 4688 (median 1,827 per host over 29 days). Across the 1,752 small `*srv` hosts the median is 34 distinct command lines per host, and the most common ones are on every host: Splunk forwarder helpers (splunk-powershell.exe, splunk-netmon.exe, …).
  - This looks like templated background hosts, not 1,757 real, independently used machines. Whether they are synthetic is **not determined** from the data alone; the BOTSv1 docs don't say.
- **Verdict:** fails the Sysmon criterion: 3 hosts with process-level Sysmon, 2 days. A Security-only reading (1,760 hosts with 4688) is possible, but the per-host diversity above makes it a weak benign baseline. I'd not use it for role-indexed baselines without understanding how those hosts were generated.

### Phase 1 pipeline smoke test (both mappers)

Converter: `ctit/ingest/bots.py` (`read_v1` → `canonical.to_frame`). Sysmon events are parsed from the `_raw` XML; Security events from the classic `_raw` text, with labels renamed to XML names. Input: all 830,389 Sysmon events (1,760 hosts) plus Security for 23 hosts (the 3 Sysmon hosts and 20 `*srv` hosts drawn with `random.Random(0)`), 242,669 events. The full 14.2M-event Security file was not mapped: an in-memory SQLite run at that size doesn't fit in 24 GB.
Frame: 1,073,058 rows × 151 columns, saved as `data/bots/v1/canonical/smoke.parquet`.

| mapper | K (Sysmon) | K (all sources) | Sysmon tag rate | Security tag rate |
|---|---|---|---|---|
| extended (frozen v2) | 7: Execution, Persistence, Privilege Escalation, Defense Evasion, Discovery, Command and Control, Impact | 9: the 7 + Credential Access, Lateral Movement | 0.0096% (80 events) | 3.97% (9,625) |
| BRiMS (DRIFT) | 2: Execution, Defense Evasion | 3: + Privilege Escalation | 0.38% (3,135) | 3.67% (8,904) |

Per-tactic benign tag rate (fraction of that source's events):
- **Extended, Sysmon:** Persistence 3.5e-5, Execution 3.4e-5, Discovery 7e-6, Impact 7e-6, Defense Evasion 6e-6, Privilege Escalation 4e-6, C2 4e-6.
- **Extended, Security:** Impact 3.95e-2, Credential Access 5.8e-5, Defense Evasion 4.1e-5, Discovery 2.9e-5, Execution 2.5e-5, Lateral Movement 8e-6, Privilege Escalation 4e-6.
- **BRiMS, Sysmon:** Execution 2.0e-3, Defense Evasion 1.7e-3. **BRiMS, Security:** Privilege Escalation 3.67e-2.

Notes:
- **One rule makes up 99.5% of extended Security tags:** "User Logoff Event" (`win_security_user_logoff.yml`, EventID 4634/4647 → Impact), 9,580 of 9,625. On Windows Security it's a near-constant benign stream. This is a property of the frozen mapper, not of BOTS. No change made; listed under "Not determined / open" below.
- **Converter bug found and fixed in this phase.** Classic-text Security rows first had only `ComputerName`. DRIFT's `normalize_schema` reads `Computer` before `Hostname`, so every Security row got a null host and was dropped, and `build_tokens` then failed on an empty frame. The converter now sets `Computer`, as XML-rendered events do. DRIFT is unchanged. The smoke frame was patched the same way (`Computer` ← `ComputerName`) rather than re-read.

## Phase 2: BOTSv3

`data/bots/v3/botsv3_data_set.tgz` (335 MB; 352 entries, no absolute or `..` paths). Extracted to `data/bots/v3/extracted/`. License file: CC0 1.0. Index `botsv3`: 17 buckets (one `DISABLED-`), 107 sourcetypes, 31 hosts.

- **(a) All hosts, by event count:** hoth 382,718; serverless 333,697; gacrux.i-0920036c8ca91e501 175,345; mars.i-08e52f8b5a034012d 158,512; BSTOLL-L 101,918; matar 84,390; ip-172-16-0-109.ec2.internal 83,673; FROTHLY-FW1 80,192; splunkhwf.froth.ly 78,478; BTUN-L 76,371; PCERF-L 65,184; FYODOR-L 65,138; MKRAEUS-L 59,425; JWORTOS-L 55,550; ABUNGST-L 52,335; gacrux.i-06fea586f3d3c8ce8 43,523; gacrux.i-09cbc261e84259b54 42,000; gacrux.i-0cc93bade2b3cba63 32,261; SEPM 20,383; BGIST-L 18,314; splunk.froth.ly 17,769; ip-172-31-36-235 1,073; ip-172-16-0-13 418; ip-172-16-0-145 415; ip-172-16-0-127 413; console.us.code42.com:443 378; ip-172-31-12-76 222; ip-172-16-0-178 173; ntesla 2; OD-FM-NA-i-0ad2d665d4bdace22.amazonaws.com 1.
  - Top sourcetypes: syslog 283,976; stream:ip 227,872; osquery:results 219,997; stream:dns 218,456; aws:cloudwatchlogs:vpcflow 183,354; stream:udp 157,960; winhostmon 129,679; aws:cloudwatchlogs 115,145; stream:tcp 84,031; osquery:info 83,961; cisco:asa 80,192; wineventlog:security 46,469; …; xmlwineventlog Sysmon 9,212.
- **(b) Per-sourcetype attribution:** this is determined, from the journal; see Method notes.
  - Sysmon (8 hosts): FYODOR-L 4,126; ABUNGST-L 1,479; BSTOLL-L 1,048; PCERF-L 743; BGIST-L 472; BTUN-L 468; MKRAEUS-L 453; JWORTOS-L 423. Median 607.5.
  - Security (9 hosts): BSTOLL-L 23,812; MKRAEUS-L 4,097; PCERF-L 4,092; BTUN-L 3,839; BGIST-L 3,102; ABUNGST-L 2,680; FYODOR-L 2,460; JWORTOS-L 2,381; SEPM 6. Median 3,102.
  - Sysmon EventCodes: 3: 5,072; 1: 3,616; 11: 172; 13: 162; 15: 50; 12: 48; 5: 45; 6: 40; 4: 5; 2: 1; 8: 1.
  - Security top EventCodes: 5156, 4689, 4688 (7,427), 4673, 5157, 4670, 4957, 4985, 4663, 4659, 4945, 4624, 4627, 4672, 5061, 4799.
- **(c) Windows endpoints:** 8 laptops (`*-L`), all with Sysmon and Security, plus SEPM, a Symantec EP manager server with Windows System/Application logs and 6 Security events. Everything else is AWS (EC2 `ip-*`, `gacrux.*`, `mars.*`, serverless/Lambda), Linux (hoth, matar, splunk*), the Cisco ASA firewall, or SaaS (code42, O365).
- **Time:** every Windows event falls on 2018-08-20, between 09:00 and 15:27 UTC (about 6.5 hours).
- **Verdict:** fails: 8 Windows hosts, 1 role, under 1 day.

## Phase 3: BOTSv2 (full, 16.4 GB)

`data/bots/v2/botsv2_data_set.tgz`: 17,609,041,137 bytes, MD5 `fd2673726c96e97a39fc03119d6686c6` (matches the README). 1,060 entries, no absolute/`..` paths or links. Extracted to `data/bots/v2/extracted/` (23 GB). Index `botsv2`: 57 buckets, 226,337,681 events, 25 hosts, 105 sourcetypes.
- **Decoder check:** every bucket's decoded per-host counts equal `Hosts.data` (57/57).
- **Hosts (all sourcetypes):**
  - Windows: wrk-btun, wrk-ghoppy, wrk-aturing, wrk-klagerf, wrk-abungst, wrk-fmaltes, wrk-bgist, venus, mercury.
  - Not Windows event logs: cassiopeia, MACLORY-AIR13 / MACLORY-AIR13S.local (macOS), jupiter, gacrux, growler, jabbah, eridanus, matar, uranus, altair, neptune, kutekitten, one EC2 host, one `OD-FM-NA` host, `bots2017` (2 events).
- **Sysmon (8 hosts, 2017-08-01..31, all 31 days):**

  | host | events |
  |---|---|
  | wrk-aturing | 163,282 |
  | wrk-fmaltes | 157,764 |
  | wrk-btun | 157,086 |
  | wrk-ghoppy | 150,348 |
  | wrk-bgist | 141,608 |
  | wrk-abungst | 140,475 |
  | wrk-klagerf | 123,383 |
  | venus | 72,437 |

  Median 145,978. EventCodes: 1: 568,895; 5: 504,652; 2: 22,300; 11: 5,771; 3: 4,576; 6: 171; 13: 15. No 7, 8, 10 or 22.
- **Security (9 hosts):**
  - mercury 1,605,899. It is the only host logging 4768/4769 (14,012 / 9,170), so it is the DC.
  - The 8 Sysmon hosts: 56,645–80,821 each.
  - Top EventCodes: 4688 618,568; 4634 400,158; 4624 399,097; 4672 373,520; 4776 339,472; 4625 16,577; 4768 14,012; 4769 9,170.
- **The benign background is one day replayed:**
  - On each Windows host, 16–17 of 31 days have exactly the same Sysmon and Security counts (wrk-aturing: 4,409 Sysmon / 2,171 Security; venus 1,609 / 1,627; mercury Security 41,672).
  - Hashing each day's events on (EventID, Image, CommandLine, ParentImage, TargetFilename, NewProcessName, Subject/TargetUserName, time of day) gives **one identical signature for all 16 such days** on wrk-aturing (Sysmon and Security) and all 17 on venus. Only Sysmon record IDs, ProcessGuid/ProcessId and UtcTime differ; Security even repeats RecordNumber.
  - Every other day = that baseline + the attack-only subset's events, to the event (Phase 4).
  - So BOTSv2 has **one distinct benign day per Windows host**. A fit/test split by time would test on copies of the fit data.
- **Verdict:** fails. 8 Sysmon hosts, 1 role with ≥5 hosts (7 workstations), and effectively 1 benign day.

## Phase 4: attack contamination (v2, v3)

- **Official repos:** `splunk/botsv2` and `splunk/botsv3` contain only README.md and LICENSE. They list sourcetypes and required apps but **no attack hosts, times or ground truth**.
- **BOTSv2, from data:**
  - I downloaded the official "attack-only" subset (`botsv2_data_set_attack_only.tgz`, MD5 `6ea8f15c…` matches; 17 buckets, 68,887,597 events, 23 hosts). The README calls it the attack-relevant data with "minimal non-attack-related" data.
  - Its Windows events span 2017-08-03 18:00 to 2017-08-29 11:11 UTC.
  - It covers **all 9 Windows hosts** on 14–15 days each: 03, 05, 08, 10, 11, 12, 15, 16, 18, 19, 24, 25, 26, 29 Aug; plus 07 Aug on wrk-btun and wrk-klagerf, and 27 Aug on wrk-aturing.
  - On those days, full = replayed baseline + attack-only, exactly. The heaviest days are 18–19 Aug (wrk-aturing 19 Aug: 14,254 attack-only Sysmon events) and 24–26 Aug.
  - **Clean Windows hosts: 0** of 9 are untouched.
  - **Clean pre-attack window:** 2017-08-01 00:00 to 2017-08-03 18:00 UTC for every host, plus 16–17 non-attack-only days per host. All of it is the replayed day.
  - Caveat: "attack-only" is Splunk's curated subset, not labelled ground truth. That it equals the attack windows is **not determined**.
- **BOTSv3:** no attack-only subset and no ground truth in the repo. All Windows data lies in one 6.5 h span; the attack window and touched hosts are **not determined**.

## Phase 5: raw event extraction without Splunk

- **Works, end to end, with no Splunk install:** `ctit/ingest/bots.py` decodes bucket journals → `to_record` (Sysmon XML; classic Security text) → `canonical.to_frame`.
  - BOTSv2: all Sysmon + Security for the 9 Windows hosts, 3,284,830 records. Every scan count matches; 0 skipped. Written to `data/bots/v2/canonical/` (one parquet per bucket).
  - BOTSv3: all 9 Windows hosts, 55,681 records = 9,212 Sysmon + 46,469 Security. Written to `data/bots/v3/canonical/`.
- **Both mappers on one host** (wrk-aturing, all 31 days: 163,282 Sysmon + 80,821 Security):

  | mapper | K (Sysmon) | K (all) | Sysmon tag rate | Security tag rate |
  |---|---|---|---|---|
  | extended | Defense Evasion, Credential Access, C2 | + Impact | 1.25% (2,040; 2,033 are "Suspicious SYSTEM User Process Creation") | 0.042% |
  | BRiMS | Execution, Defense Evasion | + Privilege Escalation | 3.29% | 0.66% |

  "Tor Client/Browser Execution" fires 4 times on attack-only days.

## Phase 6: OpTC local check (read-only)

Found an existing conversion from the STRATA-E eval work. Nothing there was modified; at most one host-day was read, plus parquet footers.

- **Converted data:** `$CTIT_OPTC_ROOT/<date>/SysClientNNNN.systemia.com.parquet` (default `data/optc/canonical/`), one file per host-day, 37 GB. Written by `adapters/ecar_to_strata.py` in the separate STRATA-E evaluation project, with the mapping in its `protocol/ecar_to_sysmon_map.csv`.

  | day | host files | rows/host min / median / max |
  |---|---|---|
  | 2019-09-19 | 473 | 1.58M / 2.90M / 3.96M |
  | 2019-09-20 | 473 | 0.58M / 2.16M / 2.48M |
  | 2019-09-21 | 473 | 2.59M / 2.91M / 3.34M |
  | 2019-09-22 | 473 | 2.53M / 2.73M / 3.22M |
  | 2019-09-23 | 475 | 1.59M / 2.69M / 3.02M |
  | 2019-09-24 | 229 | 2.53M / 2.62M / 2.87M |

  A day runs 04:00 to 03:59 UTC (local midnight, EDT).
- **Raw and sample eCAR also present:** a raw eCAR directory outside the repo (622 MB, 2019-09-19..24) and a sample directory whose index `$CTIT_OPTC_INDEX` points into (1.6 GB, a few hosts for 2019-09-16..22). Format: gzipped eCAR JSON lines.
- **Format:** a Sysmon-like frame, not the W2 canonical frame. Columns: `ts, host, event_id, image, parent_image, cmdline, user, integrity_level, signed, hash_sha256, dest_ip, dest_port, protocol, target_image, target_object, ticket_encryption_type, logon_type, target_filename, registry_event_type, image_resolved`.
  - eCAR objects map to Sysmon/Security IDs, e.g. PROCESS CREATE → 1, FLOW START → 3, MODULE LOAD → 7, PROCESS OPEN → 10, FILE CREATE → 11, REGISTRY → 12/13, TASK → 4698/4699/4702, USER_SESSION → 4624/4634/4672.
  - One host-day (SysClient0051, 2019-09-19, 3.2M rows): 3: 2.12M; 10: 766k; 7: 232k; 11: 48k; 8: 14k; 23: 13k; 13: 10k; **1: 7,078**; 5: 7,030; 12: 5.8k; 4624: 206; 4672: 189; 4702: 180.
- **PROCESS fields:**
  - Kept: image path (`image`, a `\Device\HarddiskVolume1\...` path, 100% filled on process creates), command line (`cmdline`, 99.96% filled), parent image path (`parent_image`, 99.93% filled).
  - **Not kept:** `pid`, `ppid`, eCAR process UUIDs (`actorID`/`objectID`). The raw eCAR has all of these.
- **FLOW fields:**
  - Kept: `dest_ip`, `dest_port`, `protocol`.
  - **Not kept:** `src_ip`, `src_port`, `direction`; the raw eCAR has them. FLOW MESSAGE and FLOW OPEN are dropped, by design.
- **Roles:** every hostname is `SysClientNNNN.systemia.com`. STRATA-E's own proposed role file (`reports/phase1b_proposed/optc_role_patterns.yaml`) has no patterns and puts every host in "workstation". The local conversion has no DC or server hostnames. Roles are **not determined**. They would have to be inferred from behaviour (e.g. Kerberos/4769-style activity is absent from the eCAR map) or from OpTC documentation.
- **Attack days and hosts:** taken from Jack's STRATA-E artifacts, read-only.
  - `protocol/splits.yaml` (signed v1.1) records red-team days 2019-09-23/24/25, "verified: Inria labels sc1/sc2/sc3".
  - `$CTIT_OPTC_LABELS/redteam_hosts.json` (default `data/optc/labels/`): Inria corrected-release labels, commit `644f41f`. 29 target hosts in total (sc1 17, sc2 10, sc3 2).
  - So **19–22 Sep (4 days) are pre-attack for all 473 hosts**, and 446 of the 473 hosts in the 22 Sep conversion are never red-team targets (27 targets are in the population; SysClient0005 and 0010 are not).
  - Caveat from the same file: 19 Sep is truncated in parts of the sample (it ends ~16:21 EDT for some hosts).
  - The schedule was not re-derived from raw labels in this session.

## Addenda 1–2: OpTC vs Sysmon format mismatch

**Question.** W2 splices tactic tokens from Sysmon-format technique recordings (`data/eval/tactic_signatures.parquet`: 170 recordings, Splunk Attack Data full-XML plus OTRF atomic) into benign streams. If the benign corpus is OpTC (eCAR converted to a Sysmon-like frame), the same frozen mapper sees two different data formats. Rules can fire on one side and be unable to fire on the other.

### Converter: `ctit/ingest/optc.py` (new; tested in `tests/test_ingest_optc.py`)
- **Input and output.** Reads the STRATA-E host-day parquet read-only. Writes the W2 canonical frame with Sigma field names per event ID.
- **Field mapping:**

  | event ID | Sigma fields |
  |---|---|
  | 1 | Image, ParentImage, CommandLine, User |
  | 3 | Image, User, DestinationIp, DestinationPort, Protocol |
  | 5, 7 | Image, User |
  | 8, 10 | SourceImage, TargetImage, SourceUser |
  | 11, 23 | Image, User, TargetFilename |
  | 12, 13 | Image, User, TargetObject, EventType |
  | 4624 | LogonType |
  | 4634, 4672, 4698, 4699, 4702, 7045 | EventID only |

- **Fields the conversion lacks.** No `ImageLoaded`, `Hashes`, `IntegrityLevel`, `OriginalFileName`, `ParentCommandLine`, `CurrentDirectory`, `Description/Product/Company`, `GrantedAccess`, `CallTrace`, `Details`, `QueryName`, `PipeName`, `Initiated`, `SourcePort`. Fill rates were measured on SysClient0052, 2019-09-22; `hash_sha256`, `integrity_level` and `signed` are 0% filled.
- **Value normalization to Sysmon conventions:**
  - `\Device\HarddiskVolumeN\` → drive letter. The letter is derived per host, never assumed: a process-create row votes N→X when its command line starts with `X:\<rest>` and its image is `\Device\HarddiskVolumeN\<rest>`. The volume holding `\Windows\System32` is logged.
  - `\REGISTRY\MACHINE\` → `HKLM\` and `\REGISTRY\USER\` → `HKU\`.
  - Volumes with no evidence are left unchanged. The per-host log is at `data/optc_check/2019-09-22/drive_maps.json`.

### Format-sensitive rule conditions (Image, ParentImage, TargetFilename, TargetObject)
Counted from the frozen `compiled_rules.jsonl` SQL. LIKE `'%x'` = endswith, `'%x%'` = contains, `'x%'` = startswith, no wildcard / `=` / `IN` = equals.

| field | rules referencing it | endswith/contains only | format-sensitive* |
|---|---|---|---|
| Image | 1,196 | 1,027 | 169 |
| ParentImage | 244 | 189 | 55 |
| TargetFilename | 178 | 130 | 48 |
| TargetObject | 245 | 231 | 14 |
| **any of the four** | **1,504** | 1,243 | **261** |

\* Format-sensitive = the rule has a startswith, equals or anchored-regex condition on the field (237 rules), or a literal holding a drive path (`C:\`), a hive prefix (`HKLM\`/`HKU\`/`HKCU\`/`HKCR\`) or `\REGISTRY\` (244 rules). 261 rules meet either test.

Condition counts by operator:
- **Image:** endswith 3,266; contains 575; startswith 397; equals 351.
- **ParentImage:** endswith 509; contains 99; equals 66; startswith 25.
- **TargetFilename:** endswith 843; contains 448; startswith 63; equals 13; regex 7.
- **TargetObject:** contains 685; endswith 351; equals 6; startswith 4.

Most matches are endswith/contains and would survive eCAR's kernel path forms. The 261 sensitive rules would not fire on unnormalized OpTC values.

### Rule evaluability by Sigma category
A rule is **field-evaluable** on a dataset if, for some (Channel, EventID) the rule accepts, every field it references is a non-null column in that data. OpTC fields come from the converter table above. Recording fields are the non-null columns per (Channel, EventID) across the 170 recordings the signature library uses.

| category | rules | OpTC-evaluable | recordings-evaluable | shared |
|---|---|---|---|---|
| process_creation | 2,314 | 465 | 1,617 | 465 |
| registry/registry_set | 203 | 47 | 203 | 47 |
| file/file_event | 161 | 155 | 155 | 155 |
| builtin/security | 137 | 2 | 110 | 2 |
| image_load | 99 | 0 | 97 | **0 (excluded)** |
| builtin/system | 59 | 0 | 2 | 0 |
| network_connection | 50 | 3 | 46 | 3 |
| registry/registry_event | 31 | 18 | 28 | 18 |
| dns_query | 22 | 0 | 22 | 0 |
| pipe_created | 16 | 0 | 16 | 0 |
| process_access | 14 | 0 | 13 | 0 |
| file/file_delete | 12 | 12 | 12 | 12 |
| create_remote_thread | 10 | 6 | 9 | 6 |
| driver_load | 10 | 0 | 10 | 0 |
| registry/registry_delete | 10 | 10 | 10 | 10 |
| registry/registry_add | 1 | 1 | 1 | 1 |
| other (file_access 7, create_stream_hash 5, sysmon 5, wmi_event 3, 6 singletons) | 26 | 0 | 14 | 0 |
| **total** | **3,174** | **719** | **2,365** | **719** |

- **The shared subset is every OpTC-evaluable rule:** 719 rules, all in the Sysmon variant. The 1,157 `security_4688` rules drop out because OpTC has no 4688; its process creates are Sysmon EID 1.
- **image_load:** 99 rules; 94 of them reference `ImageLoaded`. None is OpTC-evaluable, since OpTC EID 7 carries only the loading process. The whole category is excluded from the shared subset on both sides.
- **Process creation is the main loss:** 465 of 2,314 rules are OpTC-evaluable. Most others need `OriginalFileName` (1,144 rules), `ParentCommandLine`, `IntegrityLevel`, `Hashes`, or PE metadata. OpTC has none of these.

### K and benign tag rates under the shared subset (719 rules)

**Signature recordings** (170 recordings, 1,104,262 events):
- Full mapper: K = 13 (all but Reconnaissance), 11,145 tagged events.
- Shared subset: K = 11. It loses **Collection** (6 events under the full mapper) and **Exfiltration** (1); 6,777 tagged events (61%).
- Per-tactic tagged events, full → shared: Persistence 3,102 → 2,792; Execution 2,227 → 1,440; Defense Evasion 2,023 → 732; Privilege Escalation 1,287 → 142; Impact 898 → 859; Discovery 717 → 139; Lateral Movement 546 → 530; Credential Access 209 → 82; C2 68 → 6; Initial Access 41 → 35; Resource Development 20 → 20.

**OpTC benign day 2019-09-22**, 50 hosts drawn with `random.Random(0)` from the 446 never-targeted hosts:
- Volume: 143,326,880 Sysmon-mapped events plus 37,370 Security events.
- Tagging ran on 1,001,170 de-duplicated rows, each weighted by its event count. This is exact: identical rows get identical tags.
- Drive maps: on all 50 hosts, volume 1 → `C:` (it holds `\Windows\System32`), with no conflicting votes. De-duplicated and full-row votes agree on every host.

| | before normalization (kernel paths) | after normalization |
|---|---|---|
| K (OpTC) | 6: Resource Development, Execution, Privilege Escalation, Defense Evasion, Discovery, Impact | **same 6** |
| rules firing | 16 | 11 |
| Sysmon tag rate, all | 1.73e-3 | **1.07e-3** |
| Defense Evasion | 1.26e-3 | **6.0e-4** |
| Privilege Escalation | 4.63e-4 | 4.57e-4 |
| Discovery | 8.0e-6 | 8.0e-6 |
| Execution | 3.7e-6 | 1.6e-6 |
| Resource Development | 3.5e-7 | 4.9e-8 |
| Security tag rate (Impact, User Logoff 4634) | 7.59e-2 | 7.59e-2 |

- **The difference is material.** Unnormalized, "System File Execution Location Anomaly" fires on 91,858 events, because every system binary sits outside `C:\Windows\System32` in kernel form. After normalization it fires on 457. "Windows Binaries Write Suspicious Extensions" (1,740 events) and "EVTX Created In Uncommon Location" (1,162) disappear. **The normalized numbers are the ones used below.**
- **Residual mismatches that normalization does not fix.** These are eCAR semantics, not path format:
  1. **Bare image names.** 85,401 of 319,423 process creates (27%) have a bare image name (`PING.EXE`, `reg.exe`, `schtasks.exe`, …) instead of a path. This alone fires "Execution Of Non-Existing File" (high, Defense Evasion) 85,401 times: 99% of the normalized Defense Evasion rate.
  2. **Remote threads.** eCAR THREAD REMOTE_CREATE → EID 8 gives 691,609 "remote thread" events on 50 hosts. The top sources are System, vmtoolsd.exe, svchost.exe and cmd.exe, far beyond what Sysmon EID 8 logs. "Rare Remote Thread Creation By Uncommon Source Image" fires 62,911 times: essentially all of the Privilege Escalation rate.
  3. **Unmapped values.** `\REGISTRY\A\` (application hives, 100,171 registry events) and `\Device\Mup\` (UNC, 1,756 file events) stay as-is. Whether Sysmon renders them the same way is not determined.
- **Comparison with the BOTSv1 Sysmon smoke test (full mapper):** 9.6e-5 there vs 1.07e-3 here. The OpTC benign tag rate is about 11× higher, driven by the two eCAR artifacts above, even after normalization and with a smaller rule set.

## Recommendation (W2 primary benign corpus)

**Decision for Jack, not made here.** Under the revised criteria (pooled baseline, roles informational), **no open corpus measured here gives ≥5,000 scorable DRIFT-session windows**, so none supports 0.1% FPR thresholds as the spec currently defines a window. Only OpTC clears 500.

**Recommended: OpTC as primary, conditional on three fixes. ATLASv2 as the realism robustness check. Neither BOTS version.**

1. **OpTC (primary).**
   - **For:** 446 never-targeted hosts × 4 benign days, public domain, and 2,883 DRIFT sessions (≥500, so 1% FPR is supportable). It is the only candidate at scale.
   - **Main risk: format mismatch.** Injected tokens come from Sysmon recordings; benign streams come from eCAR.
     - The 719-rule shared subset closes the *field* gap: same rule set on both sides, `image_load` excluded.
     - Value normalization closes the *path-form* gap: tag rate 1.73e-3 → 1.07e-3, same K.
     - **Neither closes the semantic gap:** 27% of process creates have bare image names, and eCAR emits far more remote-thread events than Sysmon. These two artifacts produce ~99% of benign Defense Evasion and Privilege Escalation tags. They also make essentially every OpTC session scorable. Detection on OpTC would partly measure eCAR quirks.
   - **Second risk: window shape.** DRIFT sessions are ~1 per host-day, because the stream never pauses 30 s, against minutes-long sessions on Sysmon corpora.
   - **Third risk:** scripted background (STRATA-E's own audit).
   - **Work, about 4–6 days:**
     1. Convert 446 hosts × 4 days with `ctit/ingest/optc.py` (½ day; roughly 25 GB under `data/`, scaled from the 37 GB six-day STRATA-E conversion — an estimate).
     2. Decide how to treat the two artifacts, e.g. drop eCAR EID 8 and resolve bare images from raw eCAR process records (1–2 days, needs Jack).
     3. Freeze the shared subset as a declared mapper variant and rebuild the signature library under it (1 day; a spec issue, below).
     4. Settle the window definition for OpTC (Jack).
     5. Rerun T1/K and the WP5 gate on OpTC (1 day).
2. **ATLASv2 (secondary, realism).**
   - **For:** real users (documented), Sysmon-native, so no format mismatch, and already ingested and tagged.
   - **Main risk: volume.** 2 hosts and 15 scorable sessions, so no FPR threshold is estimable; ATLASv2 Sysmon has only EID 1/5.
   - **Use:** qualitative and robustness only, e.g. score distribution of real-user windows vs OpTC windows.
   - **Work:** ½ day (sessions are already computed).
3. **BOTSv2 (not recommended).**
   - **Main risk, disqualifying:** one benign day replayed 16–17× per host. Time-split fit/test would test on copies of the fit data. Every Windows host is in the attack-only subset. 0 scorable Sysmon windows.
   - **Work if used anyway:** ~1 day (converter done). Only one distinct day can be used.
4. **BOTSv3 (not recommended).**
   - **Main risk:** 8 hosts, 6.5 h, attack window not determined, 12 scorable windows.
   - **Work:** none beyond what's done.
5. **BOTSv1 (not recommended).** 3 real Sysmon hosts on 2 days; the other 1,757 hosts look templated.

**Proposed SPEC_ISSUES entry.** Not filed; this session commits only the listed files. Jack to file or reject:
- **Problem:** "§3 Window = DRIFT session" yields too few scorable windows on every open corpus measured: 0–15 on Sysmon corpora, ~2.9k day-long windows on OpTC. The 0.1% FPR metric (§6) is unreachable.
- **Options:**
  - (a) Promote the appendix's fixed tagged-event windows (k = 8) to primary for public-corpus runs. OpTC sample: 19,074 windows on 50 host-days; ATLASv2 10; BOTSv3 9.
  - (b) Drop the 0.1% FPR metric for public corpora.
  - (c) Keep sessions but sessionize on process-creation events only.
- Each changes a metric definition, so it needs Jack's sign-off before any scoring.

## Not determined / open

| item | why | what would resolve it |
|---|---|---|
| BOTSv1: are the 1,757 EID-3-only `weNNNNsrv` hosts synthetic? | Data shows near-identical per-host content; docs silent | BOTS authors / BOTSv1 build notes |
| BOTSv2/v3 per-host attack ground truth and exact windows | Official repos have only README/LICENSE; attack-only is a curated subset, not labels | BOTS CTF question/answer sets (not public in these repos) or the authors |
| BOTSv3 attack window | No attack-only subset; all data in 6.5 h | Same as above |
| OpTC host roles | All hostnames are `SysClientNNNN`; local conversion has no DC/server names | OpTC network docs (e.g. ground-truth PDF / topology) or behavioural inference |
| OpTC benign generation (users vs scripts) | README silent; STRATA-E audit finds scripted range jobs | DARPA TC/OpTC reports |
| OpTC scorable fraction on 19–21 Sep | Tagged sessions measured on the 22 Sep sample only (50/50 scorable) | Run `optc.to_frame` + tagging on all 4 days |
| Sysmon rendering of `\REGISTRY\A\` and `\Device\Mup\` | Left unnormalized (100,171 + 1,756 events in the sample) | Sysmon docs or a Sysmon test VM |
| ATLASv2 license terms | Not checked this session | ATLASv2 repo / paper |
| "User Logoff Event" (4634/4647 → Impact) dominates Security tags | 99.5% of extended Security tags on BOTSv1, and the bulk of OpTC/BOTSv2 Security tags | Jack: mapper-review item (no mapper change made) |
