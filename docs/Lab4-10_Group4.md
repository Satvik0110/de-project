# Final Progress Report: Real-Time Cybersecurity Event Analytics Platform

**Group 4 (B23EE1094, B23ES1032, B23EE1041)**

## 1. Progress Overview

The platform is complete end to end: all five functional requirements from Lab 2 are built, integrated and tested. A red-team simulator runs real attacks against a lab network. The defended systems log what they observe. A stream processor detects attacks within milliseconds. Every event is retained in a Parquet data lake, and curated results go to a PostgreSQL warehouse. A SOC dashboard shows detections, multi-stage incidents with AI-written summaries, and pipeline health. The platform also grades its own detection against the simulator's ground truth. Since Lab 6–8 we integrated the simulator, finished both storage layers, and added incident correlation, AI summaries, the dashboard and the self-evaluation.

| Requirement (Lab 2) | Status | Delivered as |
|---|---|---|
| FR1 Attack simulation | Done | 10 attack and 2 benign-but-suspicious scenarios, plus continuous employee traffic |
| FR2 Stream processing | Done | Event-time windows, watermark, dedup, 10 rules, early alerts |
| FR3 Dual storage | Done | Parquet lake + PostgreSQL warehouse |
| FR4 Attack injection UI | Done | Red-team console |
| FR5 Monitoring dashboard | Done | SOC dashboard: alerts, incidents, scoreboard, pipeline health |

*Table 1. Functional requirements and their final status.*

## 2. Architecture

[Figure 1: architecture diagram]

*Figure 1. End-to-end architecture as built.*

**The defended systems write the security log, not the attacker.** The simulator only acts. The target web application logs every request it serves, and a network sensor logs every TCP connection, including scans of closed ports that the web application never sees. Both forward events through a log shipper with a bounded queue and retry-with-backoff, the role Filebeat plays in production [8]. Each simulated machine connects from its own address in 127.0.0.0/8, so source IPs are observed by the kernel rather than reported by the attacker. This mirrors how a real SIEM is fed: an attacker cannot misreport its own activity.

Events pass through a validating ingest API into Kafka, keyed by source IP. Every downstream service is an independent consumer group of the same topic: the stream processor, the lake writer, the warehouse writer and the dashboard. Kafka gives each group its own copy of the log [1], so slow storage never delays detection.

## 3. Key Data Engineering Decisions

| Decision | Why |
|---|---|
| Frozen event contract, validated twice (ingest and processor); invalid records go to a dead-letter topic with the reason | Schema drift surfaces at the door instead of corrupting the warehouse, and bad input is kept as evidence rather than dropped |
| Partition key = source IP | All events from one attacker stay in order on one partition |
| Event-time sliding windows (60 s, sliding every 10 s), stored as 10 s panes | Out-of-order arrival does not distort counts, and each event is stored once instead of six times |
| Watermark = newest event time − 10 s; dedup on `event_id` | Bounded lateness and bounded memory under at-least-once delivery [3] |
| Offsets committed only past events whose windows have closed, and only after outputs are acknowledged | After a crash, open windows are rebuilt from Kafka with nothing lost and nothing re-emitted |
| Deterministic `alert_id`, upserted in the warehouse | At-least-once delivery plus idempotent writes gives effectively-once results |
| Lake: Snappy Parquet in Hive partitions `year/month/day/hour`, by event time | Columnar scans with partition pruning [2]; a late event still lands in its true hour |
| Live data pushed over WebSocket from Kafka; history pulled with SQL | Addresses the FR5 risk from Lab 2 (dashboard polling slowing analytical queries) |
| Ground truth on a separate topic that the processor never reads | Detection cannot "see the answers" |

*Table 2. Key design decisions and their rationale.*

## 4. Detection, Correlation and AI Summaries

Ten deterministic rules cover credential attacks (brute force, password spraying, distributed and successful brute force), discovery (port scans, host sweeps), exploitation (signature matching for SQL, command, path-traversal, template and script injection), and denial of service (API floods, connection floods). Each rule is mapped to a MITRE ATT&CK technique and tactic [5]. Because every rule measures something that only grows within a window, an alert fires the moment a threshold is crossed instead of when the window closes. It is then updated in place as the count grows.

Alerts from the same attacker are chained into an incident while they keep arriving less than ten minutes apart (a session window [3]). An incident spanning two or more ATT&CK tactics is flagged as multi-stage and raised one severity level. A port scan, injection probes, a brute force and a successful login therefore appear as one critical intrusion rather than five unrelated alerts.

Fulfilling the AI objective from Lab 1, an LLM (Gemini) writes a plain-language summary of each incident: what happened, the likely goal, whether anything succeeded, and the first response actions. It runs outside the detection path, only once an incident has been quiet for a few seconds, and sends only alert metadata. A deterministic template takes over whenever the model is unavailable.

## 5. Self-Evaluation Against Ground Truth

Because the simulator knows what it launched, the platform grades its own detection. This is the standard way intrusion detection is evaluated on labelled traffic [6], built here into the running system. Precision and recall alone would be 100% by construction, since the attacks were designed to cross the thresholds. We therefore added three deliberately hard cases:

- **An evasive attack:** a low-and-slow brute force paced at one guess every 15 s, so no window reaches the threshold.
- **Two benign-but-suspicious cases:** an IT inventory scan from an administrator's host, and a morning login rush from many employees behind one office NAT address.

Each produces a miss or a false alarm with a known cause and mitigation.

We also report measures that do vary:
- **Mean time to detect (MTTD).**
- **The share of each attack already seen when the first alert fired**, computed by querying the Parquet lake.
- **The alert-reduction funnel:** events → alerts → incidents.

## 6. Results

Measured on a laptop (Intel i5-1335U, 8 GB RAM) at demonstration load: continuous background traffic plus attack bursts.

| Metric | Result |
|---|---|
| Detection latency (event ingested → alert) | p50 ≈ 50 ms, max ≈ 110 ms |
| Mean time to detect (campaign start → first alert) | 0.53 s |
| Advantage of early alerting | Alerts fire 60–70 s before the window would close |
| Attack seen before the first alert | 5% (injection) to ≈55% (scans), set by each rule's threshold |
| Alert reduction | 1,248 attack events → 40 alerts → 26 incidents |
| Recall / precision (including the hard cases) | 97.6% / 85%: the evasive attack is missed, both benign cases raise false alarms |
| False alarms on normal employee traffic | 0 |

*Table 3. Detection results.*

| Metric | Result |
|---|---|
| Completeness (shipped → Kafka → processed → lake) | 3,857 shipped = 3,857 in Kafka: 0 events lost |
| Data freshness per layer | Detection ≈ 70 ms · warehouse ≈ 1 s · lake ≤ 30 s (flush interval) |
| Storage efficiency | Parquet 5.2× smaller than the raw JSON |
| Duplicates under at-least-once delivery | Every event sent twice → counted once |
| Recovery after restart | Open windows rebuilt, 0 alerts re-emitted |
| Tests | 46 unit tests + 3 end-to-end suites, all passing |

*Table 4. Data pipeline results.*

One measurement drove a design change. Detection latency was initially 272 ms, most of it spent with the processor waiting to fill a 500-event batch at low traffic. Bounding that wait cut median latency to 41 ms without giving up batching under load.

## 7. Limitations and Next Steps

- **Scale:** the processor runs as a single instance, because the global watermark needs every partition. Scaling out would require a keyed shuffle or a framework such as Flink [4].
- **Throughput:** a load benchmark for maximum sustainable throughput is the next step [7].
- **Detection:** thresholds are static. The low-and-slow miss motivates longer windows or per-account baselines, which could be graded with the same scoreboard.
- **Storage:** the lake needs a compaction job for small files.

## 8. Project Metrics

[Sprint burnup, sprint burndown, sprint throughput, cumulative flow diagram, cycle time and velocity, to be added from the project tracker.]

## 9. References

1. Kreps, J., Narkhede, N., Rao, J. *Kafka: A Distributed Messaging System for Log Processing.* NetDB, 2011.
2. Melnik, S. et al. *Dremel: Interactive Analysis of Web-Scale Datasets.* PVLDB 3(1), 2010.
3. Akidau, T. et al. *The Dataflow Model.* PVLDB 8(12), 2015.
4. Carbone, P. et al. *Apache Flink: Stream and Batch Processing in a Single Engine.* IEEE Data Eng. Bull. 38(4), 2015.
5. Strom, B. E. et al. *MITRE ATT&CK: Design and Philosophy.* MITRE Technical Report, 2018.
6. Sharafaldin, I., Lashkari, A. H., Ghorbani, A. A. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization.* ICISSP, 2018.
7. Karimov, J. et al. *Benchmarking Distributed Stream Data Processing Systems.* IEEE ICDE, 2018.
8. Kent, K., Souppaya, M. *Guide to Computer Security Log Management.* NIST SP 800-92, 2006 (white paper).
9. González-Granadillo, G. et al. *Security Information and Event Management (SIEM): Analysis, Trends, and Usage in Critical Infrastructures.* Sensors 21(14), 2021.
10. Google Patent US20110016123A1. *Scalable Real Time Event Stream Processing.*
11. [Patent on security event / alert correlation: to be added after verifying on Google Patents.]

## 10. Project Tracker

Project tracker: https://docs.google.com/spreadsheets/d/1XgUgVPtEXbcVPbfo1FbYuKVqqkgST1nDbfMCx63SGYU/edit?usp=sharing
