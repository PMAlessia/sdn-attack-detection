# SDN Attack Detection and Mitigation (SYN flood & ARP spoofing/MITM)

Bachelor's thesis project. Detection and mitigation of **SYN flood** and
**ARP spoofing / MITM** attacks in a Software-Defined Network, emulated with
**Mininet + Open vSwitch**, controlled by a **Ryu** application, with attacks
written in **Scapy**. The two attacks are demonstrated separately, each in three
scenarios (normal / attack / mitigation) that share the same topology and
parameters, changing only whether the attack runs and the controller's mode.

---

## 1. Repository

- **Source code repository:** `<REPOSITORY_URL>`  <!-- paste your repo URL here -->
- The repository contains the **complete source code** (Python) and
  configuration. Compiled/binary artifacts, raw run logs and generated figures
  are **excluded** from version control (see `.gitignore`).
- **Access for evaluation:** the repository is private. It will be **shared
  internally with the project coordinator and the members of the evaluation
  committee upon request.** To request access, contact the author with the
  account (email / platform username) to be granted read access.

---

## 2. Deliverables

| Deliverable | Location |
|-------------|----------|
| SDN controller application (Ryu IDS/IPS) | `controller/` |
| Network topology (Mininet, 1 switch + 4 hosts) | `topologies/topo_lab.py` |
| Attack scripts (Scapy) | `attacks/` |
| Experiment harness (services, clients, automated runner) | `experiments/` |
| Analysis and figure generation | `analysis/` |
| Configuration (source of truth) | `config/lab.yaml`, `config/scenarios.yaml` |
| Unit tests (logic independent of Mininet/Ryu) | `tests/` |
| Demonstration runbook and pre-run checklist | `docs/` |
| Final thesis figures (PNG for preview, PDF vector for the document) | `results/figures/final/` |
| Editable topology diagram (draw.io) | `docs/arp_mitm.drawio` |

---

## 3. Environment

Already provisioned in the project VM:

- Ubuntu 20.04.1, Python 3.8.5
- Mininet 2.3.0, Open vSwitch 2.13.1, OpenFlow 1.3
- Ryu 4.34, Scapy 2.5.0

Two Python environments are used deliberately:

- a **virtual environment (`venv`)** for the Ryu controller, the Scapy attacks
  and the analysis tools (Ryu, Scapy, PyYAML, pandas, matplotlib);
- the **system interpreter (`/usr/bin/python3`)** for Mininet, which is
  installed as a system package and is not available inside the venv.

---

## 4. Build / compilation

The application is written in **Python 3.8** and is interpreted, so there is no
separate compilation step. "Building" the application means creating the virtual
environment and installing the pinned dependencies:

```bash
git clone <REPOSITORY_URL> ~/sdn-attack-detection
cd ~/sdn-attack-detection

python3 -m venv venv
source venv/bin/activate

# Build tools compatible with Ryu 4.34 MUST be installed first
# (Ryu depends on pkg_resources / older setuptools):
python -m pip install 'pip==23.3.2' 'setuptools==65.5.1' 'wheel==0.42.0'

# Then the pinned runtime dependencies:
python -m pip install -r requirements.txt
```

`requirements.txt` pins every version for reproducibility (notably
`eventlet==0.30.2`, the last release that still exposes the `ALREADY_HANDLED`
constant Ryu 4.34 uses).

Mininet is used through the **system** interpreter and is not installed by the
steps above; it is part of the VM image.

---

## 5. Installation check

With the virtual environment active:

```bash
python3 lab_config.py     # prints the 4 hosts and the scenarios
ryu-manager --version     # ryu-manager 4.34
sudo mn -c                # clean any leftover Mininet state
```

Optional — run the unit tests (pure logic, no Mininet/Ryu needed):

```bash
python3 -m pytest tests/          # or run the test files individually
```

---

## 6. Launching the application

The controller and the topology run in **separate terminals**, both from the
project root. Always clean up **before** starting the controller, because
`mn -c` also kills a running `ryu-manager`.

**Order:** `sudo mn -c` → start controller (Terminal A) → start topology (Terminal B).

### Terminal A — SDN controller

```bash
cd ~/sdn-attack-detection && source venv/bin/activate

# mode = monitor_only (detect + alert, no blocking) or enforce (install drop rule)
SDN_MODE=monitor_only SDN_RUN_ID=demo_run \
  ryu-manager --ofp-tcp-listen-port 6653 controller/sdn_ids.py
```

### Terminal B — Mininet topology

```bash
cd ~/sdn-attack-detection
sudo python3 topologies/topo_lab.py
mininet> pingall            # must be 0% dropped
```

Then, from the `mininet>` prompt, start the target service, a legitimate client
and (manually) an attack — for example a SYN flood:

```
mininet> h1 python3 experiments/tcp_server.py --run-id demo_run &
mininet> h2 python3 experiments/tcp_client.py --run-id demo_run --label h2 --duration 120 &
mininet> h3 python3 attacks/syn_flood.py --rate 500 --duration 60
```


### Automated scenario runs (reproducible campaigns)

Each run is one scenario with a fixed duration and controlled shutdown. The
runner needs the **system** interpreter (Mininet), so it is launched with
`sudo /usr/bin/python3`:

```bash
sudo /usr/bin/python3 experiments/scenario_runner.py --scenario syn_attack    --run-id att_syn_1
sudo /usr/bin/python3 experiments/scenario_runner.py --scenario syn_mitigated --run-id mit_syn_1
sudo /usr/bin/python3 experiments/scenario_runner.py --scenario arp_attack    --run-id att_arp_1
sudo /usr/bin/python3 experiments/scenario_runner.py --scenario arp_mitigated --run-id mit_arp_1
```

Every run writes its raw evidence to `logs/raw/<run_id>/`.

---

## 7. Generating the thesis figures

Figures are produced **only from the raw run logs** (no synthetic values). The
SYN-flood figures are generated with:

```bash
source venv/bin/activate
python3 analysis/syn_figures.py \
    --attack-run    logs/raw/att_syn_1 \
    --mitigated-run logs/raw/mit_syn_1 \
    --out results/figures/final
```

This writes three figures (PNG + vector PDF) to `results/figures/final/`:
`syn_rate_timeline_attack` (detection), `syn_rate_timeline_mitigated`
(mitigation) and `client_service_timeline` (impact on legitimate clients).

---

## 8. Repository structure

```
sdn-attack-detection/
├── config/
│   ├── lab.yaml            # source of truth: IP-MAC-port bindings, ports, thresholds
│   └── scenarios.yaml      # the six scenario definitions
├── lab_config.py           # shared configuration loader
├── topologies/
│   └── topo_lab.py         # 1 switch + 4 hosts, fixed MACs/ports, OpenFlow 1.3
├── controller/             # Ryu application (SDN IDS/IPS)
│   ├── sdn_ids.py          #   entry point, coordinates the modules
│   ├── forwarding.py       #   MAC learning + L2 forwarding
│   ├── telemetry.py        #   FlowStats polling (SYN counting)
│   ├── syn_guard.py        #   baseline + threshold -> SYN alert
│   ├── arp_guard.py        #   IP-MAC-port binding validation -> ARP verdict
│   ├── flow_manager.py     #   FlowMod (count/drop), cookies, barrier
│   └── event_logger.py     #   JSONL events (monotonic + UTC)
├── attacks/
│   ├── syn_flood.py        # non-spoofed SYN flood + RST suppression
│   ├── arp_mitm.py         # MITM orchestrator (relay + poisoning)
│   ├── arp_poisoner.py     # bidirectional ARP poisoning + corrective ARP
│   ├── scapy_relay.py      # L2 relay + payload rewrite
│   └── payload_transform.py# the transform (pure, testable logic)
├── experiments/
│   ├── tcp_server.py       # target service h1:8080
│   ├── tcp_client.py       # legitimate client (measures availability)
│   ├── message_server.py   # ARP message receiver (reproducible)
│   ├── message_client.py   # ARP message sender
│   ├── collectors.py       # snapshots (ip neigh, ss syn-recv, dump-flows)
│   └── scenario_runner.py  # automated scenario runs (campaigns)
├── analysis/
│   ├── metrics.py          # log parsing -> DataFrames + statistics
│   ├── syn_figures.py      # SYN-flood figure generation (from real logs)
│   └── style.py            # shared style (colorblind-safe palette, light background)
├── tests/                  # unit tests for the pure logic
├── logs/raw/               # raw per-run logs (git-ignored)
└── results/figures/        # final figures (PNG + PDF)
```

---

## 9. Design notes (methodology chapter)

- **ARP detection** is deterministic (IP-MAC-port bindings from `lab.yaml`), not
  statistical: in a fixed topology, the contradiction "h3's port claims h1's IP"
  is direct evidence. `in_port` is the criterion that is robust against MAC
  spoofing.
- **SYN detection** uses aggregate rules that count SYNs toward `h1:8080`
  **per input port** (no `tcp_src`), so variable source ports do not create
  thousands of flows. An alert requires the threshold to be exceeded over several
  consecutive windows.
- **Mitigation** is anchored on `in_port` (plus `arp_spa` for ARP), with a
  `cookie` for selective removal and `BarrierRequest`/`Reply` to measure exactly
  when Open vSwitch applied the rule.
- **Thresholds** are measured from normal runs, not invented
  (`metrics.suggest_threshold()`), and justified in the thesis.
- **Figures** are generated exclusively from the raw run logs; no synthetic values.