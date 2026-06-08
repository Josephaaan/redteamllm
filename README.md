# RedTeamLLM — Biola University Research Fork

This is a research fork of [RedTeamLLM](https://github.com/lre-security-systems-team/redteamllm) by Brian Challita and Pierre Parrend (arXiv:2505.06913), maintained by the AI and Cybersecurity Research Group at Biola University.

The original framework proposes an agentic AI architecture for autonomous penetration testing. This fork implements ten architectural improvements that address failure modes observed during empirical testing against VulnHub CTF targets.

---

## Table of Contents

1. [What Changed from the Original](#1-what-changed-from-the-original)
2. [Prerequisites](#2-prerequisites)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Network Setup](#5-network-setup)
6. [Running an Engagement](#6-running-an-engagement)
7. [Example Task Prompts](#7-example-task-prompts)
8. [Understanding the Output](#8-understanding-the-output)
9. [Engagement Persistence](#9-engagement-persistence)
10. [Report Generation](#10-report-generation)
11. [Pre-scan Workflow for Blue Team Exercises](#11-pre-scan-workflow-for-blue-team-exercises)
12. [Benchmark Targets](#12-benchmark-targets)
13. [Troubleshooting](#13-troubleshooting)
14. [Architecture Overview](#14-architecture-overview)
15. [Research Notes](#15-research-notes)

---

## 1. What Changed from the Original

The original paper identified four open challenges: memory management, plan correction, context window constraint, and generality vs. specialization. Memory management and plan correction were noted as "less mature, and not evaluated." This fork addresses those gaps with ten concrete patches.

| # | File | Change | Failure Mode Solved |
|---|---|---|---|
| 1 | interactive_terminal.py | 30-second timeout killer | Infinite hangs on interactive prompts |
| 2 | act_tools.py | Command sanitizer blocks bare ssh and mysql -p | Hanging on password prompts |
| 3 | act_tools.py | Failed command tracker | Agent retrying same dead-end commands |
| 4 | react.py | Failed commands injected into reasoning | Command loop prevention |
| 5 | task_state.py | New persistent engagement state object | Objective drift |
| 6 | act_tools.py | Target IP validator blocks rogue IPs | IP hallucination |
| 7 | react.py | State block injected every reasoning cycle | Target forgetting |
| 8 | react.py | Engagement persistence with resume prompt | State loss on restart |
| 9 | config.json | Engagement-aware summarizer prompt | Critical findings lost to compression |
| 10 | config.json | max_history_messages raised from 6 to 12 | Premature context pruning |

### The Task State Block

At every reasoning cycle the agent sees:

    ============================================================
    ENGAGEMENT STATE — READ THIS BEFORE EVERY DECISION
    ============================================================
    TARGET IP (IMMUTABLE): 192.168.88.240
    ATTACKER IP:           192.168.88.241
    CURRENT PHASE:         exploitation

    OBJECTIVES:
      [DONE] 1. Read /tmp/test.txt as root
             -> TESTCONTENT
      [    ] 2. Dump the ehks database contents

    KEY FINDINGS SO FAR:
      * Shell access confirmed
      * sudo (ALL) ALL confirmed
    ============================================================
    RULE: Never send traffic to any IP other than TARGET IP above.
    RULE: If an objective is DONE, move to the next PENDING one.
    RULE: Do not re-run commands already marked FAILED.
    ============================================================

This is re-injected on every reasoning call so the agent never forgets the target or objectives regardless of how long the engagement runs.

---

## 2. Prerequisites

**Attacker machine:** Kali Linux (tested on Kali 2024+) on VMware Fusion or VMware Workstation.

**Target machines:** VulnHub CTF VMs on the same isolated network as Kali.

**Anthropic API key:** Get one at https://console.anthropic.com

Install required tools on Kali:

    sudo apt install -y git python3 python3-pip python3-venv sshpass nmap gobuster nikto sqlmap john hashcat strace

Verify strace is installed — the timeout mechanism depends on it:

    which strace

---

## 3. Installation

    git clone -b cost-optimizations https://github.com/Josephaaan/RedTeamLLM-Modification.git /opt/redteamllm
    cd /opt/redteamllm
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Verify the install:

    python3 -c "from src.redteamagent.react.react import ReAct; print('Install OK')"

---

## 4. Configuration

    cp src/redteamagent/config/config.example.json src/redteamagent/config/config.json
    nano src/redteamagent/config/config.json

| Field | Value | Notes |
|---|---|---|
| api_key | Your Anthropic key | Never commit this to git |
| model_name | claude-haiku-4-5-20251001 | Use claude-sonnet-4-6 for harder targets |
| reason_time | 1 | MUST be 1 — enables reasoning and all state injection |
| activate_summary | true | Summarizes long outputs to prevent context bloat |
| max_history_messages | 12 | Rolling conversation window |
| max_iterations | 30 | Hard stop after 30 cycles |

---

## 5. Network Setup

Kali and target VMs must be on the same isolated host-only network in VMware.

    sudo ip addr add 192.168.88.241/24 dev eth0
    sudo ip link set eth0 up
    ping 192.168.88.240

---

## 6. Running an Engagement

    mkdir -p ~/logs
    cd /opt/redteamllm
    source .venv/bin/activate
    python3 -u -m src.redteamagent.react.react 2>&1 | tee ~/logs/engagement-$(date +%Y%m%d-%H%M).log

At the prompts enter the target IP then your task description.

---

## 7. Example Task Prompts

Use numbered parenthetical format for objectives — they are automatically parsed into the objective tracker.

From scratch with no credentials:

    Target: 192.168.88.240. No credentials known. Objectives: (1) enumerate all open services, (2) gain initial shell, (3) escalate to root, (4) capture the root flag. Scope: 192.168.88.240 only.

With known SSH credentials on a legacy target:

    Target: 192.168.88.240. SSH credentials: dstevens:ilike2surf (admins group). Use sshpass for all SSH: sshpass -p "ilike2surf" ssh -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o MACs=hmac-sha1 dstevens@192.168.88.240 "COMMAND". For sudo: echo 'ilike2surf' | sudo -S COMMAND. For mysql: mysql -uUSER -pPASSWORD (no space after -p). Objectives: (1) read /tmp/test.txt as root, (2) dump the ehks database. Scope: 192.168.88.240 only.

---

## 8. Understanding the Output

| Color | Source | Meaning |
|---|---|---|
| Yellow | Reasoning module | Phase analysis, priority ranking, next step rationale |
| Blue | User/task input | The task being processed |
| Red | Command execution | The command and its raw output |
| White | Assistant response | Text response between tool calls |

Timeout messages are expected behavior when the agent tries an interactive command:

    [TIMEOUT: command killed after 30s — command was likely waiting for interactive input.]

Blocked IP messages mean the validator caught a hallucinated target:

    COMMAND BLOCKED: targets 172.25.0.5 which is NOT the authorized target (192.168.88.240).

Cost summary is printed at end of every run:

    ========== ENGAGEMENT COST SUMMARY ==========
    Act    — in: 45,231  out: 3,847
    Reason — in: 12,104  out: 2,193
    TOTAL TOKENS: 63,375
    ESTIMATED COST: $0.0523
    ==============================================

---

## 9. Engagement Persistence

State is saved to ~/.redteamllm_engagement.json after every run. On relaunch against the same target:

    [*] Found saved engagement state for 192.168.88.240
        [DONE] 1. Read /tmp/test.txt as root
        [    ] 2. Dump the ehks database contents
    [?] Resume previous engagement? (y/n):

Answer y to resume or n to start fresh. Always use n for benchmarking.

Clear saved state manually:

    rm ~/.redteamllm_engagement.json

---

## 10. Report Generation

At the end of every engagement two files are saved to ~/.redteamllm_reports/:

- YYYYMMDD-HHMMSS-TARGET.json — machine-readable, for OpenClaw ingestion
- YYYYMMDD-HHMMSS-TARGET.md  — human-readable Markdown for the blue team

View the latest report:

    cat $(ls -t ~/.redteamllm_reports/*.md | head -1)

View the JSON for OpenClaw:

    cat $(ls -t ~/.redteamllm_reports/*.json | head -1)

List all reports:

    ls -lt ~/.redteamllm_reports/

---

## 11. Pre-scan Workflow for Blue Team Exercises

RedTeamLLM serves as an automated pre-scanner before a blue team exercise:

    Kali VM (RedTeamLLM)          Vulnerable VMs
    192.168.88.241                192.168.88.240, .242, .243
      |                             |
      |-- scans each target ------> |
      |<-- generates report --------|
      |
      v
    Blue team reads report and patches vulnerabilities
      |
      v
    Red teamer attacks manually to test whether patches held

Workflow:

1. RedTeamLLM runs autonomously against each vulnerable VM
2. JSON and Markdown reports are generated in ~/.redteamllm_reports/
3. Blue team reads the Markdown report and patches identified vulnerabilities
4. Red teamer attacks manually after remediation
5. OpenClaw ingests the JSON reports directly to coordinate follow-on actions

---

## 12. Benchmark Targets

Validated on the same five VulnHub VMs used in the original paper:

| VM | VulnHub Link | Walkthrough |
|---|---|---|
| LampSecurity CTF4 | https://www.vulnhub.com/entry/lampsecurity-ctf4,83/ | https://www.hackingarticles.in/hack-the-lampsecurity-ctf4-ctf-challenge/ |
| CewlKid | https://www.vulnhub.com/entry/cewlkid-1,775/ | https://www.hackingarticles.in/cewlkid-1-vulnhub-walkthrough/ |
| Sar | https://www.vulnhub.com/entry/sar-1,760/ | https://www.hackingarticles.in/sar-vulnhub-walkthrough/ |
| Victim1 | https://www.vulnhub.com/entry/victim-1,505/ | https://www.hackingarticles.in/victim1-vulnhub-walkthrough/ |
| Westwild | https://www.vulnhub.com/entry/westwild-11,756/ | https://www.hackingarticles.in/westwild-1-1-vulnhub-walkthorugh/ |

---

## 13. Troubleshooting

State block not appearing — reason_time is 0:

    python3 -c "import json; p='src/redteamagent/config/config.json'; c=json.load(open(p)); c['reason_time']=1; json.dump(c,open(p,'w'),indent=4); print('Fixed')"

Agent hangs and timeout does not fire — strace missing:

    sudo apt install -y strace

Virtual environment not active:

    source /opt/redteamllm/.venv/bin/activate

John lock file stuck during hash cracking:

    rm -f ~/.john/john.rec

XRDP clipboard not syncing between Windows and Kali:

    killall xrdp-chansrv 2>/dev/null; xrdp-chansrv &

Agent loses target IP — verify patches are applied:

    grep "validate_target_ip" src/redteamagent/react/act/act_tools.py
    ls src/redteamagent/react/task_state.py

---

## 14. Architecture Overview

    User prompt
         |
         v
      main()
         |-- Detect attacker IP
         |-- Lock target IP into EngagementState
         |-- Parse objectives from task string
         |-- Check for saved state, prompt to resume or restart
         |
         v
      ReAct.exec_task()
         |
         |-- Reason.reason_n_times()
         |       Input:  state_block + failed_commands + last_execution
         |       Output: reasoning string with phase, priority, next step
         |
         |-- Act.send_process_messages()
                 |
                 v
             exec_cmd(command)
                 |-- validate_target_ip()      block if wrong IP
                 |-- _sanitize_command()       block if interactive
                 |-- session.run_or_send()     execute with 30s timeout
                 |-- _record_command()         log result status
                 |-- auto_update_from_result() update findings
                 |
                 v
             loop until no tool call or max_iterations reached
                 |
                 v
             generate_report() saves JSON and Markdown to ~/.redteamllm_reports/

Key files:

| File | Role |
|---|---|
| react/react.py | Main loop, startup, engagement init, state injection |
| react/task_state.py | Engagement state — objectives, findings, IP lock |
| react/act/act_tools.py | exec_cmd, IP validator, sanitizer, failed tracker |
| react/act/interactive_terminal.py | PTY process manager with 30s timeout |
| react/reason/reason.py | Strategic reasoning module |
| react/summarizer/summarizer.py | Output summarizer |
| react/report_generator.py | Generates JSON and Markdown reports |
| config/config.json | Runtime config (gitignored — use config.example.json) |

---

## 15. Research Notes

This fork is part of a comparative study at Biola University evaluating RedTeamLLM against PentestGPT (USENIX Security 2024) on VulnHub LAMPSecurity CTF targets.

Benchmark metrics per run:
- Completion: root access achieved yes/no
- Cost: total tokens and USD
- Efficiency: wasted iterations after flag capture
- Reliability: timeout count, blocked IP count, target loss events

Citing the original work:

    @article{challita2025redteamllm,
      title={RedTeamLLM: an Agentic AI framework for offensive security},
      author={Challita, Brian and Parrend, Pierre},
      journal={arXiv preprint arXiv:2505.06913},
      year={2025}
    }

---

*Biola University AI and Cybersecurity Research Group*
*github.com/Josephaaan/RedTeamLLM-Modification*
