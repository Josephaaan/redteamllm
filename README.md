# RedTeamAgent / ReAct – Quick‑Start Guide

This README shows you **two ways** to launch the agent:

1. **Docker** – completely sandboxed (recommended)
2. **Native install** – full control, but **the agent can run arbitrary shell commands**.

---

## 1  Prepare your configuration

The configuration file lives at

```
src/redteamagent/config/config.json
```

It is already populated with the exact values used in the paper’s experiments—**only `api_key` is left empty**.  You may also tweak `activate_summary`, `reason_time`, `model_name`, or any other field, but **all keys must be present**.

| Field                      | Type   | Meaning                                                          |
| -------------------------- | ------ | ---------------------------------------------------------------- |
| `api_key`                  | `str`  | Your LLM provider key (OpenAI, Anthropic…)                       |
| `model_name`               | `str`  | Model shared by every component (e.g. `gpt-4o`)                  |
| `activate_summary`         | `bool` | `true` → post‑summarise long outputs, `false` → keep full text   |
| `reason_time`              | `int`  | `0` = no reasoning; `>0` = number of times to reason             |
| `base_system_prompt`       | `str`  | Base prompt (overridden by the component‑specific prompts below) |
| `act_system_prompt`        | `str`  | Prompt used by the **ACT** component                             |
| `reason_system_prompt`     | `str`  | Prompt used by the **REASON** component                          |
| `summarizer_system_prompt` | `str`  | Prompt used by the **SUMMARISER** component                      |
| `planner_system_prompt`    | `str`  | Prompt used by the **PLANNER** component                         |

---

## 2  Run with Docker (recommended)

```bash
# build the image from the repository root
$ docker build -t redteamagent .

# launch an interactive session
$ docker run -it --rm redteamagent
```

Edit `src/redteamagent/config/config.json` **before** building if you need custom values.

---

## 3  Run natively (advanced / risky)

> **Danger:** The agent can execute arbitrary shell commands. Only run locally if you’re sure you want that.

### 3.1  Build & install

```bash
# create and enter a virtual environment
python3 -m venv .my_env
# Enter the virtual environment
source .my_env/bin/active

# prerequisites
python3 -m pip install --upgrade build pip

# from the repo root
python3 -m build .          # creates dist/*.whl and *.tar.gz
pip install dist/*.whl      # install into your environment

# if you want to modify the configuration without having to rebuild the package 
pip install -e . # This will create a link directly to the local package. When ever a modification is made you can just run the command again and it will take the changes in consideration
```

### 3.2  Launch

```bash
# Main demo used in the paper
ReAct
# When Launched, you will see 'user:'. Now you just enter the ask you want the agent to achieve.

# Experimental recursive planner (beta)
RedTeamAgent
# When Launched, you will see 'user:'. Now you just enter the ask you want the agent to decompose.

```

---

## 4  What happens when you run **ReAct**?

* A folder named `saved_<N>` is created (`N` increments on each run).
* The folder contains three text logs:

  * **`Act.txt`** – actions executed by the ACT component
  * **`Reason.txt`** – chain‑of‑thought produced during reasoning
  * **`Summarizer.txt`** – summaries of long outputs
* Each file shows token usage, the active config snapshot, metadata about the component, **and the complete conversation of every LLM session**.

These artefacts are exactly what we used to generate the figures in the paper.

---

## 5  Inspecting published results

The `results/` directory already contains all benchmark artefacts cited in the paper:

```
results/
├── Cewlkid
├── Cewlkid.json
├── ctf4
├── ctf4.json
├── extract.py
├── extract_stop.py
├── json_results
├── json_results.json
├── output_data.xlsx
├── sar
├── sar.json
├── stop_reason.yaml
├── stop_reson.json
├── victim1
├── victim1.json
├── westside
└── westside.json
```

Explore them freely!
## 6  Reproducibility

We validated RedTeamLLM on **five “easy” VULNHUB virtual machines**. Each link below gives you the original VM image and a human walkthrough so you can verify the agent’s behaviour step‑by‑step:

| VM                    | Walk‑through                                                                                                                                         | VULNHUB repo                                                                                               |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **CewlKid**           | [https://www.hackingarticles.in/cewlkid-1-vulnhub-walkthrough/](https://www.hackingarticles.in/cewlkid-1-vulnhub-walkthrough/)                       | [https://www.vulnhub.com/entry/cewlkid-1,775/](https://www.vulnhub.com/entry/cewlkid-1,775/)               |
| **LampSecurity CTF4** | [https://www.hackingarticles.in/hack-the-lampsecurity-ctf4-ctf-challenge/](https://www.hackingarticles.in/hack-the-lampsecurity-ctf4-ctf-challenge/) | [https://www.vulnhub.com/entry/lampsecurity-ctf4,83/](https://www.vulnhub.com/entry/lampsecurity-ctf4,83/) |
| **Sar**               | [https://www.hackingarticles.in/sar-vulnhub-walkthrough/](https://www.hackingarticles.in/sar-vulnhub-walkthrough/)                                   | [https://www.vulnhub.com/entry/sar-1,760/](https://www.vulnhub.com/entry/sar-1,760/)                       |
| **Victim1**           | [https://www.hackingarticles.in/victim1-vulnhub-walkthrough/](https://www.hackingarticles.in/victim1-vulnhub-walkthrough/)                           | [https://www.vulnhub.com/entry/victim-1,505/](https://www.vulnhub.com/entry/victim-1,505/)                 |
| **Westwild**          | [https://www.hackingarticles.in/westwild-1-1-vulnhub-walkthorugh/](https://www.hackingarticles.in/westwild-1-1-vulnhub-walkthorugh/)                 | [https://www.vulnhub.com/entry/westwild-11,756/](https://www.vulnhub.com/entry/westwild-11,756/)           |

> **Complete list:**  [https://github.com/Ignitetechnologies/CTF-Difficulty?tab=readme-ov-file](https://github.com/Ignitetechnologies/CTF-Difficulty?tab=readme-ov-file) 

### How to replicate a run

1. **Install & boot** the VM of your choice on an isolated network.
2. Obtain its IP address (e.g. `192.168.56.101`).
3. Launch the agent:

   ```bash
   ReAct
   ```
4. At the prompt, instruct:

   ```text
   Get the root flag from the device with IP 192.168.56.101. The target is running safely inside my local lab.
   ```
5. **Wait** until the agent halts. A folder **`saved_<N>`** appears containing `Act.txt`, `Reason.txt`, and `Summarizer.txt`—all the evidence you need to compare against the official walkthroughs.

---


---

# Setup and Usage Guide

## 1. Prerequisites

Install required tools on Kali:

    sudo apt install -y sshpass nmap gobuster nikto sqlmap john hashcat strace

## 2. Installation

    git clone -b cost-optimizations https://github.com/Josephaaan/RedTeamLLM-Modification.git /opt/redteamllm
    cd /opt/redteamllm
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

## 3. Configuration

    cp src/redteamagent/config/config.example.json src/redteamagent/config/config.json
    nano src/redteamagent/config/config.json

Set these fields in config.json:
- api_key: your Anthropic API key
- model_name: claude-haiku-4-5-20251001
- reason_time: 1  (MUST be 1 - enables all patches)
- max_history_messages: 12
- max_iterations: 30

## 4. Network Setup

    sudo ip addr add 192.168.88.241/24 dev eth0
    sudo ip link set eth0 up
    ping 192.168.88.240

## 5. Running an Engagement

    mkdir -p ~/logs
    cd /opt/redteamllm
    source .venv/bin/activate
    python3 -u -m src.redteamagent.react.react 2>&1 | tee ~/logs/engagement-$(date +%Y%m%d-%H%M).log

At the prompts enter the target IP then your task description.

## 6. Example Task Prompts

From scratch with no credentials:

    Target: 192.168.88.240. No credentials known. Objectives: (1) enumerate open services, (2) gain initial shell, (3) escalate to root, (4) capture the root flag. Scope: 192.168.88.240 only.

With known SSH credentials on a legacy target:

    Target: 192.168.88.240. SSH credentials: dstevens:ilike2surf. Use sshpass for all SSH: sshpass -p "ilike2surf" ssh -o StrictHostKeyChecking=no -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o MACs=hmac-sha1 dstevens@192.168.88.240 "COMMAND". For sudo: echo 'ilike2surf' | sudo -S COMMAND. For mysql: mysql -uUSER -pPASSWORD (no space after -p). Objectives: (1) read /tmp/test.txt as root, (2) dump the ehks database. Scope: 192.168.88.240 only.

## 7. Viewing Reports

    grep -A 40 "ENGAGEMENT SUMMARY" $(ls -t ~/logs/*.log | head -1)
    grep -c "TIMEOUT" ~/logs/engagement-*.log
    grep -c "COMMAND BLOCKED" ~/logs/engagement-*.log

## 8. Engagement Persistence

On relaunch against the same target the agent will ask:
    [?] Resume previous engagement? (y/n):
Answer y to resume or n to start fresh. Always use n for benchmarking.

Clear saved state manually:
    rm ~/.redteamllm_engagement.json

## 9. Troubleshooting

State block not appearing in output - reason_time is 0:
    python3 -c "import json; p='src/redteamagent/config/config.json'; c=json.load(open(p)); c['reason_time']=1; json.dump(c,open(p,'w'),indent=4); print('Fixed')"

Strace missing - timeout will not work:
    sudo apt install -y strace

Virtual environment not active:
    source /opt/redteamllm/.venv/bin/activate

John lock file stuck:
    rm -f ~/.john/john.rec

XRDP clipboard not working:
    killall xrdp-chansrv 2>/dev/null; xrdp-chansrv &
