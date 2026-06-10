from dataclasses import dataclass
from typing import Optional
import re
import string

@dataclass
class Objective:
    description: str
    status: str = "PENDING"
    result: str = ""

# Generic, target-agnostic service keywords used to characterise which attack
# vectors have been touched. This is a vocabulary of common network services,
# NOT a description of any particular target or its intended solution.
_SERVICE_KEYWORDS = {
    "http", "https", "ssh", "ftp", "sftp", "smb", "smtp", "imap", "pop3",
    "dns", "telnet", "mysql", "mssql", "postgres", "postgresql", "rdp",
    "ldap", "snmp", "nfs", "redis", "mongodb", "vnc", "sip", "rsync",
    "tftp", "kerberos", "winrm", "oracle", "memcached", "elasticsearch",
}

# Characters that legitimately appear inside flags/finding bodies. Anything
# outside this set (e.g. '|', '~', backtick, control bytes) signals the kind of
# high-entropy binary noise produced by a failed/garbled decrypt.
_CLEAN_BODY_CHARS = set(string.ascii_letters + string.digits + "_-./:@+=,.!?#%& ()[]")


class EngagementState:
    def __init__(self):
        self.target_ip = None
        self.attacker_ip = None
        self.objectives = []
        self.phase = "recon"
        self.key_findings = []
        self._initialized = False
        # Stall / anti-rabbit-hole tracking.
        self.iteration = 0                # monotonically increasing reasoning-loop counter
        self.last_finding_iter = 0        # iteration at which the last new finding landed
        self.last_advised_iter = 0        # iteration at which we last emitted a stall advisory
        self.vectors_touched = set()      # generic services/ports seen across commands

    def init(self, target_ip, attacker_ip):
        self.target_ip = target_ip
        self.attacker_ip = attacker_ip
        self._initialized = True

    def add_objective(self, description):
        self.objectives.append(Objective(description=description))

    def mark_done(self, index, result=""):
        if 0 <= index < len(self.objectives):
            self.objectives[index].status = "DONE"
            self.objectives[index].result = result

    def mark_failed(self, index, reason=""):
        if 0 <= index < len(self.objectives):
            self.objectives[index].status = "FAILED"
            self.objectives[index].result = reason

    def add_finding(self, finding):
        if finding not in self.key_findings:
            self.key_findings.append(finding)
            # A genuinely new verified finding resets the stall window.
            self.last_finding_iter = self.iteration

    def advance_iteration(self):
        """Advance the reasoning-loop counter. Called once per react cycle."""
        self.iteration += 1
        return self.iteration

    def note_vectors(self, command):
        """Derive generic 'vectors touched' from a command, target-agnostically.

        We record distinct service keywords (http/ssh/ftp/...) and explicit
        host:port destinations. Nothing here is keyed to a specific target,
        service, or solution path.
        """
        if not command:
            return
        cmd = command.lower()
        for word in re.findall(r'[a-z][a-z0-9]*', cmd):
            if word in _SERVICE_KEYWORDS:
                self.vectors_touched.add(word)
        # host:port style destinations (e.g. 10.0.0.1:8080, ssh://h:22)
        for port in re.findall(r':(\d{1,5})(?:\b|/)', cmd):
            p = int(port)
            if 0 < p <= 65535:
                self.vectors_touched.add(f"port:{p}")

    def stall_check(self, current_iter, threshold=6):
        """Return a neutral advisory when progress has stalled.

        Fires when `threshold` consecutive iterations pass with no new verified
        finding. The message is deliberately non-leading: it never names a
        specific service, credential, or technique — it only nudges the
        reasoner to consider unexplored vectors or stopping.
        """
        if threshold is None or threshold <= 0:
            return ""
        baseline = max(self.last_finding_iter, self.last_advised_iter)
        if current_iter - baseline < threshold:
            return ""
        self.last_advised_iter = current_iter
        gap = current_iter - self.last_finding_iter
        if self.vectors_touched:
            vectors = ", ".join(sorted(self.vectors_touched))
        else:
            vectors = "none recorded"
        return (
            f"No new verified evidence in {gap} iterations. "
            f"You have touched these vectors: {vectors}. "
            "Consider whether an enumerated-but-unexplored service remains, "
            "or whether the current objective is exhausted and you should stop."
        )

    def set_phase(self, phase):
        self.phase = phase

    def validate_target_ip(self, command):
        if not self.target_ip:
            return None
        found_ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', command)
        for ip in found_ips:
            if ip != self.target_ip and ip != self.attacker_ip and ip != "127.0.0.1":
                return ip
        return None

    def status_block(self):
        if not self._initialized:
            return ""
        lines = [
            "=" * 60,
            "ENGAGEMENT STATE — READ THIS BEFORE EVERY DECISION",
            "=" * 60,
            f"TARGET IP (IMMUTABLE): {self.target_ip}",
            f"ATTACKER IP:           {self.attacker_ip}",
            f"CURRENT PHASE:         {self.phase}",
            "",
            "OBJECTIVES:",
        ]
        for i, obj in enumerate(self.objectives):
            icon = {"PENDING": "[ ]", "IN_PROGRESS": "[>]",
                    "DONE": "[✓]", "FAILED": "[✗]"}.get(obj.status, "[ ]")
            line = f"  {icon} {i+1}. {obj.description}"
            if obj.result:
                line += f"\n       -> {obj.result}"
            lines.append(line)
        if self.key_findings:
            lines.append("")
            lines.append("KEY FINDINGS SO FAR:")
            for f in self.key_findings[-8:]:
                lines.append(f"  * {f}")
        lines += [
            "=" * 60,
            "RULE: Never send traffic to any IP other than TARGET IP above.",
            "RULE: If an objective is [OK] DONE, move to the next PENDING one.",
            "RULE: Do not re-run commands already marked FAILED.",
            "=" * 60,
        ]
        return "\n".join(lines)

    def parse_objectives_from_task(self, task):
        matches = re.findall(r'\((\d+)\)\s+([^,()\n]+?)(?=\s*[,()\n]|$)', task)
        if matches:
            for _, desc in matches:
                desc = desc.strip()
                if len(desc) > 5:
                    self.add_objective(desc)
        else:
            matches = re.findall(r'(?:step\s*)?\d+[.):\s]+([^\n.]+)', task, re.IGNORECASE)
            for m in matches:
                m = m.strip()
                if len(m) > 5:
                    self.add_objective(m)

    @staticmethod
    def _is_clean_flag(token):
        """Content-based test for a well-formed WORD{...} flag.

        The decision is made purely on the matched token's content, never on the
        command that produced it: a clean cybersploit{...} printed by echo/python
        is accepted, while a garbled Gp{{xg{~t|h7|u} printed by cat is rejected.

        A token is clean when:
          - it has no replacement characters (\\ufffd),
          - it has no nested/doubled braces ({{ or }}),
          - its overall length is within a sane bound (3-80),
          - the body is non-empty printable ASCII, and
          - the body contains no high-entropy binary-noise characters.
        """
        if '�' in token:
            return False
        if '{{' in token or '}}' in token:
            return False
        if not (3 <= len(token) <= 80):
            return False
        open_idx = token.find('{')
        if open_idx <= 0 or not token.endswith('}'):
            return False
        body = token[open_idx + 1:-1]
        if not body:
            return False
        # Printable ASCII only (no control bytes, no high-bit garbage).
        if any(not (32 <= ord(c) < 127) for c in body):
            return False
        # Reject bodies that carry binary-noise characters such as '|', '~',
        # backtick, etc. that characterised the garbled XOR/decrypt output.
        if any(c not in _CLEAN_BODY_CHARS for c in body):
            return False
        return True

    def auto_update_from_result(self, command, result):
        self.note_vectors(command)
        # Record well-formed WORD{...} flags. Candidate matches use a
        # brace-free body so a clean flag is captured; each candidate is then
        # validated on content alone.
        for match in re.finditer(r'[A-Za-z0-9_]+\{[^{}]*\}', result):
            token = match.group(0)
            if self._is_clean_flag(token):
                self.add_finding(f"FLAG/CONTENT: {token}")
        if 'TESTCONTENT' in result:
            self.add_finding("FLAG/CONTENT: TESTCONTENT")
        if 'uid=' in result and 'gid=' in result:
            self.add_finding(f"Shell access: {command[:60]}")
        if '(all) all' in result.lower():
            self.add_finding("sudo (ALL) ALL confirmed")
        if 'insert into' in result.lower() and 'md5(' in result.lower():
            self.add_finding(f"Credentials in: {command[:60]}")

engagement = EngagementState()


if __name__ == "__main__":
    # A clean flag decoded from target data must be recorded, regardless of the
    # command that produced it...
    accepted = EngagementState()
    accepted.init("10.0.0.1", "10.0.0.2")
    accepted.auto_update_from_result(
        'echo "..." | base64 -d',
        "cybersploit{youtube.com/c/cybersploit}",
    )
    assert any("cybersploit{youtube.com/c/cybersploit}" in f for f in accepted.key_findings), \
        f"clean flag not recorded: {accepted.key_findings}"

    # ...while garbled binary-noise output must be rejected, even from cat.
    rejected = EngagementState()
    rejected.init("10.0.0.1", "10.0.0.2")
    rejected.auto_update_from_result("cat /tmp/secret", "Gp{{xg{~t|h7|u}")
    assert not rejected.key_findings, \
        f"garbled output should not be recorded: {rejected.key_findings}"

    # Stall detector stays quiet before the threshold and nudges after it,
    # without naming any specific service or technique.
    stalled = EngagementState()
    stalled.init("10.0.0.1", "10.0.0.2")
    stalled.note_vectors("curl http://10.0.0.1:80/")
    assert stalled.stall_check(3, threshold=6) == ""
    advisory = stalled.stall_check(7, threshold=6)
    assert advisory and "http" in advisory and "ssh" not in advisory.lower(), advisory

    print("task_state self-checks passed")
