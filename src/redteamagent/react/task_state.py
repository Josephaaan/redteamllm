from dataclasses import dataclass
from typing import Optional
import re

# Service keywords used to derive "vectors touched" generically from the
# commands the agent runs. This list is intentionally protocol-generic and
# is not tied to any particular target, box, or engagement.
_SERVICE_KEYWORDS = (
    "http", "https", "ssh", "ftp", "tftp", "smb", "telnet", "rdp",
    "mysql", "mssql", "postgres", "dns", "ldap", "snmp", "smtp",
    "pop3", "imap", "nfs", "vnc", "redis", "mongodb", "rpc", "kerberos",
)

# Characters that are normal inside a legitimate flag/content body. Anything
# else pushes the body toward the high-entropy binary-noise signature that
# characterised the agent's own garbled XOR scratch output.
_BENIGN_FLAG_CHARS = set(
    " ._-/:@!#%&+=,;'\"()[]<>*?~|^$"
)


def _is_wellformed_flag(token: str) -> bool:
    """Content-based test for a WORD{...} flag candidate.

    Accept a token only when its body is well-formed: printable ASCII, no
    nested braces, no Unicode replacement chars, a sane length, and a body
    that is not dominated by high-entropy binary noise. The decision is made
    purely on the *content* of the token, never on the command that produced
    it -- a clean cybersploit{...} from echo/python is accepted, a garbled
    Gp{{xg{~t|h7|u} from cat is rejected.
    """
    m = re.fullmatch(r'([A-Za-z0-9_]+)\{([^{}]*)\}', token)
    if not m:
        return False
    body = m.group(2)
    # Reject Unicode replacement chars (decode failures) and any non-printable
    # or non-ASCII byte anywhere in the token.
    if '�' in token:
        return False
    if any(ord(c) < 32 or ord(c) > 126 for c in token):
        return False
    # Reject nested braces such as Gp{{...}} or WORD{a{b}.
    if '{{' in token or '}}' in token or '{' in body or '}' in body:
        return False
    # Sane length bound on the body.
    if not (3 <= len(body) <= 80):
        return False
    # Reject high-entropy binary noise: a real flag body is mostly made of
    # alphanumerics plus a handful of common punctuation characters.
    benign = sum(1 for c in body if c.isalnum() or c in _BENIGN_FLAG_CHARS)
    if benign / len(body) < 0.75:
        return False
    return True


@dataclass
class Objective:
    description: str
    status: str = "PENDING"
    result: str = ""

class EngagementState:
    def __init__(self):
        self.target_ip = None
        self.attacker_ip = None
        self.objectives = []
        self.phase = "recon"
        self.key_findings = []
        self._initialized = False
        # Stall / anti-rabbit-hole tracking.
        self.iteration = 0
        self.last_finding_iter = 0
        self.vectors_touched = set()

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

    def note_vectors(self, command):
        """Derive the attack vectors a command touches, generically.

        Records distinct service keywords (http, ssh, ftp, smb, ...) and
        destination ports parsed out of the command. This is deliberately
        target-agnostic: it never references a specific host, credential, or
        technique -- only the protocol surface implied by the command text.
        """
        if not command:
            return
        cmd = command.lower()
        for svc in _SERVICE_KEYWORDS:
            if re.search(rf'\b{svc}\b', cmd):
                self.vectors_touched.add(svc)
        # Destination ports: nmap-style "-p 80", "port 22", or "host:443".
        for port in re.findall(r'(?:-p\s*|\bport\s+|:)(\d{1,5})\b', cmd):
            if 0 < int(port) <= 65535:
                self.vectors_touched.add(f"port/{port}")

    def stall_check(self, current_iter, threshold=6):
        """Return a neutral advisory when progress has stalled.

        When `threshold` consecutive iterations pass with no new verified
        finding, return a short, non-leading nudge listing the vectors touched
        so far. The advisory never names a specific service, credential, or
        technique -- it only prompts the reasoner to reconsider unexplored
        surface or whether the objective is exhausted.
        """
        gap = current_iter - self.last_finding_iter
        if gap < threshold:
            return ""
        if self.vectors_touched:
            vectors = ", ".join(sorted(self.vectors_touched))
        else:
            vectors = "none recorded"
        return (
            f"No new verified evidence in {gap} iterations. "
            f"You have touched these vectors: {vectors}. "
            f"Consider whether an enumerated-but-unexplored service remains, "
            f"or whether the current objective is exhausted and you should stop."
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

    def auto_update_from_result(self, command, result):
        # Track which vectors this command exercised (generic, target-agnostic).
        self.note_vectors(command)
        # Record WORD{...} flags using a content-based test only. The command
        # that produced the token is irrelevant: a clean body is accepted, a
        # garbled / high-entropy body is rejected, regardless of echo/python/cat.
        for match in re.finditer(r'[A-Za-z0-9_]+\{[^}]+\}', result):
            token = match.group(0)
            if _is_wellformed_flag(token):
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
    # Quick content-based flag-recording checks.
    _s = EngagementState()
    _s.auto_update_from_result(
        'echo "..." | base64 -d',
        "cybersploit{youtube.com/c/cybersploit}",
    )
    assert "FLAG/CONTENT: cybersploit{youtube.com/c/cybersploit}" in _s.key_findings, \
        "clean flag from a decode pipeline should be recorded"

    _s2 = EngagementState()
    _s2.auto_update_from_result("cat secret.bin", "Gp{{xg{~t|h7|u}")
    assert not any("Gp{{" in f for f in _s2.key_findings), \
        "garbled high-entropy token should NOT be recorded"

    # The recorder must key on content, not the command name: a clean flag
    # printed by python/echo is accepted, a garbled one from cat is rejected.
    assert _is_wellformed_flag("cybersploit{youtube.com/c/cybersploit}")
    assert not _is_wellformed_flag("Gp{{xg{~t|h7|u}")
    print("task_state self-checks passed")
