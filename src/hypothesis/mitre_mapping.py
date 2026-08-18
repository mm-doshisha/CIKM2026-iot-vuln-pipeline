"""MITRE ATT&CK technique mapping for rule metadata.

Maps the LLM's attack hypothesis to a coarse attack category and the
corresponding ATT&CK technique IDs, used to annotate generated Suricata rules.
"""

from typing import List, Tuple


def _classify_attack(analysis: dict, http_method: str = "") -> Tuple[str, List[str]]:
    """Map LLM analysis to attack category and ATT&CK technique IDs."""
    hyp = analysis.get("attack_hypothesis", {})
    syntax = (hyp.get("payload_syntax") or "").lower()
    param = (hyp.get("dangerous_param") or "").lower()
    effect = (hyp.get("expected_effect") or "").lower()
    server_action = (hyp.get("server_action") or "").lower()

    if any(k in syntax for k in ("shell", "command", "cmd", "os command")):
        return "command_injection", ["T1059", "T1059.004"]
    if any(k in syntax for k in ("path traversal", "directory traversal", "../")):
        return "path_traversal", ["T1005", "T1083"]
    if any(k in effect for k in ("information", "leak", "sensitive", "debug", "config")):
        return "info_leak", ["T1190", "T1005"]
    if any(k in syntax for k in ("sql", "sqli")):
        return "sql_injection", ["T1190"]
    if any(k in syntax for k in ("template", "ssti", "jinja")):
        return "template_injection", ["T1059"]
    if any(k in syntax for k in ("eval", "code injection")):
        return "code_injection", ["T1059"]
    if param in ("none", "no_payload", "") or "auth" in effect or "bypass" in effect:
        return "auth_bypass", ["T1078", "T1556"]
    if any(k in server_action for k in ("shell", "exec", "system", "popen", "subprocess")):
        return "command_injection", ["T1059", "T1059.004"]
    if any(k in server_action for k in ("file", "read", "open", "path")):
        return "path_traversal", ["T1005", "T1083"]

    return "other", []


def get_mitre_technique_id(analysis: dict) -> str:
    """Get the primary MITRE ATT&CK technique ID for metadata."""
    _, mitre_ids = _classify_attack(analysis)
    return mitre_ids[0] if mitre_ids else ""
