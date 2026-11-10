"""Conservative heuristics over printable strings; never treats hits as proof."""
import re

PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{6,}")
PATTERNS = [
    ("possible_hardcoded_password", re.compile(r"(?i)\b(password|passwd|pwd)\s*[:=]\s*['\"]?[^ \r\n'\"]{4,}")),
    ("possible_private_key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("debug_service_reference", re.compile(r"(?i)\b(telnetd|dropbear|debug console|uart console)\b")),
    ("weak_crypto_reference", re.compile(r"(?i)\b(md5|des|3des|rc4)\b")),
    ("insecure_protocol_reference", re.compile(r"(?i)\b(ftp://|http://)")),
]
KERNEL_RE = re.compile(r"\bLinux version\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?[^\s]*)")


def extract_strings(data: bytes, limit: int = 20000) -> list[str]:
    if limit < 0:
        raise ValueError("limit must be zero or greater")
    if limit == 0:
        return []
    values = []
    for match in PRINTABLE_RE.finditer(data):
        values.append(match.group(0).decode("ascii", errors="replace"))
        if len(values) >= limit:
            break
    return values


def inspect_strings(strings: list[str], max_evidence_per_rule: int = 10) -> list[dict]:
    if max_evidence_per_rule < 0:
        raise ValueError("max_evidence_per_rule must be zero or greater")
    if max_evidence_per_rule == 0:
        return []
    findings = []
    for rule, pattern in PATTERNS:
        evidence = []
        for value in strings:
            if pattern.search(value):
                evidence.append(value[:240])
                if len(evidence) >= max_evidence_per_rule:
                    break
        if evidence:
            findings.append({
                "rule": rule,
                "severity": "review",
                "confidence": "low",
                "count_sampled": len(evidence),
                "evidence": evidence,
                "message": "Heuristic indicator only; manually validate context and whether the component is active.",
            })
    return findings


def find_kernel_versions(strings: list[str]) -> list[str]:
    found = []
    for value in strings:
        for version in KERNEL_RE.findall(value):
            if version not in found:
                found.append(version)
    return found
