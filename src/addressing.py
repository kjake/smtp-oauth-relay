from __future__ import annotations

import os
import re
from email.utils import parseaddr
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from domain_settings import DomainSettings


ADDRESS_DOMAIN_PATTERN = re.compile(r'@([^>\s]+)')
SMTP_DOT_ATOM_TEXT = r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~-]+"
SMTP_DOT_ATOM = rf"{SMTP_DOT_ATOM_TEXT}(?:\.{SMTP_DOT_ATOM_TEXT})*"
SMTP_QUOTED_STRING = r"\"(?:[\x20-\x21\x23-\x5B\x5D-\x7E]|\\[\x20-\x7E])*\""
SMTP_ADDRESS_LITERAL = r"\[(?:IPv6:[0-9A-Fa-f:.]+|[\x21-\x5A\x5E-\x7E]+)\]"
SMTP_DOMAIN = rf"(?:{SMTP_DOT_ATOM}|{SMTP_ADDRESS_LITERAL})"
SMTP_LOCAL_PART = rf"(?:{SMTP_DOT_ATOM}|{SMTP_QUOTED_STRING})"
SMTP_DOT_ATOM_PATTERN = re.compile(rf"^{SMTP_DOT_ATOM}$")
SMTP_QUOTED_STRING_PATTERN = re.compile(rf"^{SMTP_QUOTED_STRING}$")
SMTP_DOMAIN_PATTERN = re.compile(rf"^{SMTP_DOMAIN}$")


def parse_email_address(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if candidate in ('', '<>'):
        return None
    address = parseaddr(candidate)[1].strip()
    if not address or address == '<>' or '@' not in address:
        return None
    return address


def normalize_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    normalized = str(value).strip().lower()
    if normalized in {"true", "1", "yes", "y"}:
        return True
    if normalized in {"false", "0", "no", "n"}:
        return False
    return None


def is_valid_smtp_mailbox(address: str, *, allow_null: bool = False) -> bool:
    if allow_null and address == "<>":
        return True
    if not address or "<" in address or ">" in address:
        return False
    if address.count("@") != 1:
        return False
    local_part, domain_part = address.split("@", 1)
    if not (
        SMTP_DOT_ATOM_PATTERN.match(local_part)
        or SMTP_QUOTED_STRING_PATTERN.match(local_part)
    ):
        return False
    if not SMTP_DOMAIN_PATTERN.match(domain_part):
        return False
    if len(local_part) > 64 or len(domain_part) > 255:
        return False
    if domain_part.startswith("[") and domain_part.endswith("]"):
        return True
    labels = domain_part.split(".")
    return not any(len(label) == 0 or len(label) > 63 for label in labels)


def extract_domain_hint(*values: str | None) -> str | None:
    for value in values:
        if not value:
            continue
        match = ADDRESS_DOMAIN_PATTERN.search(value)
        if match:
            return match.group(1).strip().strip('>').lower()
    return None


def failback_env_var_name(domain: str) -> str:
    return f"{domain.replace('.', '_').upper()}_FROM_FAILBACK"


def lookup_failback_address(domain: str | None) -> str | None:
    if not domain:
        return None
    return os.getenv(failback_env_var_name(domain))


def failure_notification_env_var_name(domain: str) -> str:
    return f"{domain.replace('.', '_').upper()}_FAILURE_NOTIFICATION"


def lookup_failure_notification_address(
    domain: str | None,
    domain_settings: DomainSettings | None
) -> str | None:
    if not domain:
        return None
    env_value = os.getenv(failure_notification_env_var_name(domain))
    if env_value:
        return parse_email_address(env_value)
    if domain_settings and domain_settings.failure_notification:
        return domain_settings.failure_notification
    return None


def to_failback_env_var_name(domain: str) -> str:
    return f"{domain.replace('.', '_').upper()}_TO_FAILBACK"


def lookup_to_failback_address(domain: str | None) -> str | None:
    if not domain:
        return None
    env_value = os.getenv(to_failback_env_var_name(domain))
    if env_value:
        return parse_email_address(env_value)
    return None
