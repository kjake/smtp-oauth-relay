import asyncio
import logging
import requests
import base64
import os
import re
import uuid
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr

import dkim

from custom import CustomController
from aiosmtpd.smtp import AuthResult

from azure.identity import DefaultAzureCredential
from azure.data.tables import TableClient

import sslContext


# Load configuration from environment variables
def load_env(name, default=None, sanitize=lambda x: x, valid_values=None, convert=lambda x: x):
    value = sanitize(os.getenv(name, default))
    if valid_values and value not in valid_values:
        raise ValueError(f"Invalid {name}: {value}")
    return convert(value)

# Configuration
LOG_LEVEL = load_env(
    name='LOG_LEVEL',
    default='WARNING',
    valid_values=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
    sanitize=lambda x: x.upper()
)
TLS_SOURCE = load_env(
    name='TLS_SOURCE', 
    default='file', 
    valid_values=['off', 'file', 'keyvault'], 
    sanitize=lambda x: x.lower(),
)
REQUIRE_TLS = load_env(
    name='REQUIRE_TLS', 
    default='true', 
    valid_values=['true', 'false'], 
    sanitize=lambda x: x.lower(),
    convert=lambda x: x == 'true'
)
SERVER_GREETING = load_env(
    name='SERVER_GREETING', 
    default='Microsoft Graph SMTP OAuth Relay'
)
TLS_CERT_FILEPATH = load_env(
    name='TLS_CERT_FILEPATH',
    default='certs/cert.pem'
)
TLS_KEY_FILEPATH = load_env(
    name='TLS_KEY_FILEPATH',
    default='certs/key.pem'
)
TLS_CIPHER_SUITE = load_env(
    name='TLS_CIPHER_SUITE',
    default=None # Make it optional
)
USERNAME_DELIMITER = load_env(
    name='USERNAME_DELIMITER',
    default='@',
    valid_values=['@', ':', '|']
)
AZURE_KEY_VAULT_URL = load_env(
    name='AZURE_KEY_VAULT_URL',
    default=None,  # Make it optional
)
AZURE_KEY_VAULT_CERT_NAME = load_env(
    name='AZURE_KEY_VAULT_CERT_NAME',
    default=None,  # Make it optional
)
AZURE_TABLES_URL = load_env(
    name='AZURE_TABLES_URL',
    default=None,  # Make it optional
)
AZURE_TABLES_PARTITION_KEY = load_env(
    name='AZURE_TABLES_PARTITION_KEY',
    default='user'
)
DKIM_SELECTOR = load_env(
    name='DKIM_SELECTOR',
    default=None,
    sanitize=lambda x: x.strip() if x else x
)
DKIM_PRIVATE_KEY = load_env(
    name='DKIM_PRIVATE_KEY',
    default=None,
    sanitize=lambda x: x.replace('\\n', '\n') if x else x
)
DKIM_PRIVATE_KEY_PATH = load_env(
    name='DKIM_PRIVATE_KEY_PATH',
    default=None,
    sanitize=lambda x: x.strip() if x else x
)
DKIM_ENABLED = load_env(
    name='DKIM_ENABLED',
    default='false',
    valid_values=['true', 'false'],
    sanitize=lambda x: x.lower(),
    convert=lambda x: x == 'true'
)
DKIM_CANONICALIZATION = load_env(
    name='DKIM_CANONICALIZATION',
    default='relaxed/relaxed',
    sanitize=lambda x: x.strip().lower() if x else x
)
DKIM_HEADERS = load_env(
    name='DKIM_HEADERS',
    default='from,to,subject,date,mime-version,content-type,content-transfer-encoding',
    sanitize=lambda x: x.strip().lower() if x else x,
    convert=lambda x: [item.strip() for item in x.split(',') if item.strip()]
)
DKIM_TABLES_PARTITION_KEY = load_env(
    name='DKIM_TABLES_PARTITION_KEY',
    default='dkim'
)

ADDRESS_DOMAIN_PATTERN = re.compile(r'@([^>\s]+)')


@dataclass(frozen=True)
class DkimConfig:
    selector: str
    private_key: str
    canonicalization: str
    headers: list[str]
    source: str


DKIM_DEFAULT_CONFIG: DkimConfig | None = None


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


def extract_domain_hint(*values: str | None) -> str | None:
    for value in values:
        if not value:
            continue
        match = ADDRESS_DOMAIN_PATTERN.search(value)
        if match:
            return match.group(1).strip().strip('>')
    return None


def failback_env_var_name(domain: str) -> str:
    return f"{domain.replace('.', '_').upper()}_FROM_FAILBACK"


def lookup_failback_address(domain: str | None) -> str | None:
    if not domain:
        return None
    return os.getenv(failback_env_var_name(domain))


def decode_uuid_or_base64url(input_str: str) -> str:
    """
    Checks if input is a UUID string, otherwise attempts to decode as base64url and convert to UUID string.
    Returns a decoded string in UUID format.
    """

    # check if the input is a UUID
    uuid_pattern = re.compile(r'^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$')
    if uuid_pattern.match(input_str):
        return input_str

    # Attempt to decode as base64url
    try:
        return str(uuid.UUID(bytes=base64.urlsafe_b64decode(input_str + '=' * (-len(input_str) % 4))))
    except Exception:
        raise ValueError(f"Invalid base64url encoding in input '{input_str}'")


def split_raw_message(raw_message: bytes) -> tuple[bytes, bytes, bytes]:
    header_end = raw_message.find(b"\r\n\r\n")
    separator = b"\r\n\r\n"
    if header_end == -1:
        header_end = raw_message.find(b"\n\n")
        separator = b"\n\n"
    if header_end == -1:
        if raw_message.startswith(b"\r\n"):
            return b"", b"\r\n", raw_message[len(b"\r\n"):]
        if raw_message.startswith(b"\n"):
            return b"", b"\n", raw_message[len(b"\n"):]
        return raw_message, b"", b""
    header_bytes = raw_message[:header_end]
    body_bytes = raw_message[header_end + len(separator):]
    return header_bytes, separator, body_bytes


def update_raw_headers(raw_message: bytes, updates: dict[str, str | None]) -> bytes:
    header_bytes, separator, body_bytes = split_raw_message(raw_message)
    line_ending = b"\r\n" if b"\r\n" in header_bytes else b"\n"

    updated_keys = {key.lower() for key in updates}
    new_lines: list[bytes] = []
    skip_header = False

    for line in header_bytes.splitlines(keepends=True):
        if line.startswith((b" ", b"\t")):
            if skip_header:
                continue
            new_lines.append(line)
            continue

        header_name = line.split(b":", 1)[0].decode("utf-8", "replace").strip().lower()
        skip_header = header_name in updated_keys
        if skip_header:
            continue
        new_lines.append(line)

    for header_name, header_value in updates.items():
        if header_value is None:
            continue
        new_lines.append(f"{header_name}: {header_value}".encode("utf-8") + line_ending)

    rebuilt_headers = b"".join(new_lines)
    if separator:
        return rebuilt_headers + separator + body_bytes
    if body_bytes:
        return rebuilt_headers + (line_ending + line_ending) + body_bytes
    return rebuilt_headers


def parse_dkim_canonicalization(value: str) -> tuple[bytes, bytes]:
    parts = value.split("/", maxsplit=1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError(f"Invalid DKIM canonicalization value: {value}")
    return parts[0].encode("utf-8"), parts[1].encode("utf-8")


def normalize_dkim_private_key(value: str) -> str:
    normalized = value.strip()
    if "BEGIN" not in normalized or "PRIVATE KEY" not in normalized:
        raise ValueError("DKIM private key must be PEM-encoded")
    return normalized


def read_dkim_private_key_from_path(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return normalize_dkim_private_key(handle.read())
    except FileNotFoundError as exc:
        raise ValueError(f"DKIM private key file not found: {path}") from exc
    except OSError as exc:
        raise ValueError(f"Failed to read DKIM private key file: {path}") from exc


def build_dkim_config(
    selector: str | None,
    private_key: str | None,
    private_key_path: str | None,
    canonicalization: str,
    headers: list[str],
    source: str
) -> DkimConfig:
    if not selector:
        raise ValueError(f"DKIM selector is required ({source})")

    if private_key_path:
        if private_key:
            logging.warning(
                "Both DKIM_PRIVATE_KEY and DKIM_PRIVATE_KEY_PATH provided; using DKIM_PRIVATE_KEY_PATH (%s)",
                source
            )
        resolved_key = read_dkim_private_key_from_path(private_key_path)
    elif private_key:
        resolved_key = normalize_dkim_private_key(private_key)
    else:
        raise ValueError(f"DKIM private key is required ({source})")

    if not headers:
        raise ValueError(f"DKIM headers list cannot be empty ({source})")

    parse_dkim_canonicalization(canonicalization)

    return DkimConfig(
        selector=selector,
        private_key=resolved_key,
        canonicalization=canonicalization,
        headers=headers,
        source=source
    )


def initialize_dkim_config() -> None:
    global DKIM_DEFAULT_CONFIG

    if not DKIM_ENABLED:
        if DKIM_SELECTOR or DKIM_PRIVATE_KEY or DKIM_PRIVATE_KEY_PATH:
            logging.info("DKIM settings provided but DKIM is disabled (DKIM_ENABLED=false).")
        DKIM_DEFAULT_CONFIG = None
        return

    try:
        DKIM_DEFAULT_CONFIG = build_dkim_config(
            selector=DKIM_SELECTOR,
            private_key=DKIM_PRIVATE_KEY,
            private_key_path=DKIM_PRIVATE_KEY_PATH,
            canonicalization=DKIM_CANONICALIZATION,
            headers=DKIM_HEADERS,
            source="environment"
        )
        logging.info("DKIM signing enabled with selector '%s' (source: %s).",
                     DKIM_DEFAULT_CONFIG.selector,
                     DKIM_DEFAULT_CONFIG.source)
    except ValueError as exc:
        logging.error("DKIM configuration error: %s", exc)
        raise


def lookup_dkim_config(domain: str) -> DkimConfig | None:
    if not AZURE_TABLES_URL:
        return None

    try:
        credential = DefaultAzureCredential()
        with TableClient.from_table_url(table_url=AZURE_TABLES_URL, credential=credential) as client: # pyright: ignore[reportArgumentType]
            entities = client.query_entities(
                query_filter=f"PartitionKey eq '{DKIM_TABLES_PARTITION_KEY}' and RowKey eq '{domain}'"
            )
            entity = None
            for item in entities:
                entity = item
                break
    except Exception as exc:
        logging.error("Failed to query DKIM settings from Azure Table: %s", exc)
        return None

    if not entity:
        return None

    selector = entity.get('dkim_selector')
    private_key = entity.get('dkim_private_key')
    private_key_path = entity.get('dkim_private_key_path')
    canonicalization = entity.get('dkim_canonicalization', DKIM_CANONICALIZATION)
    headers_value = entity.get('dkim_headers')
    if headers_value:
        headers = [item.strip().lower() for item in str(headers_value).split(",") if item.strip()]
    else:
        headers = DKIM_HEADERS

    try:
        return build_dkim_config(
            selector=selector,
            private_key=private_key,
            private_key_path=private_key_path,
            canonicalization=canonicalization,
            headers=headers,
            source=f"azure table entry for domain {domain}"
        )
    except ValueError as exc:
        logging.error("Invalid DKIM settings for domain %s: %s", domain, exc)
        return None


def get_dkim_config_for_sender(from_email: str) -> DkimConfig | None:
    if not DKIM_ENABLED:
        return None
    domain = from_email.split("@", 1)[-1].lower()
    config = lookup_dkim_config(domain)
    if config:
        return config
    return DKIM_DEFAULT_CONFIG


def sign_raw_message_with_dkim(
    raw_message: bytes,
    from_email: str,
    selector: str,
    private_key: str,
    canonicalization: str,
    header_list: list[str]
) -> bytes:
    header_bytes, separator, body_bytes = split_raw_message(raw_message)
    line_ending = b"\r\n" if b"\r\n" in header_bytes else b"\n"

    domain = from_email.split("@", 1)[-1].encode("utf-8")
    canonicalize = parse_dkim_canonicalization(canonicalization)
    include_headers = [header.encode("utf-8") for header in header_list]
    signature = dkim.sign(
        message=raw_message,
        selector=selector.encode("utf-8"),
        domain=domain,
        privkey=private_key.encode("utf-8"),
        canonicalize=canonicalize,
        include_headers=include_headers
    )
    if not signature.endswith((b"\r\n", b"\n")):
        signature += line_ending

    if separator:
        return signature + header_bytes + separator + body_bytes
    if body_bytes:
        return signature + header_bytes + (line_ending + line_ending) + body_bytes
    return signature + header_bytes


def lookup_user(lookup_id: str) -> tuple[str, str, str|None]:
    """
    Search in Azure Table for user information based on the lookup_id (RowKey).
    Returns (tenant_id, client_id, from_email) or raises ValueError if not found.
    """
    if not AZURE_TABLES_URL:
        raise ValueError("AZURE_TABLES_URL environment variable not set")

    try:
        credential = DefaultAzureCredential()
        with TableClient.from_table_url(table_url=AZURE_TABLES_URL, credential=credential) as client: # pyright: ignore[reportArgumentType]
            entities = client.query_entities(query_filter=f"PartitionKey eq '{AZURE_TABLES_PARTITION_KEY}' and RowKey eq '{lookup_id}'")
            entity = None
            for i in entities:
                entity = i
                break
    except Exception as e:
        raise RuntimeError(f"Failed to query Azure Table: {str(e)}") from e

    if not entity:
        raise ValueError(f"No entity found for RowKey '{lookup_id}'")

    tenant_id = entity.get('tenant_id')
    client_id = entity.get('client_id')
    from_email = entity.get('from_email')

    if not tenant_id or not client_id:
        raise ValueError(f"Entity for RowKey '{lookup_id}' is missing tenant_id or client_id")

    return tenant_id, client_id, from_email


def parse_username(username: str) -> tuple[str, str, str|None]:
    """
    Parse the username to extract tenant_id and client_id.
    The expected format is: tenant_id{USERNAME_DELIMITER}client_id{. optional_tld}
    """
    
    # remove the optional TLD if present
    if '.' in username:
        username = username.split('.')[0]

    # Check if username is valid
    if not username or USERNAME_DELIMITER not in username:
        raise ValueError(f"Invalid username format. Expected format: tenant_id{USERNAME_DELIMITER}client_id")
    
    # Split the username by the delimiter
    parts = username.split(USERNAME_DELIMITER)
    if len(parts) != 2:
        raise ValueError(f"Invalid username format. Expected exactly one '{USERNAME_DELIMITER}' character")
    
    # check if the second part hints a user stored in the lookup table
    if parts[1] == 'lookup':
        return lookup_user(parts[0])

    # else return both parts decoded
    return decode_uuid_or_base64url(parts[0]), decode_uuid_or_base64url(parts[1]), None


def get_access_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": "https://graph.microsoft.com/.default"
    }
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    
    try:
        response = requests.post(
            url=f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token", 
            data=data, 
            headers=headers
        )
        response.raise_for_status()
        return response.json().get("access_token")
    except requests.RequestException as e:
        logging.error(f"OAuth token request failed: {str(e)}")
        if hasattr(e, 'response') and e.response:
            logging.error(f"Response status: {e.response.status_code}, Response body: {e.response.text}")
        raise


GRAPH_MIME_CONTENT_TYPE = "text/plain"


def send_email(access_token: str, body: bytes, from_email: str) -> bool:
    url = f"https://graph.microsoft.com/v1.0/users/{from_email}/sendMail"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": GRAPH_MIME_CONTENT_TYPE
    }
    
    try:
        data = base64.b64encode(body)
        logging.debug(f"Sending email from {from_email}")
        
        response = requests.post(url, data=data, headers=headers)
        if response.status_code == 202:
            logging.info("Email sent successfully!")
            return True
        else:
            logging.error(f"Failed to send email: Status code {response.status_code}")
            logging.error(f"Response body: {response.text}")
            return False
    except Exception as e:
        logging.exception(f"Exception while sending email: {str(e)}")
        return False



class Authenticator:
    def __call__(self, server, session, envelope, mechanism, auth_data):
        try:
            # Only support LOGIN and PLAIN mechanisms
            if mechanism not in ('LOGIN', 'PLAIN'):
                logging.warning(f"Unsupported auth mechanism: {mechanism}")
                return AuthResult(success=False, handled=False, message="504 5.7.4 Unsupported authentication mechanism")
                
            # Check if authentication data is present
            if not auth_data or not auth_data.login or not auth_data.password:
                logging.warning("Missing authentication data")
                return AuthResult(success=False, handled=False, message="535 5.7.8 Authentication credentials missing")
                
            try:
                login_str = auth_data.login.decode("utf-8")
            except Exception as e:
                logging.error(f"Failed to decode login string: {str(e)}")
                return AuthResult(success=False, handled=False, message="535 5.7.8 Invalid authentication credentials encoding")
            
            # Parse tenant_id and client_id from login string using the configured format
            try:
                tenant_id, client_id, from_email = parse_username(login_str)
            except ValueError as e:
                logging.error(str(e))
                return AuthResult(success=False, handled=False, message=f"535 5.7.8 {str(e)}")
                
            client_secret = auth_data.password
            session.lookup_from_email = from_email

            try:
                session.access_token = get_access_token(tenant_id, client_id, client_secret)
                return AuthResult(success=True)
            except Exception as e:
                logging.error(f"Authentication failed: {str(e)}")
                return AuthResult(success=False, handled=False, message="535 5.7.8 Authentication failed")
                
        except Exception as e:
            logging.exception(f"Unexpected error during authentication: {str(e)}")
            return AuthResult(success=False, handled=False, message="554 5.7.0 Unexpected error during authentication")


class Handler:
    async def handle_DATA(self, server, session, envelope):
        try:
            logging.info(f"Message from {envelope.mail_from} to {envelope.rcpt_tos}")

            if not hasattr(session, 'access_token'):
                logging.error("No access token available in session")
                return "530 5.7.0 Authentication required"

            raw_message = envelope.content
            parsed_message = BytesParser(policy=policy.default).parsebytes(raw_message)
            x_sender_raw = parsed_message.get('X-Sender')
            x_sender_address = parse_email_address(x_sender_raw)

            return_path_address = parse_email_address(parsed_message.get('Return-Path'))
            from_header_address = parse_email_address(parsed_message.get('From'))
            envelope_from_address = parse_email_address(envelope.mail_from)
            header_updates: dict[str, str | None] = {}

            if x_sender_raw is not None and not x_sender_address:
                replacement_sender = return_path_address or from_header_address
                if replacement_sender:
                    header_updates['X-Sender'] = replacement_sender
                    x_sender_address = replacement_sender

            from_email = x_sender_address or return_path_address or from_header_address or envelope_from_address

            if not from_email:
                domain_hint = extract_domain_hint(
                    x_sender_raw,
                    parsed_message.get('Return-Path'),
                    parsed_message.get('From'),
                    envelope.mail_from,
                    *(envelope.rcpt_tos or [])
                )
                failback_address = lookup_failback_address(domain_hint)
                if failback_address:
                    logging.warning(
                        "Using failback sender address for malformed message (domain hint: %s)",
                        domain_hint
                    )
                    from_email = failback_address
                    header_updates['From'] = failback_address
                    if not parse_email_address(parsed_message.get('X-Sender')):
                        header_updates['X-Sender'] = failback_address
                else:
                    logging.error("Unable to determine sender address and no failback configured.")
                    return "554 Transaction failed"

            if session.lookup_from_email:
                # some clients won't let you set a from address independent of the auth user. Issue: #36
                # replace from header in envelope if lookup_from_email is set
                header_updates['From'] = session.lookup_from_email
                from_email = session.lookup_from_email

            if header_updates:
                raw_message = update_raw_headers(raw_message, header_updates)

            dkim_config = get_dkim_config_for_sender(from_email)
            if dkim_config:
                try:
                    raw_message = sign_raw_message_with_dkim(
                        raw_message=raw_message,
                        from_email=from_email,
                        selector=dkim_config.selector,
                        private_key=dkim_config.private_key,
                        canonicalization=dkim_config.canonicalization,
                        header_list=dkim_config.headers
                    )
                except Exception as e:
                    logging.exception("DKIM signing failed (source: %s): %s", dkim_config.source, e)
                    return "554 5.7.0 DKIM signing failed"
            elif DKIM_ENABLED:
                logging.error(
                    "DKIM is enabled but no valid configuration is available for sender domain %s",
                    from_email.split("@", 1)[-1]
                )
                return "554 5.7.0 DKIM configuration missing"

            # Send email using Microsoft Graph API
            success = send_email(session.access_token, raw_message, from_email)

            if success:
                return "250 OK"
            else:
                return "554 Transaction failed"
                
        except Exception as e:
            logging.exception(f"Error handling DATA command: {str(e)}")
            return "554 Transaction failed"



# noinspection PyShadowingNames
async def amain():
    initialize_dkim_config()
    match TLS_SOURCE:
        case 'file':
            context = sslContext.from_file(TLS_CERT_FILEPATH, TLS_KEY_FILEPATH)
            logging.info(f"Loaded certificate from file: {TLS_CERT_FILEPATH}")
            
        case 'keyvault':
            if not AZURE_KEY_VAULT_URL or not AZURE_KEY_VAULT_CERT_NAME:
                logging.error("Azure Key Vault URL and Certificate Name must be set when TLS_SOURCE is 'keyvault'")
                raise ValueError("Azure Key Vault URL and Certificate Name must be set")
            context = sslContext.from_keyvault(AZURE_KEY_VAULT_URL, AZURE_KEY_VAULT_CERT_NAME)
            logging.info(f"Loaded certificate from Azure Key Vault: {AZURE_KEY_VAULT_CERT_NAME}")
            
        case 'off':
            context = None

        case _:
            logging.error(f"Invalid TLS_SOURCE: {TLS_SOURCE}")
            raise ValueError(f"Invalid TLS_SOURCE: {TLS_SOURCE}")

    # Configure TLS cipher suite if specified
    if context:
        if TLS_CIPHER_SUITE:
            context.set_ciphers(TLS_CIPHER_SUITE)

        logging.info(f"TLS cipher suites used: {', '.join([i['name'] for i in context.get_ciphers()])}")

    controller = None
    try:
        controller = CustomController(
            Handler(),
            hostname='', # bind dual-stack on all interfaces
            port=8025,
            ident=SERVER_GREETING,
            authenticator=Authenticator(),
            auth_required=True,
            auth_require_tls=REQUIRE_TLS,
            require_starttls=REQUIRE_TLS,
            tls_context=context
        )
        controller.start()
        logging.info("SMTP OAuth relay server started on port 8025")
    except Exception as e:
        logging.exception(f"Failed to start SMTP server: {str(e)}")
        if controller:
            controller.stop()
        raise


if __name__ == '__main__':
    # Setup logging
    logging.basicConfig(
        level=LOG_LEVEL,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    # Create event loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    # Run main function
    try:
        loop.create_task(amain())
        loop.run_forever()
    except KeyboardInterrupt:
        logging.info("Shutdown requested via keyboard interrupt")
    except Exception as e:
        logging.exception(f"Unexpected error: {str(e)}")
    finally:
        logging.info("Shutting down...")
        tasks = asyncio.all_tasks(loop)
        for task in tasks:
            task.cancel()
        loop.close()
