# Configuration Reference

This document provides a comprehensive reference for all configuration options available in the SMTP OAuth Relay.

## Table of Contents
- [Environment Variables](#environment-variables)
- [TLS Configuration](#tls-configuration)
- [Authentication Configuration](#authentication-configuration)
- [Azure Integration](#azure-integration)
- [Logging Configuration](#logging-configuration)

## Environment Variables

All configuration is done through environment variables. Below is a complete reference:

### General Settings

#### LOG_LEVEL
- **Type**: String
- **Default**: `WARNING`
- **Valid Values**: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (case-insensitive)
- **Description**: Controls the verbosity of logging output.

**Examples**:
```bash
# Development - verbose logging
LOG_LEVEL=DEBUG

# Production - minimal logging
LOG_LEVEL=WARNING

# Troubleshooting - informational messages
LOG_LEVEL=INFO
```

#### SERVER_GREETING
- **Type**: String
- **Default**: `Microsoft Graph SMTP OAuth Relay`
- **Description**: The identification string sent to clients when they connect (SMTP banner).

**Example**:
```bash
SERVER_GREETING="My Company SMTP Relay"
```

#### HTTP_TIMEOUT_SECONDS
- **Type**: Float
- **Default**: `30`
- **Description**: Timeout in seconds for outbound HTTP calls to the Microsoft identity platform and Microsoft Graph API. Increase this value if your environment has high latency.

**Example**:
```bash
HTTP_TIMEOUT_SECONDS=45
```

### TLS Configuration

#### TLS_SOURCE
- **Type**: String
- **Default**: `file`
- **Valid Values**: `off`, `file`, `keyvault` (case-insensitive)
- **Description**: Specifies where TLS certificates are loaded from.
  - `off`: TLS disabled (not recommended for production)
  - `file`: Load certificates from filesystem
  - `keyvault`: Load certificates from Azure Key Vault

**Examples**:
```bash
# Load from filesystem (default)
TLS_SOURCE=file

# Use Azure Key Vault
TLS_SOURCE=keyvault

# Disable TLS (development only)
TLS_SOURCE=off
```

#### REQUIRE_TLS
- **Type**: Boolean
- **Default**: `true`
- **Valid Values**: `true`, `false` (case-insensitive)
- **Description**: Whether to require TLS encryption for authentication. When `true`:
  - Clients must use STARTTLS before authenticating
  - Authentication attempts without TLS are rejected
  
**Security Note**: Should always be `true` in production environments.

**Examples**:
```bash
# Require TLS (recommended)
REQUIRE_TLS=true

# Allow unencrypted connections (development only)
REQUIRE_TLS=false
```

#### TLS_CERT_FILEPATH
- **Type**: String (file path)
- **Default**: `certs/cert.pem`
- **Description**: Path to PEM-encoded TLS certificate file. Only used when `TLS_SOURCE=file`.

**Example**:
```bash
TLS_CERT_FILEPATH=/etc/smtp-relay/certs/fullchain.pem
```

#### TLS_KEY_FILEPATH
- **Type**: String (file path)
- **Default**: `certs/key.pem`
- **Description**: Path to PEM-encoded TLS private key file. Only used when `TLS_SOURCE=file`.

**Example**:
```bash
TLS_KEY_FILEPATH=/etc/smtp-relay/certs/privkey.pem
```

#### TLS_CIPHER_SUITE
- **Type**: String
- **Default**: None (uses system defaults)
- **Description**: Specifies the TLS cipher suite to use for secure connections. Follows [OpenSSL cipher string format](https://docs.openssl.org/3.0/man1/openssl-ciphers/#cipher-list-format). See the following table for all [ciphers](https://wiki.mozilla.org/Security/Cipher_Suites). The used cipher suites will be logged on startup.

> [!NOTE]  
> Note that the TLS 1.3 cipher suites cannot be disabled or modified.



**Example**:
```bash
TLS_CIPHER_SUITE=DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305
```

### Authentication Configuration

#### USERNAME_DELIMITER
- **Type**: String (single character)
- **Default**: `@`
- **Valid Values**: `@`, `:`, `|`
- **Description**: Character used to separate tenant ID and client ID in the username.

**Examples**:
```bash
# Using @ delimiter (default)
USERNAME_DELIMITER=@
# Username format: tenant_id@client_id

# Using colon delimiter
USERNAME_DELIMITER=:
# Username format: tenant_id:client_id

# Using pipe delimiter
USERNAME_DELIMITER=|
# Username format: tenant_id|client_id
```

**Why change the delimiter?**
- Some email clients may have restrictions on allowed characters
- The `@` symbol is commonly expected in email usernames
- Use `:` or `|` if your client has issues with `@`

### Azure Integration

#### AZURE_KEY_VAULT_URL
- **Type**: String (URL)
- **Default**: None (optional)
- **Required When**: `TLS_SOURCE=keyvault`
- **Description**: The URL of the Azure Key Vault containing TLS certificates.

**Example**:
```bash
AZURE_KEY_VAULT_URL=https://my-keyvault.vault.azure.net/
```

**Requirements**:
- The application must have a managed identity
- The identity must have `Get Secret` permissions on the Key Vault (for example, the **Key Vault Secrets User** role)
- Certificate must be imported so its secret contains a PKCS#12 payload

#### AZURE_KEY_VAULT_CERT_NAME
- **Type**: String
- **Default**: None (optional)
- **Required When**: `TLS_SOURCE=keyvault`
- **Description**: The name of the certificate in Azure Key Vault.

**Example**:
```bash
AZURE_KEY_VAULT_CERT_NAME=smtp-relay-certificate
```

#### AZURE_TABLES_URL
- **Type**: String (URL)
- **Default**: None (optional)
- **Description**: The URL of an Azure Table for user lookup functionality. Enables storing credentials centrally.

**Example**:
```bash
AZURE_TABLES_URL=https://mystorageaccount.table.core.windows.net/users
```

**Table Schema**:
| Column | Type | Description |
|--------|------|-------------|
| PartitionKey | String | User partition (configurable via `AZURE_TABLES_PARTITION_KEY`) |
| RowKey | String | Lookup ID used in username |
| tenant_id | String | Azure tenant ID (UUID) |
| client_id | String | Application client ID (UUID) |
| from_email | String (optional) | Email address to use as sender |

See [Azure Tables Integration](azure-tables.md) for detailed setup.

#### AZURE_TABLES_PARTITION_KEY
- **Type**: String
- **Default**: `user`
- **Description**: The partition key to use when querying the Azure Table.

**Example**:
```bash
AZURE_TABLES_PARTITION_KEY=smtp-users
```

#### DOMAIN_SETTINGS_TABLES_PARTITION_KEY
- **Type**: String
- **Default**: `domain`
- **Description**: The partition key to use when querying Azure Table entries for per-domain settings such as From remapping and failure notifications.

**Example**:
```bash
DOMAIN_SETTINGS_TABLES_PARTITION_KEY=domain-settings
```

### Sender Failback Configuration

#### `<DOMAIN>_FROM_FAILBACK`
- **Type**: String (email address)
- **Default**: None (optional)
- **Description**: Provides a failback sender address when the incoming message is malformed or missing a valid sender. The variable name is derived from the sender domain by replacing `.` with `_` and uppercasing. For example, for `example.com`, set `EXAMPLE_COM_FROM_FAILBACK`.

**Example**:
```bash
EXAMPLE_COM_FROM_FAILBACK=noreply@example.com
```

#### FROM_REMAP_DOMAINS
- **Type**: Comma-separated list of domains
- **Default**: None (optional)
- **Description**: Enables From address remapping for the listed domains. When enabled, the relay replaces the message From header with the corresponding `<DOMAIN>_FROM_FAILBACK` value, and inserts the original From as a Reply-To header so replies still reach the original sender. This works alongside Azure Table settings (see `DOMAIN_SETTINGS_TABLES_PARTITION_KEY`) for per-domain control.

**Example**:
```bash
FROM_REMAP_DOMAINS=example.com,legacy.internal
```

#### FROM_REMAP_ADDRESSES
- **Type**: Comma-separated list of email addresses
- **Default**: None (optional)
- **Description**: Enables From address remapping for specific mailbox addresses. Use this when only certain senders (such as distribution groups) need remapping while other addresses in the same domain remain unchanged.

**Example**:
```bash
FROM_REMAP_ADDRESSES=accounting@example.com,ops@example.com
```

#### `<DOMAIN>_FAILURE_NOTIFICATION`
- **Type**: String (email address)
- **Default**: None (optional)
- **Description**: Address that receives failure notifications when sending a message fails for the given domain. The relay sends a basic summary including From/To/Subject and the error. The variable name is derived from the sender domain by replacing `.` with `_` and uppercasing.

**Example**:
```bash
EXAMPLE_COM_FAILURE_NOTIFICATION=mail-ops@example.com
```

### DKIM Signing Configuration

#### DKIM_ENABLED
- **Type**: Boolean
- **Default**: `false`
- **Valid Values**: `true`, `false` (case-insensitive)
- **Description**: Enables DKIM signing when `true`. If unset, DKIM signing is enabled automatically when a selector and key are provided. If you rely exclusively on Azure Table entries for DKIM configuration, set `DKIM_ENABLED=true` to turn on signing. When enabled, the relay validates DKIM settings at startup and logs errors for missing or malformed keys.

**Example**:
```bash
DKIM_ENABLED=true
```

#### DKIM_SELECTOR
- **Type**: String
- **Default**: None (optional)
- **Description**: DKIM selector used for signing. When set along with `DKIM_PRIVATE_KEY`, the relay signs outgoing messages.

**Example**:
```bash
DKIM_SELECTOR=relay
```

#### DKIM_PRIVATE_KEY
- **Type**: String (PEM-encoded key)
- **Default**: None (optional)
- **Description**: PEM-encoded private key used for DKIM signing. Use `\n` to represent newlines when setting via environment variable.

**Example**:
```bash
DKIM_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
```

#### DKIM_PRIVATE_KEY_PATH
- **Type**: String (file path)
- **Default**: None (optional)
- **Description**: Path to a PEM-encoded private key file for DKIM signing. If both `DKIM_PRIVATE_KEY` and `DKIM_PRIVATE_KEY_PATH` are set, the file path is used.

**Example**:
```bash
DKIM_PRIVATE_KEY_PATH=/etc/smtp-relay/dkim/private.key
```

#### DKIM_CANONICALIZATION
- **Type**: String
- **Default**: `relaxed/relaxed`
- **Description**: Canonicalization algorithms for DKIM signing in the form `header/body`.

**Example**:
```bash
DKIM_CANONICALIZATION=relaxed/relaxed
```

#### DKIM_HEADERS
- **Type**: Comma-separated list
- **Default**: `from,to,subject,date,message-id,mime-version,content-type,content-transfer-encoding`
- **Description**: Ordered list of headers to include in the DKIM signature.

**Example**:
```bash
DKIM_HEADERS=from,to,subject,date,message-id,mime-version,content-type,content-transfer-encoding
```

#### DKIM_TABLES_PARTITION_KEY
- **Type**: String
- **Default**: `dkim`
- **Description**: Partition key used when looking up DKIM settings per sender domain in Azure Table storage. The RowKey should match the sender domain (e.g., `example.com`).

**Example**:
```bash
DKIM_TABLES_PARTITION_KEY=dkim
```

**Domain alignment**:
Ensure the selector and private key correspond to the domain used in the message's `From` header. DKIM requires alignment between the signing domain and the sender domain.

## Configuration Examples

### Production Configuration (File-based TLS)

```bash
LOG_LEVEL=WARNING
TLS_SOURCE=file
REQUIRE_TLS=true
TLS_CERT_FILEPATH=/etc/letsencrypt/live/smtp.example.com/fullchain.pem
TLS_KEY_FILEPATH=/etc/letsencrypt/live/smtp.example.com/privkey.pem
USERNAME_DELIMITER=@
SERVER_GREETING=Example Corp SMTP Relay
```

### Production Configuration (Key Vault TLS)

```bash
LOG_LEVEL=WARNING
TLS_SOURCE=keyvault
REQUIRE_TLS=true
AZURE_KEY_VAULT_URL=https://prod-keyvault.vault.azure.net/
AZURE_KEY_VAULT_CERT_NAME=smtp-relay-cert
USERNAME_DELIMITER=@
SERVER_GREETING=Example Corp SMTP Relay
```

### Development Configuration

```bash
LOG_LEVEL=DEBUG
TLS_SOURCE=file
REQUIRE_TLS=false
TLS_CERT_FILEPATH=certs/cert.pem
TLS_KEY_FILEPATH=certs/key.pem
USERNAME_DELIMITER=@
```

### Configuration with Azure Tables

```bash
LOG_LEVEL=INFO
TLS_SOURCE=keyvault
REQUIRE_TLS=true
AZURE_KEY_VAULT_URL=https://my-keyvault.vault.azure.net/
AZURE_KEY_VAULT_CERT_NAME=smtp-cert
AZURE_TABLES_URL=https://mystorageaccount.table.core.windows.net/users
AZURE_TABLES_PARTITION_KEY=smtp-users
DKIM_SELECTOR=relay
DKIM_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
DKIM_CANONICALIZATION=relaxed/relaxed
DKIM_HEADERS=from,to,subject,date,message-id,mime-version,content-type,content-transfer-encoding
DKIM_ENABLED=true
USERNAME_DELIMITER=@
```

## Validation

The server validates configuration on startup and will fail with clear error messages if:
- Required variables are missing
- Values are outside valid ranges
- File paths don't exist (when `TLS_SOURCE=file`)
- Key Vault is inaccessible (when `TLS_SOURCE=keyvault`)

## Next Steps

- [Set up Azure/Entra ID](azure-setup.md)
- [Configure TLS certificates](installation.md#tls--certificates)
- [Configure SMTP clients](client-setup.md)
- [Set up Azure Tables](azure-tables.md)
