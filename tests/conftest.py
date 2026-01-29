import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


def _ensure_requests_stub() -> None:
    try:
        import requests  # noqa: F401
    except ModuleNotFoundError:
        stub = ModuleType("requests")

        class RequestException(Exception):
            pass

        def post(*_args, **_kwargs):
            raise RequestException("requests stub in tests")

        stub.RequestException = RequestException
        stub.post = post
        sys.modules["requests"] = stub


def _ensure_azure_stubs() -> None:
    try:
        import azure  # noqa: F401
    except ModuleNotFoundError:
        sys.modules["azure"] = ModuleType("azure")

    if "azure.data" not in sys.modules:
        sys.modules["azure.data"] = ModuleType("azure.data")

    if "azure.data.tables" not in sys.modules:
        tables = ModuleType("azure.data.tables")

        class TableClient:
            @staticmethod
            def from_table_url(*_args, **_kwargs):
                raise RuntimeError("azure.data.tables stub in tests")

        tables.TableClient = TableClient
        sys.modules["azure.data.tables"] = tables

    if "azure.identity" not in sys.modules:
        identity = ModuleType("azure.identity")

        class DefaultAzureCredential:  # noqa: N801 - match Azure SDK naming
            pass

        identity.DefaultAzureCredential = DefaultAzureCredential
        sys.modules["azure.identity"] = identity

    if "azure.keyvault.secrets" not in sys.modules:
        secrets = ModuleType("azure.keyvault.secrets")

        class SecretClient:  # noqa: N801 - match Azure SDK naming
            def __init__(self, *args, **kwargs):
                pass

        secrets.SecretClient = SecretClient
        sys.modules["azure.keyvault.secrets"] = secrets


_ensure_requests_stub()
_ensure_azure_stubs()
