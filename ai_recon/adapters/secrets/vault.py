"""VaultAdapter — resolves secrets from HashiCorp Vault KV v2."""
from __future__ import annotations

import os

try:
    import hvac
    import hvac.exceptions
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "hvac is required for VaultAdapter. "
        "Install it with: pip install hvac"
    ) from _exc

from ai_recon.core.errors import SecretResolutionError


class VaultAdapter:
    """Resolves 'vault:secret/data/path#field' references from HashiCorp Vault KV v2.

    Ref format: ``vault:<mount>/<path>#<field>``
    Example:    ``vault:secret/data/myapp/db#password``

    The Vault token is fetched from *env_adapter* (if provided) or falls back
    to ``os.environ["VAULT_TOKEN"]``.
    """

    _PREFIX = "vault:"

    def __init__(
        self,
        url: str,
        token_ref: str,
        env_adapter: object | None = None,
    ) -> None:
        self._url = url
        # Resolve the Vault token.
        if env_adapter is not None:
            token = env_adapter.resolve(token_ref)  # type: ignore[attr-defined]
        else:
            token = os.environ.get("VAULT_TOKEN", "")
        if not token:
            raise SecretResolutionError(
                ref=token_ref,
                reason="VAULT_TOKEN is not set and no env_adapter provided a value",
            )
        self._client: hvac.Client = hvac.Client(url=url, token=token)

    def resolve(self, ref: str) -> str:
        """Parse 'vault:path#field', read from Vault KV v2, return the field value."""
        if not ref.startswith(self._PREFIX):
            raise SecretResolutionError(
                ref=ref,
                reason=f"VaultAdapter only handles refs starting with '{self._PREFIX}'",
            )
        body = ref[len(self._PREFIX):]
        if "#" not in body:
            raise SecretResolutionError(
                ref=ref,
                reason="Vault ref must contain '#' to separate path and field (e.g. vault:secret/data/path#field)",
            )
        path, field = body.rsplit("#", 1)
        try:
            secret = self._client.secrets.kv.v2.read_secret_version(path=path)
        except hvac.exceptions.InvalidPath as exc:
            raise SecretResolutionError(
                ref=ref,
                reason=f"Vault path '{path}' not found: {exc}",
            ) from exc
        data: dict = secret["data"]["data"]
        if field not in data:
            raise SecretResolutionError(
                ref=ref,
                reason=f"field '{field}' not present at Vault path '{path}'",
            )
        return str(data[field])

    def list_refs(self) -> list[str]:
        """Vault enumeration is out of scope; always returns an empty list."""
        return []
