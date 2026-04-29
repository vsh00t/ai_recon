"""KeyringAdapter — resolves secrets via the system keyring."""
from __future__ import annotations

try:
    import keyring
except ImportError as _exc:  # pragma: no cover
    raise ImportError(
        "keyring is required for KeyringAdapter. "
        "Install it with: pip install keyring"
    ) from _exc

from ai_recon.core.errors import SecretResolutionError


class KeyringAdapter:
    """Resolves 'keyring:service/username' references via the system keyring.

    Ref format: ``keyring:<service>/<username>``
    Example:    ``keyring:myapp/api_key``
    """

    _PREFIX = "keyring:"

    def resolve(self, ref: str) -> str:
        """Return the keyring password for the given service/username pair.

        Raises:
            SecretResolutionError: if the ref format is invalid or the
                keyring returns ``None`` (credential not stored).
        """
        if not ref.startswith(self._PREFIX):
            raise SecretResolutionError(
                ref=ref,
                reason=f"KeyringAdapter only handles refs starting with '{self._PREFIX}'",
            )
        body = ref[len(self._PREFIX):]
        if "/" not in body:
            raise SecretResolutionError(
                ref=ref,
                reason="keyring ref must be 'keyring:service/username'",
            )
        service, username = body.split("/", 1)
        value = keyring.get_password(service, username)
        if value is None:
            raise SecretResolutionError(
                ref=ref,
                reason=f"no credential found in keyring for service='{service}' username='{username}'",
            )
        return value

    def list_refs(self) -> list[str]:
        """Keyring enumeration is not supported; always returns an empty list."""
        return []
