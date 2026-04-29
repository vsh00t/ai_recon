"""EnvAdapter — resolves secret refs from os.environ."""
from __future__ import annotations

import os

from ai_recon.core.errors import SecretResolutionError


class EnvAdapter:
    """Resolves 'env:VAR_NAME' references from os.environ.

    Accepted formats:
        - ``env:VAR_NAME``  — explicit prefix; raises if VAR_NAME not in environ.
        - ``VAR_NAME``      — bare name; returns empty string if not found.
    """

    _PREFIX = "env:"

    def resolve(self, ref: str) -> str:
        if ref.startswith(self._PREFIX):
            var_name = ref[len(self._PREFIX):]
            value = os.environ.get(var_name)
            if value is None:
                raise SecretResolutionError(
                    ref=ref,
                    reason=f"environment variable '{var_name}' is not set",
                )
            return value
        # Bare name — best-effort resolution, empty string as fallback.
        return os.environ.get(ref, "")

    def list_refs(self) -> list[str]:
        """Return all env vars starting with 'AIRECON_' as 'env:VAR' references."""
        return [
            f"{self._PREFIX}{key}"
            for key in os.environ
            if key.startswith("AIRECON_")
        ]
