"""Read-only Aperture CLI integration for Pairling runtime status."""

from .status import (
    APERTURE_CLI_KNOWN_VERSION,
    APERTURE_CLI_PROVIDER_PATH,
    APERTURE_CLI_STATUS_PATH,
    ApertureCLIProbe,
    provider_payload,
    status_payload,
)
from .launch import command_for_context, contexts_payload, validate_launch_context

__all__ = [
    "APERTURE_CLI_KNOWN_VERSION",
    "APERTURE_CLI_PROVIDER_PATH",
    "APERTURE_CLI_STATUS_PATH",
    "ApertureCLIProbe",
    "command_for_context",
    "contexts_payload",
    "provider_payload",
    "status_payload",
    "validate_launch_context",
]
