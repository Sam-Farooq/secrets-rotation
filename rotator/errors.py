"""One exception per reason a rotation stops, because the caller treats them
differently: a config error means do not start, a store or provider error means
stop where you are, and a refusal means the target is not ours to touch."""

from __future__ import annotations


class RotatorError(Exception):
    pass


class ConfigError(RotatorError):
    """targets.toml says something that cannot be acted on."""


class Refused(RotatorError):
    """A secret id outside the declared set. The IAM policy is the real
    boundary; this is the one that produces a readable message."""


class StoreError(RotatorError):
    """Secrets Manager or Vault would not do what was asked."""


class ProviderError(RotatorError):
    """The database would not do what was asked."""
