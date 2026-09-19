"""Immutable, fail-closed policy snapshots for the development control plane.

This module deliberately describes what a policy *permits*.  It neither detects
data nor authorizes a release.  A caller must bind the returned snapshot digest
to a run before processing it.  There is no "best effort" fallback for an
unknown format, language, category, policy, or version.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Iterable, Mapping


class PolicyError(ValueError):
    """A deliberately source-independent policy validation error."""

    MESSAGE = "Unsupported policy configuration"

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


# These are families, rather than detector labels.  A detector integration must
# explicitly map its label to one of these families before a policy can govern it.
TAXONOMY_CATEGORIES = frozenset({
    "PII",
    "HEALTH_SENSITIVE",
    "PAYMENT",
    "CREDENTIAL",
    "BUSINESS_CONFIDENTIAL",
    "QUASI_IDENTIFIER",
})
SUPPORTED_FORMATS = frozenset({"text", "json", "jsonl", "csv"})
SUPPORTED_ACTIONS = frozenset({"suppress", "generalize", "tokenize", "review", "block"})
SUPPORTED_RELEASE_MODES = frozenset({"external_anonymized", "restricted_pseudonymized"})
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,79}\Z")
_LANGUAGE = re.compile(r"(?:und|[a-z]{2,3}(?:-[A-Z]{2})?)\Z")
_MAX_RULES = 64


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and bool(_IDENTIFIER.fullmatch(value))


def _validate_language(value: object) -> str:
    if not isinstance(value, str) or not _LANGUAGE.fullmatch(value):
        raise PolicyError()
    return value


@dataclass(frozen=True, slots=True)
class PolicyRule:
    """One category action; lower priority wins between matching categories."""

    category: str
    action: str
    priority: int = 100

    def __post_init__(self) -> None:
        if (self.category not in TAXONOMY_CATEGORIES or self.action not in SUPPORTED_ACTIONS
                or isinstance(self.priority, bool) or not isinstance(self.priority, int)
                or not 0 <= self.priority <= 10_000):
            raise PolicyError()

    def canonical(self) -> dict[str, object]:
        return {"action": self.action, "category": self.category, "priority": self.priority}


@dataclass(frozen=True, slots=True)
class PolicyProfile:
    """An authoring value.  Registration seals it into a :class:`PolicySnapshot`."""

    policy_id: str
    version: str
    release_modes: tuple[str, ...]
    formats: tuple[str, ...]
    languages: tuple[str, ...]
    rules: tuple[PolicyRule, ...]

    def __post_init__(self) -> None:
        if not _valid_identifier(self.policy_id) or not _valid_identifier(self.version):
            raise PolicyError()
        for values, allowed in ((self.release_modes, SUPPORTED_RELEASE_MODES), (self.formats, SUPPORTED_FORMATS)):
            if not isinstance(values, tuple) or not values or len(values) != len(set(values)) or any(v not in allowed for v in values):
                raise PolicyError()
        if (not isinstance(self.languages, tuple) or not self.languages
                or len(self.languages) != len(set(self.languages))):
            raise PolicyError()
        for language in self.languages:
            _validate_language(language)
        if (not isinstance(self.rules, tuple) or not self.rules or len(self.rules) > _MAX_RULES
                or any(not isinstance(rule, PolicyRule) for rule in self.rules)
                or len({rule.category for rule in self.rules}) != len(self.rules)):
            raise PolicyError()

    @property
    def key(self) -> str:
        """Stable client-facing policy/version reference (for example ``baseline-v1``)."""
        return f"{self.policy_id}-{self.version}"

    def canonical(self) -> dict[str, object]:
        # Sort all unordered policy choices.  The digest therefore does not
        # change merely because an equivalent configuration was authored in a
        # different order.  Rule precedence is encoded by priority, not order.
        return {
            "formats": sorted(self.formats),
            "languages": sorted(self.languages),
            "policy_id": self.policy_id,
            "release_modes": sorted(self.release_modes),
            "rules": [rule.canonical() for rule in sorted(self.rules, key=lambda rule: (rule.category, rule.action, rule.priority))],
            "version": self.version,
        }


@dataclass(frozen=True, slots=True)
class PolicySnapshot:
    """A sealed, immutable policy value suitable for binding to a run/card."""

    key: str
    policy_id: str
    version: str
    digest: str
    release_modes: frozenset[str]
    formats: frozenset[str]
    languages: frozenset[str]
    _rules: tuple[PolicyRule, ...]
    _rule_index: Mapping[str, PolicyRule]

    @classmethod
    def seal(cls, profile: PolicyProfile) -> "PolicySnapshot":
        canonical = profile.canonical()
        encoded = json.dumps(canonical, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        rules = tuple(sorted(profile.rules, key=lambda rule: (rule.priority, rule.category, rule.action)))
        return cls(
            key=profile.key,
            policy_id=profile.policy_id,
            version=profile.version,
            digest="sha256:" + sha256(encoded).hexdigest(),
            release_modes=frozenset(profile.release_modes),
            formats=frozenset(profile.formats),
            languages=frozenset(profile.languages),
            _rules=rules,
            _rule_index=MappingProxyType({rule.category: rule for rule in rules}),
        )

    @property
    def rules(self) -> tuple[PolicyRule, ...]:
        return self._rules

    def supports(self, *, release_mode: str, format: str, language: str) -> bool:
        """Return false for all unknown values, without coercion or fallback."""
        return (release_mode in self.release_modes and format in self.formats
                and language in self.languages)

    def require_support(self, *, release_mode: str, format: str, language: str) -> None:
        if not self.supports(release_mode=release_mode, format=format, language=language):
            raise PolicyError()

    def rule_for(self, category: str) -> PolicyRule:
        """Return the sole explicit category rule; unknown/uncovered is blocked."""
        if category not in TAXONOMY_CATEGORIES or category not in self._rule_index:
            raise PolicyError()
        return self._rule_index[category]

    def effective_rule(self, categories: Iterable[str]) -> PolicyRule:
        """Choose a rule deterministically; lower numeric priority takes precedence."""
        if isinstance(categories, (str, bytes)):
            raise PolicyError()
        try:
            values = tuple(categories)
        except TypeError:
            raise PolicyError() from None
        if not values or any(category not in TAXONOMY_CATEGORIES for category in values):
            raise PolicyError()
        rules = [self._rule_index.get(category) for category in values]
        if any(rule is None for rule in rules):
            raise PolicyError()
        return min(rules, key=lambda rule: (rule.priority, rule.category, rule.action))

    def manifest(self) -> Mapping[str, object]:
        """A detached, source-free representation for a Release Card."""
        return MappingProxyType({
            "digest": self.digest,
            "formats": tuple(sorted(self.formats)),
            "key": self.key,
            "languages": tuple(sorted(self.languages)),
            "policy_id": self.policy_id,
            "release_modes": tuple(sorted(self.release_modes)),
            "version": self.version,
        })


class PolicyRegistry:
    """Process-local registry. Existing policy versions are never replaced."""

    def __init__(self, profiles: Iterable[PolicyProfile] = ()) -> None:
        self._snapshots: dict[str, PolicySnapshot] = {}
        for profile in profiles:
            self.register(profile)

    def register(self, profile: PolicyProfile) -> PolicySnapshot:
        if not isinstance(profile, PolicyProfile):
            raise PolicyError()
        snapshot = PolicySnapshot.seal(profile)
        existing = self._snapshots.get(snapshot.key)
        if existing is not None:
            # Re-registering exactly the same version is harmless, but a
            # different content digest must receive a new version identifier.
            if existing.digest != snapshot.digest:
                raise PolicyError()
            return existing
        self._snapshots[snapshot.key] = snapshot
        return snapshot

    def resolve(self, key: str) -> PolicySnapshot:
        if not _valid_identifier(key):
            raise PolicyError()
        snapshot = self._snapshots.get(key)
        if snapshot is None:
            raise PolicyError()
        return snapshot

    def keys(self) -> tuple[str, ...]:
        return tuple(sorted(self._snapshots))


def default_registry() -> PolicyRegistry:
    """Development profiles retaining M1 labels while recording explicit scope."""
    all_categories = (
        PolicyRule("CREDENTIAL", "block", 0),
        PolicyRule("PAYMENT", "suppress", 10),
        PolicyRule("HEALTH_SENSITIVE", "suppress", 20),
        PolicyRule("PII", "suppress", 30),
        PolicyRule("BUSINESS_CONFIDENTIAL", "review", 40),
        PolicyRule("QUASI_IDENTIFIER", "generalize", 50),
    )
    common = {"formats": ("text", "json", "jsonl", "csv"), "languages": ("en", "und"), "rules": all_categories}
    return PolicyRegistry((
        PolicyProfile("baseline", "v1", ("external_anonymized", "restricted_pseudonymized"), **common),
        PolicyProfile("external-release", "v1", ("external_anonymized",), **common),
        PolicyProfile("restricted-pseudonymized", "v1", ("restricted_pseudonymized",), **common),
    ))
