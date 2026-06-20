"""Environment checks for Memory Firewall."""

from __future__ import annotations

import platform
import sys
from dataclasses import dataclass
from importlib import metadata

from .version import __version__


def _is_supported_amc_version(version: str | None) -> bool:
    if version is None:
        return False
    release = version.split("+", 1)[0].split("-", 1)[0]
    parts = release.split(".")
    if len(parts) < 2:
        return False
    try:
        major = int(parts[0])
        minor = int(parts[1])
    except ValueError:
        return False
    return major == 1 and minor == 3


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Machine-readable doctor result."""

    package: str
    version: str
    python_version: str
    supported_python: bool
    agent_memory_contracts_version: str | None
    agent_memory_contracts_ok: bool
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return self.supported_python and self.agent_memory_contracts_ok

    def to_dict(self) -> dict[str, object]:
        return {
            "package": self.package,
            "version": self.version,
            "python_version": self.python_version,
            "supported_python": self.supported_python,
            "agent_memory_contracts_version": self.agent_memory_contracts_version,
            "agent_memory_contracts_ok": self.agent_memory_contracts_ok,
            "warnings": list(self.warnings),
            "ok": self.ok,
        }


def doctor_report() -> DoctorReport:
    """Return local package/dependency health."""

    warnings: list[str] = []
    supported_python = (3, 10) <= sys.version_info[:2] < (3, 13)
    if not supported_python:
        warnings.append("Memory Firewall supports Python >=3.10,<3.13.")

    amc_version: str | None
    try:
        amc_version = metadata.version("agent-memory-contracts")
    except metadata.PackageNotFoundError:
        amc_version = None
        warnings.append("agent-memory-contracts>=1.3,<1.4 is not installed.")

    amc_ok = _is_supported_amc_version(amc_version)
    if amc_version is not None and not amc_ok:
        warnings.append(
            f"Expected agent-memory-contracts>=1.3,<1.4, found {amc_version}."
        )

    return DoctorReport(
        package="memory-firewall",
        version=__version__,
        python_version=platform.python_version(),
        supported_python=supported_python,
        agent_memory_contracts_version=amc_version,
        agent_memory_contracts_ok=amc_ok,
        warnings=tuple(warnings),
    )
