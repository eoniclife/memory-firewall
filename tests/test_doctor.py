from memory_firewall.doctor import _is_supported_amc_version, doctor_report


def test_supported_amc_version_range() -> None:
    assert _is_supported_amc_version("1.3.0")
    assert _is_supported_amc_version("1.3.4")
    assert not _is_supported_amc_version("1.2.9")
    assert not _is_supported_amc_version("1.4.0")
    assert not _is_supported_amc_version(None)


def test_doctor_report_shape() -> None:
    payload = doctor_report().to_dict()
    assert payload["package"] == "memory-firewall"
    assert "python_version" in payload
    assert "agent_memory_contracts_ok" in payload
    assert isinstance(payload["warnings"], list)
