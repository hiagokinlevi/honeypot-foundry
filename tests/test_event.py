from honeypots.common.event import HoneypotEvent, _mask_credential, ServiceType


def test_credential_is_masked():
    """Raw credential must never be stored in the event."""
    event = HoneypotEvent(
        service=ServiceType.SSH,
        source_ip="1.2.3.4",
        source_port=1234,
        username="root",
        credential_observed="s3cr3t_p4ss",
    )
    assert "s3cr3t_p4ss" not in event.credential_observed
    assert event.credential_observed.startswith("[masked:")


def test_mask_credential_format():
    masked = _mask_credential("password")
    assert masked.startswith("[masked:len=8,hash_prefix=")
    assert len(masked) > 20


def test_already_masked_not_double_masked():
    event = HoneypotEvent(
        service=ServiceType.SSH,
        source_ip="1.2.3.4",
        source_port=1234,
        credential_observed="[masked:len=5,hash_prefix=abcd1234]",
    )
    # Should not be double-masked
    assert event.credential_observed.count("[masked:") == 1


def test_event_without_credential():
    event = HoneypotEvent(
        service=ServiceType.HTTP,
        source_ip="1.2.3.4",
        source_port=80,
        path="/robots.txt",
        method="GET",
    )
    assert event.credential_observed is None
