from honeypots.rate_limit import InMemoryPerIPRateLimiter


def test_rate_limit_triggers_after_threshold():
    limiter = InMemoryPerIPRateLimiter(threshold=2, window_seconds=10)

    d1 = limiter.hit("1.2.3.4", now=0.0)
    d2 = limiter.hit("1.2.3.4", now=1.0)
    d3 = limiter.hit("1.2.3.4", now=2.0)

    assert d1.triggered is False
    assert d2.triggered is False
    assert d3.triggered is True
    assert d3.count_in_window == 3


def test_rate_limit_window_expires_old_hits():
    limiter = InMemoryPerIPRateLimiter(threshold=2, window_seconds=1)

    limiter.hit("5.6.7.8", now=0.0)
    limiter.hit("5.6.7.8", now=0.5)
    d = limiter.hit("5.6.7.8", now=2.0)

    assert d.triggered is False
    assert d.count_in_window == 1


def test_rate_limit_is_per_ip():
    limiter = InMemoryPerIPRateLimiter(threshold=1, window_seconds=60)

    a1 = limiter.hit("10.0.0.1", now=0.0)
    b1 = limiter.hit("10.0.0.2", now=0.0)
    a2 = limiter.hit("10.0.0.1", now=1.0)

    assert a1.triggered is False
    assert b1.triggered is False
    assert a2.triggered is True
