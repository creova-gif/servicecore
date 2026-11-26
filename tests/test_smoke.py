from servicecore import healthcheck


def test_healthcheck() -> None:
    assert healthcheck() == "ok"
