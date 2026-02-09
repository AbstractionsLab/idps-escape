import responses
from anomaly_detector.webhook import ensure_webhook


@responses.activate
def test_destinations_path_first():
    base = "http://dash:5601"

    responses.add(
        responses.GET,
        f"{base}/_plugins/_notifications/configs",
        json={"config_list": []},
        status=200,
    )

    responses.add(
        responses.POST,
        f"{base}/_plugins/_notifications/configs",
        json={"config_id": "dest-1"},
        status=200,
    )

    dest_id = ensure_webhook(base, "u", "p", False, "RADAR Hook", "http://wh/hit")
    assert dest_id == "dest-1"


@responses.activate
def test_notifications_fallback():
    base = "http://dash:5601"

    responses.add(
        responses.GET,
        f"{base}/_plugins/_notifications/configs",
        json={"config_list": []},
        status=200,
    )

    responses.add(
        responses.POST,
        f"{base}/_plugins/_notifications/configs",
        json={},
        status=200,
    )

    responses.add(
        responses.GET,
        f"{base}/_plugins/_notifications/configs",
        json={
            "config_list": [
                {
                    "config_id": "notif-7",
                    "config": {
                        "name": "RADAR Hook",
                        "description": "",
                        "config_type": "webhook",
                        "is_enabled": True,
                        "webhook": {"url": "http://wh/hit"},
                    },
                }
            ]
        },
        status=200,
    )

    dest_id = ensure_webhook(base, "u", "p", False, "RADAR Hook", "http://wh/hit")
    assert dest_id == "notif-7"

