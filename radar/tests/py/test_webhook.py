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



@responses.activate
def test_channel_is_created_with_secret_header():
    base = "http://dash:5601"
    responses.add(responses.GET, f"{base}/_plugins/_notifications/configs", json={"config_list": []}, status=200)
    responses.add(responses.POST, f"{base}/_plugins/_notifications/configs", json={"config_id": "c1"}, status=200)
    ensure_webhook(base, "u", "p", False, "RADAR_Webhook", "http://wh/notify",
                   headers={"X-RADAR-Webhook-Token": "abc"})
    import json
    body = json.loads(responses.calls[1].request.body)
    assert body["config"]["webhook"]["header_params"] == {"X-RADAR-Webhook-Token": "abc"}


@responses.activate
def test_existing_channel_without_header_is_updated():
    base = "http://dash:5601"
    existing = {"config_id": "c1", "config": {"name": "RADAR_Webhook", "config_type": "webhook",
                                               "webhook": {"url": "http://wh/notify"}}}
    responses.add(responses.GET, f"{base}/_plugins/_notifications/configs", json={"config_list": [existing]}, status=200)
    responses.add(responses.PUT, f"{base}/_plugins/_notifications/configs/c1", json={"config_id": "c1"}, status=200)
    cid = ensure_webhook(base, "u", "p", False, "RADAR_Webhook", "http://wh/notify",
                         headers={"X-RADAR-Webhook-Token": "abc"})
    import json
    assert cid == "c1"
    assert json.loads(responses.calls[1].request.body)["config"]["webhook"]["header_params"]["X-RADAR-Webhook-Token"] == "abc"


def test_ensure_secret_generates_once(tmp_path):
    from wazuh_api import envfile
    p = tmp_path / ".env"
    a = envfile.ensure_secret(p, "WEBHOOK_SHARED_SECRET")
    assert len(a) == 64 and envfile.ensure_secret(p, "WEBHOOK_SHARED_SECRET") == a
