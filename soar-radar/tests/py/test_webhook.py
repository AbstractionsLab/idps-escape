import responses
from webhook import ensure_webhook

@responses.activate
def test_destinations_path_first():
    base = "http://dash:5601"
    # Feature detection endpoint exists
    responses.add(responses.GET, f"{base}/api/alerting/destinations", json={"destinations":[]}, status=200)
    # Create destination
    responses.add(responses.POST, f"{base}/api/alerting/destinations",
                  json={"id":"dest-1"}, status=200)

    dest_id = ensure_webhook(base, "u", "p", False, "RADAR Hook", "http://wh/hit")
    assert dest_id == "dest-1"

@responses.activate
def test_notifications_fallback():
    base = "http://dash:5601"
    # Feature detection says no (simulate 404 on list call by returning 403 on probe)
    responses.add(responses.GET, f"{base}/api/alerting/destinations", status=404)
    # List notifications
    responses.add(responses.GET, f"{base}/api/notifications", json={"data":{"items":[]}}, status=200)
    # Create notifications
    responses.add(responses.POST, f"{base}/api/notifications/create_config", json={"config_id":"notif-7"}, status=200)

    dest_id = ensure_webhook(base, "u", "p", False, "RADAR Hook", "http://wh/hit")
    assert dest_id == "notif-7"
