"""Twilio phone-call alerting. Fails soft: if Twilio isn't configured (no credentials in .env),
the engine logs a warning and continues -- it never crashes the pipeline over a missing integration.

Points Twilio at our own self-hosted TwiML endpoint (twiml_server.py, running on this same VM on
port 8080) instead of a third party. Two things ruled out third-party options:
  - Passing `twiml=` inline is rejected by trial Twilio accounts ("disallowed parameters").
  - twimlets.com (a free third-party TwiML generator) force-redirects HTTP->HTTPS, and Twilio's
    fetcher doesn't follow that redirect, so the call played Twilio's generic error message.
Hosting our own endpoint also lets the call use <Say loop="0"> to repeat the alert indefinitely
until the admin manually hangs up, instead of playing once and going silent.
"""
import urllib.parse
import urllib.request
import config

_METADATA_URL = ("http://169.254.169.254/computeMetadata/v1/instance/network-interfaces/0/"
                  "access-configs/0/external-ip")


def _get_own_external_ip():
    """Ask GCP's metadata service for this VM's current external IP -- it changes on every
    restart, so it can't be hardcoded. Falls back to config.PUBLIC_HOST if set (e.g. for
    testing from a machine that isn't the VM itself)."""
    fallback = getattr(config, 'PUBLIC_HOST', None)
    try:
        req = urllib.request.Request(_METADATA_URL, headers={'Metadata-Flavor': 'Google'})
        return urllib.request.urlopen(req, timeout=2).read().decode().strip()
    except Exception:
        if fallback:
            return fallback
        raise


def call_admin(reason_text):
    """Places a real phone call that repeats `reason_text` on loop via our own TwiML server,
    until the admin hangs up. Returns True if a call was actually placed, False if skipped/failed."""
    if not (config.TWILIO_ACCOUNT_SID and config.TWILIO_AUTH_TOKEN
            and config.TWILIO_FROM_NUMBER and config.TWILIO_TO_NUMBER):
        print(f"[notifier] Twilio not configured -- skipping call. Would have said: {reason_text}")
        return False

    try:
        from twilio.rest import Client
    except ImportError:
        print("[notifier] twilio package not installed (pip install twilio) -- skipping call.")
        return False

    try:
        host = _get_own_external_ip()
    except Exception as e:
        print(f"[notifier] Could not determine public IP for TwiML server -- skipping call: {e}")
        return False

    try:
        client = Client(config.TWILIO_ACCOUNT_SID, config.TWILIO_AUTH_TOKEN)
        encoded_msg = urllib.parse.quote(reason_text)
        url = f"http://{host}:8080/twiml?msg={encoded_msg}"
        call = client.calls.create(
            url=url,
            to=config.TWILIO_TO_NUMBER,
            from_=config.TWILIO_FROM_NUMBER,
        )
        print(f"[notifier] Call placed, sid={call.sid}, status={call.status}, twiml_url={url}")
        return True
    except Exception as e:
        # Twilio/network failures shouldn't crash alert processing -- the incident is
        # already safely recorded in the DB regardless of whether the call succeeded.
        print(f"[notifier] Call failed: {e}")
        return False
