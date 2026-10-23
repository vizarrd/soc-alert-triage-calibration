"""Tiny self-hosted TwiML server. Twilio trial accounts reject inline `twiml=` on Calls.create
and twimlets.com (the free third-party alternative) turned out to force an HTTPS redirect that
Twilio's fetcher doesn't follow, breaking the call. Hosting our own endpoint avoids both problems
and lets us use <Say loop="0"> to repeat the alert indefinitely until the admin hangs up
(the whole point of a phone alert -- it shouldn't say its piece once and go quiet).
"""
from flask import Flask, request, Response
from xml.sax.saxutils import escape

app = Flask(__name__)


@app.route('/twiml', methods=['GET', 'POST'])
def twiml():
    # Twilio POSTs to webhook URLs by default -- GET is only for manual/browser testing.
    msg = request.values.get('msg', 'Security alert. Please check the SOC dashboard.')
    safe_msg = escape(msg)
    xml = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<Response><Say loop="0">' + safe_msg + '. ' + '</Say></Response>'
    )
    return Response(xml, mimetype='text/xml')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
