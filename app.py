"""Flask routes for VoiceSOC."""
from flask import Flask, jsonify, render_template

import config

app = Flask(__name__)


@app.route("/")
def index():
    """Serve the dashboard page."""
    return render_template("index.html")


@app.route("/health")
def health():
    """Simple health check."""
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)
