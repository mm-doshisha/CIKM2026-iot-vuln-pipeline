import base64
import json
import logging
import os
import sys
import urllib.parse

from flask import Flask, request, Response

sys.path.insert(0, os.path.dirname(__file__))
from safe_pseudo_shell import SafePseudoShell

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
logger = logging.getLogger("mock_service")

SPEC_PATH = os.environ.get("SPEC_PATH", "/app/spec.json")

app = Flask(__name__)

with open(SPEC_PATH) as f:
    spec = json.load(f)

shell = SafePseudoShell(spec.get("synthetic_filesystem", {}))


@app.route("/cgi-bin/nas_sharing.cgi", methods=["GET"])
def nas_sharing():
    user = request.args.get("user", "")
    passwd = request.args.get("passwd", "")
    cmd = request.args.get("cmd", "")
    system_param = request.args.get("system", "")

    logger.info("Request: user=%s cmd=%s system=%s", user, cmd, system_param)

    route = spec["routes"][0]

    if cmd != route["params"]["cmd"]:
        return Response("Invalid command\n", status=400, content_type="text/html")

    if not system_param:
        return Response("OK\n", status=200, content_type="text/html")

    # Handle double URL-encoding: try URL-decode first, then base64-decode
    normalized = urllib.parse.unquote(system_param)
    try:
        decoded = base64.b64decode(normalized).decode("utf-8", errors="replace")
    except Exception:
        decoded = normalized

    result = shell.execute(decoded)
    return Response(result + "\n", status=200, content_type="text/html")


@app.route("/api/shell_log", methods=["GET"])
def shell_log():
    return json.dumps(shell.execution_log, indent=2), 200, {"Content-Type": "application/json"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
