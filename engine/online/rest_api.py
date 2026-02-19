"""
REST API - Local Flask server exposing SentinelCLI data as REST endpoints
"""

import threading
import json
from datetime import datetime
from typing import Dict, Any, Optional, Callable

try:
    from flask import Flask, jsonify, request, abort
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


class RestAPI:
    """Lightweight Flask REST API server for SentinelCLI data"""

    def __init__(self, host: str = "127.0.0.1", port: int = 5000):
        self.host = host
        self.port = port
        self._server_thread: Optional[threading.Thread] = None
        self._running = False
        self._data_callbacks: Dict[str, Callable] = {}
        self._app: Optional[Any] = None
        self._webhook_url: str = ""

    def register_data_source(self, name: str, callback: Callable):
        """Register a data source callback (e.g. 'threats' → fn returning threat data)"""
        self._data_callbacks[name] = callback

    def set_webhook(self, url: str):
        """Set a webhook URL for outgoing notifications"""
        self._webhook_url = url

    def _build_app(self) -> Any:
        """Build the Flask application"""
        app = Flask("SentinelCLI-API")
        app.config["JSON_SORT_KEYS"] = False

        @app.route("/")
        def index():
            return jsonify({
                "service": "SentinelCLI REST API",
                "version": "1.2.0",
                "endpoints": [
                    "/api/status",
                    "/api/threats",
                    "/api/processes",
                    "/api/ports",
                    "/api/connections",
                    "/api/webhook/test",
                ],
                "timestamp": datetime.now().isoformat(),
            })

        @app.route("/api/status")
        def status():
            cb = self._data_callbacks.get("status")
            data = cb() if cb else {"status": "running", "timestamp": datetime.now().isoformat()}
            return jsonify(data)

        @app.route("/api/threats")
        def threats():
            cb = self._data_callbacks.get("threats")
            if not cb:
                return jsonify({"error": "No scan data available. Run 'threats' command first."})
            return jsonify(cb())

        @app.route("/api/processes")
        def processes():
            cb = self._data_callbacks.get("processes")
            if not cb:
                return jsonify({"error": "No process data available."})
            return jsonify(cb())

        @app.route("/api/ports")
        def ports():
            cb = self._data_callbacks.get("ports")
            if not cb:
                return jsonify({"error": "No port data available."})
            return jsonify(cb())

        @app.route("/api/connections")
        def connections():
            cb = self._data_callbacks.get("connections")
            if not cb:
                return jsonify({"error": "No connection data available."})
            return jsonify(cb())

        @app.route("/api/webhook/test", methods=["POST"])
        def webhook_test():
            """Fire a test webhook request"""
            if not self._webhook_url:
                return jsonify({"error": "No webhook URL configured"})
            try:
                import requests as req
                payload = {
                    "source": "SentinelCLI",
                    "event": "webhook_test",
                    "message": "Test webhook from SentinelCLI REST API",
                    "timestamp": datetime.now().isoformat(),
                }
                r = req.post(self._webhook_url, json=payload, timeout=10)
                return jsonify({"success": True, "status_code": r.status_code})
            except Exception as e:
                return jsonify({"error": str(e)})

        # CORS headers for browser access
        @app.after_request
        def add_cors(response):
            response.headers["Access-Control-Allow-Origin"] = "http://localhost:*"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST"
            return response

        return app

    def start(self) -> Dict[str, Any]:
        """Start the Flask server in a background daemon thread"""
        if not FLASK_AVAILABLE:
            return {"error": "Flask not installed. Run: pip install flask"}
        if self._running:
            return {"error": f"API already running on {self.host}:{self.port}"}

        self._app = self._build_app()
        self._running = True

        def _run():
            import logging
            log = logging.getLogger("werkzeug")
            log.setLevel(logging.ERROR)
            self._app.run(host=self.host, port=self.port, debug=False, use_reloader=False)

        self._server_thread = threading.Thread(target=_run, daemon=True)
        self._server_thread.start()

        return {
            "success": True,
            "url": f"http://{self.host}:{self.port}",
            "timestamp": datetime.now().isoformat(),
        }

    def stop(self):
        """Stop the server (will terminate daemon thread with process)"""
        self._running = False
        return {"success": True, "message": "API server marked for shutdown (restarts with sentinel.py)"}

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def url(self) -> str:
        return f"http://{self.host}:{self.port}"
