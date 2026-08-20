import logging
import os
import socket
import threading
import time

from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO, emit


class DashboardServer:
    """
    NetGuard Dashboard & API
    Provides real-time updates via WebSockets and configuration via REST API.
    """
    def __init__(self, host='127.0.0.1', port=8080):
        # Correct path to the static directory
        self.static_dir = os.path.join(os.path.dirname(__file__))
        self.app = Flask(__name__, static_folder=self.static_dir)
        self.socketio = SocketIO(self.app)
        self.host = host
        self.port = port
        self.logger = logging.getLogger(__name__)
        self._status_provider = None
        
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route('/')
        def serve_index():
            return send_from_directory(self.static_dir, 'index.html')

        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            details = self._status_provider() if self._status_provider else {}
            proxy_ready = details.get("proxy", {}).get("is_running", False)
            enforcement_ready = details.get("enforcer", {}).get("is_initialized", False)
            traffic_models_ready = details.get("ai_engine", {}).get(
                "model_stack_ready", False
            )
            url_model_ready = details.get("url_reputation", {}).get(
                "model_available", False
            )
            models_ready = traffic_models_ready and url_model_ready
            ready = proxy_ready and enforcement_ready and models_ready
            return jsonify({
                "status": "online" if ready else "degraded",
                "engine": "NetGuard",
                "protection": "active" if ready else "inactive",
                "checks": {
                    "proxy_ready": proxy_ready,
                    "enforcement_ready": enforcement_ready,
                    "models_ready": models_ready,
                },
                "details": details,
            })

        @self.socketio.on('connect')
        def handle_connect():
            self.logger.info("📱 UI connected to Dashboard WebSocket.")
            emit('system_status', {'message': 'Connected to NetGuard Engine'})

    def start(self) -> bool:
        """Starts the Flask-SocketIO server in a background thread."""
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            probe.bind((self.host, self.port))
        except OSError as e:
            self.logger.error("Dashboard cannot bind to %s:%s: %s", self.host, self.port, e)
            return False
        finally:
            probe.close()

        threading.Thread(
            target=lambda: self.socketio.run(
                self.app,
                host=self.host,
                port=self.port,
                debug=False,
                use_reloader=False,
                allow_unsafe_werkzeug=True,
            ),
            daemon=True,
        ).start()
        self.logger.info(f"📊 Dashboard API & WebSocket active at http://{self.host}:{self.port}")
        return True

    def set_status_provider(self, provider):
        self._status_provider = provider

    def emit_verdict(self, uid, verdict, action, reason="", features=None,
                     feature_names=None, connection=None):
        """Pushes a real-time security verdict to the UI."""
        feature_vector = list(features or [])
        feature_values = dict(zip(feature_names or [], feature_vector))
        data = {
            "schema_version": 1,
            "timestamp": time.time(),
            "uid": uid,
            "risk_score": verdict["risk_score"],
            "classification": verdict["classification"],
            "action": action,
            "reason": reason,
            "features": feature_values,
            "feature_vector": feature_vector,
            "connection": connection or {},
        }
        self.socketio.emit('security_event', data)

    def emit_connection(self, conn):
        """Pushes a live connection event to the UI."""
        self.socketio.emit('new_connection', conn)
