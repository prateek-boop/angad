import logging
import threading
import os
from flask import Flask, jsonify, send_from_directory
from flask_socketio import SocketIO, emit

class DashboardServer:
    """
    NetGuard Dashboard & API
    Provides real-time updates via WebSockets and configuration via REST API.
    """
    def __init__(self, host='0.0.0.0', port=8080):
        # Correct path to the static directory
        self.static_dir = os.path.join(os.path.dirname(__file__))
        self.app = Flask(__name__, static_folder=self.static_dir)
        self.socketio = SocketIO(self.app, cors_allowed_origins="*")
        self.host = host
        self.port = port
        self.logger = logging.getLogger(__name__)
        
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route('/')
        def serve_index():
            return send_from_directory(self.static_dir, 'index.html')

        @self.app.route('/api/status', methods=['GET'])
        def get_status():
            return jsonify({
                "status": "online",
                "engine": "NetGuard",
                "protection": "active"
            })

        @self.socketio.on('connect')
        def handle_connect():
            self.logger.info("📱 UI connected to Dashboard WebSocket.")
            emit('system_status', {'message': 'Connected to NetGuard Engine'})

    def start(self):
        """Starts the Flask-SocketIO server in a background thread."""
        threading.Thread(
            target=lambda: self.socketio.run(self.app, host=self.host, port=self.port, debug=False, use_reloader=False, allow_unsafe_werkzeug=True),
            daemon=True
        ).start()
        self.logger.info(f"📊 Dashboard API & WebSocket active at http://{self.host}:{self.port}")

    def emit_verdict(self, uid, verdict, action):
        """Pushes a real-time security verdict to the UI."""
        data = {
            "uid": uid,
            "risk_score": verdict["risk_score"],
            "classification": verdict["classification"],
            "action": action
        }
        self.socketio.emit('security_event', data)

    def emit_connection(self, conn):
        """Pushes a live connection event to the UI."""
        self.socketio.emit('new_connection', conn)
