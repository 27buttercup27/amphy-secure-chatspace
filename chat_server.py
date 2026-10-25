import asyncio
import json
import secrets
import string
import threading
import time
from collections import defaultdict
from http.server import BaseHTTPRequestHandler, HTTPServer
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import websockets

# Persistent memory databases
user_database = {}      # { username: { password_hash, public_key } }
active_connections = {} # { username: websocket }

# Failed Attempt Tracker: { username: { "attempts": int, "lockout_until": float, "tier": int } }
failed_login_tracker = defaultdict(lambda: {"attempts": 0, "lockout_until": 0, "tier": 0})

ph = PasswordHasher()

# --- TRAFFIC CONFIGURATION ---
MAX_HTTP_REQUESTS = 25
TIME_WINDOW = 60
BAN_DURATION = 300

ip_http_history = defaultdict(list)
banned_ips = {}

# --- OWASP A07: AUTHENTICATION & PASSWORD ENGINE ---
COMMON_WEAK_PASSWORDS = {"password", "12345678", "qwerty", "admin123", "amphy123"}

def generate_strong_password(length=16) -> str:
    """Generate a high-entropy password similar to modern browser suggestions."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd) and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd) and any(c in "!@#$%^&*" for c in pwd)):
            return pwd

def evaluate_password_strength(password: str) -> dict:
    """Analyze password complexity and return feedback."""
    feedback = []
    if len(password) < 12:
        feedback.append("Password must be at least 12 characters long.")
    if not any(c.isupper() for c in password):
        feedback.append("Include at least one uppercase letter.")
    if not any(c.islower() for c in password):
        feedback.append("Include at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        feedback.append("Include at least one number.")
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        feedback.append("Include at least one special character.")
    if password.lower() in COMMON_WEAK_PASSWORDS:
        feedback.append("Password is too common or easily guessable.")

    is_strong = len(feedback) == 0
    return {
        "is_strong": is_strong,
        "feedback": feedback,
        "suggested_password": generate_strong_password() if not is_strong else None
    }

def check_account_lockout(username: str) -> tuple[bool, str]:
    """Check if an account is currently locked."""
    record = failed_login_tracker[username]
    current_time = time.time()

    if current_time < record["lockout_until"]:
        remaining_seconds = int(record["lockout_until"] - current_time)
        if remaining_seconds > 3600:
            hours = int(remaining_seconds // 3600) + 1
            return True, f"Account locked for 24 hours due to multiple failed login attempts. Try again in {hours} hours."
        else:
            minutes = int(remaining_seconds // 60) + 1
            return True, f"Account locked for 30 minutes after 5 failed attempts. Try again in {minutes} minutes."
    
    return False, ""

def record_failed_login(username: str):
    """Increment failed attempts and apply 30-minute or 24-hour locks."""
    record = failed_login_tracker[username]
    current_time = time.time()

    # Reset attempts if past the previous lockout expiration
    if record["lockout_until"] > 0 and current_time >= record["lockout_until"]:
        record["lockout_until"] = 0
        record["attempts"] = 0

    record["attempts"] += 1

    # Stage 1: 5 failed attempts -> 30-minute lock
    if record["tier"] == 0 and record["attempts"] >= 5:
        record["lockout_until"] = current_time + (30 * 60)  # 30 Minutes
        record["tier"] = 1
        record["attempts"] = 0

    # Stage 2: 3 subsequent failed attempts -> 24-hour lock
    elif record["tier"] == 1 and record["attempts"] >= 3:
        record["lockout_until"] = current_time + (24 * 3600)  # 24 Hours
        record["tier"] = 2
        record["attempts"] = 0

def reset_failed_logins(username: str):
    """Reset attempt counter and lock state upon successful login."""
    if username in failed_login_tracker:
        del failed_login_tracker[username]


# --- TRAFFIC CONTROLS ---
def is_ip_banned(ip: str) -> bool:
    current_time = time.time()
    if ip in banned_ips:
        if current_time < banned_ips[ip]:
            return True
        del banned_ips[ip]
    return False

def track_and_check_rate(ip: str) -> bool:
    current_time = time.time()
    ip_http_history[ip] = [t for t in ip_http_history[ip] if current_time - t < TIME_WINDOW]
    ip_http_history[ip].append(current_time)

    if len(ip_http_history[ip]) > MAX_HTTP_REQUESTS:
        banned_ips[ip] = current_time + BAN_DURATION
        return False
    return True


# --- HTTP SERVER ---
class KeyExchangeHandler(BaseHTTPRequestHandler):

    def _get_client_ip(self) -> str:
        forwarded_for = self.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        client_ip = self._get_client_ip()
        if is_ip_banned(client_ip) or not track_and_check_rate(client_ip):
            self._send_json({"status": "error", "message": "Too many requests. Temporary IP ban active."}, code=429)
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_length).decode("utf-8"))

        # --- Password Strength Evaluation ---
        if self.path == "/api/check_password":
            pwd = body.get("password", "")
            evaluation = evaluate_password_strength(pwd)
            self._send_json({"status": "success", **evaluation})
            return

        # --- User Registration ---
        if self.path == "/api/register":
            username = body.get("username", "").strip()
            password = body.get("password", "").strip()
            public_key = body.get("public_key")

            if not username or not password or not public_key:
                self._send_json({"status": "error", "message": "All fields required"}, code=400)
                return

            strength = evaluate_password_strength(password)
            if not strength["is_strong"]:
                self._send_json({
                    "status": "error",
                    "message": "Password does not meet security requirements.",
                    "details": strength["feedback"],
                    "suggested_password": strength["suggested_password"]
                }, code=400)
                return

            if username in user_database:
                self._send_json({"status": "error", "message": "Username taken."}, code=400)
                return

            user_database[username] = {
                "password_hash": ph.hash(password),
                "public_key": public_key
            }
            self._send_json({"status": "success", "message": f"Account created for {username}"})
            return

        # --- User Login with Lockout Enforcer ---
        if self.path == "/api/login":
            username = body.get("username", "").strip()
            password = body.get("password", "").strip()
            public_key = body.get("public_key")

            if not username or not password:
                self._send_json({"status": "error", "message": "Missing credentials"}, code=400)
                return

            is_locked, lock_message = check_account_lockout(username)
            if is_locked:
                self._send_json({"status": "error", "message": lock_message}, code=429)
                return

            user = user_database.get(username)
            if not user:
                # Mask user non-existence to mitigate credential enumeration
                self._send_json({"status": "error", "message": "Invalid credentials"}, code=401)
                return

            try:
                ph.verify(user["password_hash"], password)
                reset_failed_logins(username)
                if public_key:
                    user["public_key"] = public_key
                self._send_json({"status": "success", "message": f"Welcome back {username}"})
            except VerifyMismatchError:
                record_failed_login(username)
                self._send_json({"status": "error", "message": "Invalid credentials"}, code=401)
            return

    def do_GET(self):
        if self.path.startswith("/api/get_key/"):
            username = self.path.split("/api/get_key/")[1]
            user = user_database.get(username)
            if user:
                self._send_json({"status": "success", "public_key": user["public_key"]})
            else:
                self._send_json({"status": "error", "message": "User not found"}, code=404)

    def _send_json(self, data: dict, code: int = 200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))


# --- WEBSOCKET RELAY ---
async def websocket_handler(websocket):
    username = websocket.request.path.strip("/")
    if not username or username not in user_database:
        await websocket.close()
        return

    active_connections[username] = websocket
    try:
        async for message in websocket:
            data = json.loads(message)
            recipient = data.get("recipient")
            if recipient in active_connections:
                await active_connections[recipient].send(json.dumps(data))
    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if username in active_connections:
            del active_connections[username]

def start_http_server():
    httpd = HTTPServer(("0.0.0.0", 8000), KeyExchangeHandler)
    print("Amphy Secure HTTP Server running on http://0.0.0.0:8000")
    httpd.serve_forever()

async def main():
    threading.Thread(target=start_http_server, daemon=True).start()
    print("Amphy WebSocket Relay running on ws://0.0.0.0:8001")
    async with websockets.serve(websocket_handler, "0.0.0.0", 8001):
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())