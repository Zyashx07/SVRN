from flask import Flask, request, jsonify, render_template, url_for
from flask_sqlalchemy import SQLAlchemy
from flask import session, redirect, flash
from flask_cors import CORS
from datetime import datetime
import os, zlib, time, threading
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY") or os.urandom(32)


# SQLite DB setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///svrn_messages.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# -------------------------
# Database Model
# -------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(20), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120))
    priority = db.Column(db.String(10))
    timestamp = db.Column(db.String(50))
    sender_id = db.Column(db.String(80))

# -------------------------
# Host hardcoded login setup
# -------------------------
HOST_USERNAME = "krishna"
HOST_PASSWORD = "krishna21"


with app.app_context():
    db.create_all()


queue = []
delivered = []
DATA_FOLDER = "data"
os.makedirs(DATA_FOLDER, exist_ok=True)



# -------------------------
# Encryption Function
# -------------------------
def encrypt_data(data: bytes, passphrase: str):
    key = passphrase.encode().ljust(32, b"0")[:32]
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    enc = aesgcm.encrypt(nonce, data, None)
    return nonce + enc

# -------------------------
# FRONTEND ROUTES
# -------------------------
@app.route('/')
def index():
    return render_template('home.html')  # home shows host link, client panel, system status

@app.route('/host-login', methods=['GET', 'POST'])
def host_login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if username == HOST_USERNAME and password == HOST_PASSWORD:
            session['username'] = username
            session['role'] = 'host'
            flash("✅ Logged in as Host", "success")
            return redirect('/host')
        else:
            flash("❌ Invalid host credentials", "danger")
            return redirect('/host-login')
    return render_template('host_login.html')  # simple login form for host



# ---- PROTECTED ROUTES ----
from functools import wraps
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'host':
            flash("🚫 Access Denied", "danger")
            return redirect('/')
        return f(*args, **kwargs)
    return decorated


@app.route('/host')
@login_required
def host():
    return render_template('host.html')


# Clients only see this
@app.route('/client')
def client():
    return render_template('client.html')


from flask import jsonify

@app.route('/api/decrypted_messages')
@login_required
def decrypted_messages():
    PASSPHRASE = "default"  # same as backend
    all_msgs = []

    for msg in Message.query.order_by(Message.id.desc()).limit(20).all():  # latest 20
        try:
            with open(os.path.join(DATA_FOLDER, msg.filename), "rb") as f:
                enc = f.read()
            key = PASSPHRASE.encode().ljust(32, b"0")[:32]
            nonce = enc[:12]
            ciphertext = enc[12:]
            aesgcm = AESGCM(key)
            decrypted = aesgcm.decrypt(nonce, ciphertext, None)
            text = zlib.decompress(decrypted).decode()
        except Exception:
            text = "[Decryption failed]"

        all_msgs.append({
            "sender": msg.sender_id,
            "timestamp": msg.timestamp,
            "content": text
        })

    return jsonify(all_msgs)

@app.route('/host-logout')
@login_required
def host_logout():
    session.clear()  # removes username and role
    flash("✅ Host logged out successfully", "info")
    return redirect('/')  # go back to home page


# -------------------------
# API ROUTES
# -------------------------
@app.route('/api/send_text', methods=['POST'])
def send_text():
    data = request.json
    text = data.get('text', '')
    priority = int(data.get('priority', 1))
    passphrase = data.get('passphrase', 'default')
    sender_id = data.get('sender_id') or request.remote_addr or 'Unknown'

    comp = zlib.compress(text.encode())
    enc = encrypt_data(comp, passphrase)

    filename = f"msg_{int(time.time())}.bin"
    with open(os.path.join(DATA_FOLDER, filename), "wb") as f:
        f.write(enc)

    client_time = data.get('timestamp') or time.strftime("%Y-%m-%d %H:%M:%S")

    msg = Message(
        filename=filename,
        priority=priority,
        timestamp=client_time,
        sender_id=sender_id
    )
    db.session.add(msg)
    db.session.commit()

    queue.append((priority, enc))
    queue.sort(key=lambda x: x[0])
    print(f"[+] Queued {filename} from {sender_id}")

    return jsonify({"status": "queued", "file": filename, "sender": sender_id}), 200

@app.route('/api/receive', methods=['GET'])
def receive():
    if not queue:
        print("[!] No messages in queue")
        return jsonify({"status": "No messages in queue"}), 404
    priority, enc = queue.pop(0)
    delivered.append(enc)
    print(f"[✓] Delivered one message. Queue now: {len(queue)} | Delivered: {len(delivered)}")
    return jsonify({"status": "Delivered", "length": len(enc)}), 200

@app.route('/api/status')
def status():
    total = Message.query.count()
    print(f"[STATUS] Queue={len(queue)}, Delivered={len(delivered)}, Total={total}")
    return jsonify({
        "queue_length": len(queue),
        "delivered_count": len(delivered),
        "total_stored": total
    })

@app.route('/api/recent')
def recent_messages():
    messages = Message.query.order_by(Message.id.desc()).limit(10).all()
    return jsonify([
        {
            "filename": m.filename,
            "priority": m.priority,
            "timestamp": m.timestamp,
            "sender_id": m.sender_id
        } for m in messages
    ])

# -------------------------
# Auto Deliver Thread
# -------------------------
def auto_deliver():
    while True:
        time.sleep(10)
        if queue:
            p, e = queue.pop(0)
            delivered.append(e)
            print("[✓] Auto delivered message (10s cycle)")

threading.Thread(target=auto_deliver, daemon=True).start()

# -------------------------
# App Launch (Render-Ready)
# -------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    print("✅ Database initialized and ready")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
