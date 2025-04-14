from flask import Flask, request, jsonify, send_file
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from secretsharing import PlaintextToHexSecretSharer
import base64, os

app = Flask(__name__)

# ------------------ Key Derivation ------------------ #
def derive_key_from_string(seed_string, salt=None):
    if not salt:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    key = kdf.derive(seed_string.encode())
    return key, salt

# ------------------ RSA Key Generation ------------------ #
@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    seed = request.json.get("seed")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key, salt = derive_key_from_string(seed)

    encrypted_private = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(key)
    )

    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    os.makedirs("keys", exist_ok=True)
    with open("keys/private_key.pem", "wb") as f: f.write(encrypted_private)
    with open("keys/public_key.pem", "wb") as f: f.write(public_key)

    return jsonify({
        "message": "Keys generated successfully!",
        "salt": base64.b64encode(salt).decode(),
        "public_key": public_key.decode()
    })

# ------------------ Secret Sharing ------------------ #
@app.route("/split_secret", methods=["POST"])
def split_secret():
    secret = request.json.get("secret")
    threshold = request.json.get("threshold", 2)
    parts = request.json.get("parts", 3)
    hex_secret = secret.encode().hex()
    shares = PlaintextToHexSecretSharer.split_secret(hex_secret, threshold, parts)
    return jsonify({"shares": shares})

@app.route("/recover_secret", methods=["POST"])
def recover_secret():
    shares = request.json.get("shares")
    hex_secret = PlaintextToHexSecretSharer.recover_secret(shares)
    return jsonify({"recovered": bytes.fromhex(hex_secret).decode()})

# ------------------ Encrypt File ------------------ #
@app.route("/encrypt", methods=["POST"])
def encrypt_file():
    with open("keys/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    with open("message.txt", "rb") as f:
        message = f.read()
    encrypted = public_key.encrypt(
        message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    with open("encrypted.bin", "wb") as f:
        f.write(encrypted)
    return send_file("encrypted.bin", as_attachment=True)

# ------------------ Decrypt File ------------------ #
@app.route("/decrypt", methods=["POST"])
def decrypt_file():
    with open("keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    with open("encrypted.bin", "rb") as f:
        encrypted_data = f.read()
    decrypted = private_key.decrypt(
        encrypted_data,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    with open("decrypted.txt", "wb") as f:
        f.write(decrypted)
    return send_file("decrypted.txt", as_attachment=True)

@app.route("/")
def home():
    return "🛡️ Crypto Flask API is Live!"

