"""LinkShield - Flask web app for ML-based phishing URL detection."""
import hmac
import io
import os
import secrets
import sys
from datetime import datetime, timezone

import joblib
import pandas as pd
from flask import (Flask, redirect, render_template, request, send_file,
                   session, url_for)
from flask_sqlalchemy import SQLAlchemy
from fpdf import FPDF

try:  # optional: load variables from a local .env file
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASE_DIR, "models"))

from analyze import FEATURE_NAMES, extract_features  # noqa: E402

FEATURE_COLUMNS = [n for n in FEATURE_NAMES if n != "result"]

# ---------------------------------------------------------------- model
MODEL_CANDIDATES = [
    os.path.join(BASE_DIR, "models", "linkshield_model.pkl"),
    os.path.join(BASE_DIR, "linkshield_model.pkl"),
]
MODEL_PATH = next((p for p in MODEL_CANDIDATES if os.path.exists(p)), None)
if MODEL_PATH is None:
    raise FileNotFoundError(
        "Model file not found. Run `python models/train.py` first "
        "(see README for the dataset)."
    )
linkshield_model = joblib.load(MODEL_PATH)

# ---------------------------------------------------------------- app config
app = Flask(__name__)
# Secrets come from environment variables - never hard-code them.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")  # admin login disabled if unset
MODEL_ACCURACY = float(os.environ.get("MODEL_ACCURACY", 91.48))

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)


def utcnow():
    return datetime.now(timezone.utc)


class ScanRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url_address = db.Column(db.String(500), nullable=False)
    result = db.Column(db.String(50), nullable=False)
    timestamp = db.Column(db.DateTime, default=utcnow)


with app.app_context():
    db.create_all()

import re

URL_PATTERN = re.compile(
    r"^(https?://)?([^\s/@]+@)?"
    r"(([a-z0-9_-]+\.)+[a-z][a-z0-9-]+|(\d{1,3}\.){3}\d{1,3})"
    r"(:\d+)?([/?#]\S*)?$",
    re.IGNORECASE,
)


def is_valid_url(url):
    """Reject text that doesn't look like a URL (e.g. random characters)."""
    return bool(URL_PATTERN.match(url.strip()))
# ---------------------------------------------------------------- analysis
def analyze_url(url):
    """Return (feature_vector | None, list_of_human_readable_reasons)."""
    clean = str(url).lower().strip()
    clean = clean.replace("https://", "").replace("http://", "").rstrip("/")

    features = extract_features(clean, 0)
    if features is None:
        return None, ["🚩 Malformed URL: could not be parsed."]
    features = features[:-1]  # drop the label column

    reasons = []
    if "https" not in str(url).lower():
        reasons.append("🚩 Insecure Connection: Protocol 'https' not detected.")
    if len(clean) > 75:
        reasons.append(f"🚩 URL is unusually long ({len(clean)} characters).")

    domain = clean.split("/")[0]
    digit_count = sum(c.isdigit() for c in domain)
    if digit_count > 6:
        reasons.append(f"🚩 Too many digits in domain ({digit_count}).")
    hyphen_count = domain.count("-")
    if hyphen_count >= 3:
        reasons.append(f"🚩 Too many hyphens in domain ({hyphen_count}).")
    if "@" in clean:
        reasons.append("🚩 '@' symbol detected in URL. This is suspicious.")
    if domain.replace(".", "").isdigit():
        reasons.append("🚩 Domain appears to be an IP address.")

    return features, reasons


def generate_pdf(url, result, reasons, recommendation):
    """Build the PDF report in memory (no temp files, safe for concurrent users)."""
    pdf = FPDF()
    pdf.add_page()

    def line(text, size=12, style=""):
        pdf.set_font("Helvetica", style, size)
        safe = str(text).encode("latin-1", "ignore").decode("latin-1")
        pdf.multi_cell(0, 8, safe, new_x="LMARGIN", new_y="NEXT")

    line("LinkShield Scan Report", 16, "B")
    pdf.ln(6)
    line(f"URL: {url}")
    line(f"Result: {result}")
    pdf.ln(2)
    line("Technical Analysis:", 12, "B")
    if reasons:
        for r in reasons:
            line(f"- {r}")
    else:
        line("- No anomalies detected in URL structure.")
    pdf.ln(4)
    line(f"Guidance: {recommendation}")

    buffer = io.BytesIO(bytes(pdf.output()))
    buffer.seek(0)
    return buffer


# ---------------------------------------------------------------- routes
@app.route("/", methods=["GET", "POST"])
def home():
    result, reasons, recommendation, error = None, [], "", None
    url = ""

    if request.method == "POST":
        url = request.form.get("url", "").strip()[:500]
        features, reasons = analyze_url(url) if is_valid_url(url) else (None, [])
        if features is None:
            error = "Please enter a valid URL."
        else:
            X = pd.DataFrame([features], columns=FEATURE_COLUMNS)
            prediction = linkshield_model.predict(X)[0]

            if prediction == 0:
                result = "SAFE"
                recommendation = ("The intelligence scan confirms this link is "
                                  "legitimate. No phishing indicators found.")
            else:
                result = "MALICIOUS"
                recommendation = ("CRITICAL: Phishing signature detected. Accessing "
                                  "this link may compromise your security.")

            history = session.get("history", [])
            history.append({
                "url": url,
                "result": result,
                "time": utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            })
            session["history"] = history[-50:]  # keep the cookie small

            db.session.add(ScanRecord(url_address=url, result=result))
            db.session.commit()

    return render_template("main.html", result=result, reasons=reasons,
                           recommendation=recommendation, url=url,
                           error=error, accuracy=MODEL_ACCURACY)


@app.route("/download_pdf", methods=["POST"])
def download_pdf():
    pdf = generate_pdf(
        request.form.get("url", ""),
        request.form.get("result", ""),
        request.form.getlist("reasons"),
        request.form.get("recommendation", ""),
    )
    return send_file(pdf, as_attachment=True, download_name="scan_report.pdf",
                     mimetype="application/pdf")


@app.route("/history")
def history():
    return render_template("history.html", history=session.get("history", []))


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        if not ADMIN_PASSWORD:
            error = "Admin login is disabled (ADMIN_PASSWORD is not set)."
        elif (hmac.compare_digest(u.encode(), ADMIN_USERNAME.encode())
              and hmac.compare_digest(p.encode(), ADMIN_PASSWORD.encode())):
            session["admin_logged_in"] = True
            return redirect(url_for("admin_dashboard"))
        else:
            error = "Wrong username or password."
    return render_template("admin_login.html", error=error)


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
def admin_dashboard():
    if not session.get("admin_logged_in"):
        return redirect(url_for("admin_login"))

    filter_value = request.args.get("filter", "ALL")
    query = ScanRecord.query
    if filter_value in ("SAFE", "MALICIOUS"):
        query = query.filter_by(result=filter_value)
    latest = query.order_by(ScanRecord.timestamp.desc()).limit(50).all()

    return render_template(
        "admin.html",
        total_scans=ScanRecord.query.count(),
        safe_count=ScanRecord.query.filter_by(result="SAFE").count(),
        malicious_count=ScanRecord.query.filter_by(result="MALICIOUS").count(),
        accuracy=MODEL_ACCURACY,
        error_rate=round(100 - MODEL_ACCURACY, 2),
        latest=latest,
        filter=filter_value,
    )


if __name__ == "__main__":
    # Debug mode exposes an interactive console - enable it only locally.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
