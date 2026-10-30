# app.py
# Main Flask file for the Privacy Monitor frontend (version 1).
# This file only serves pages and passes SAMPLE data to the templates.
# There is no database, no real login, and no real scanning yet.

from flask import Flask, render_template, redirect, url_for

app = Flask(__name__)

# ---------------------------------------------------------------
# SAMPLE (DEMONSTRATION) DATA
# None of this is real. It is only here so the pages have content.
# ---------------------------------------------------------------

# Fake user used for the profile area in the top bar
SAMPLE_USER = {"name": "Sample User", "email": "sample.user@example.com"}

# Numbers for the dashboard cards
SAMPLE_STATS = {
    "total": 8,
    "score": 62,
    "high": 2,
    "medium": 3,
    "low": 3,
    "last_scan": "2026-10-28 (sample)",
    "status": "Completed (sample)",
}

SAMPLE_NOTIFICATIONS = [
    "SAMPLE: New finding alert - a possible public profile was listed.",
    "SAMPLE: Weekly summary is ready to view.",
    "SAMPLE: Reminder - review your privacy settings.",
]

# Rows for the scan results table
SAMPLE_FINDINGS = [
    {"id": 1, "finding": "Email address shown on a public page", "category": "Contact Details",
     "source": "example-site-one.com", "date": "2026-10-28", "risk": "High",
     "details": "Sample only: an email address appears in a public listing."},
    {"id": 2, "finding": "Public social profile with photo", "category": "Social Profiles and Images",
     "source": "example-social.com", "date": "2026-10-28", "risk": "Medium",
     "details": "Sample only: a profile is visible without logging in."},
    {"id": 3, "finding": "Email found in a past data breach", "category": "Breached Credentials",
     "source": "example-breach-list.com", "date": "2026-10-27", "risk": "High",
     "details": "Sample only: this is demonstration data, not a real breach."},
    {"id": 4, "finding": "Name in a public directory", "category": "Public Records",
     "source": "example-directory.org", "date": "2026-10-26", "risk": "Medium",
     "details": "Sample only: a directory lists a matching name."},
    {"id": 5, "finding": "Account with a similar name and photo", "category": "Possible Impersonation",
     "source": "example-social.com", "date": "2026-10-26", "risk": "Medium",
     "details": "Sample only: a look-alike account that needs manual checking."},
    {"id": 6, "finding": "Old phone number on a forum post", "category": "Contact Details",
     "source": "example-forum.net", "date": "2026-10-25", "risk": "Low",
     "details": "Sample only: an old post contains contact details."},
    {"id": 7, "finding": "Username reused on another site", "category": "Social Profiles and Images",
     "source": "example-gaming.com", "date": "2026-10-24", "risk": "Low",
     "details": "Sample only: the same username appears on another platform."},
    {"id": 8, "finding": "Name in an old public notice", "category": "Public Records",
     "source": "example-notices.org", "date": "2026-10-23", "risk": "Low",
     "details": "Sample only: an older public notice mentions the name."},
]

SAMPLE_SCAN_HISTORY = [
    {"date": "2026-10-28", "findings": 8, "status": "Completed (sample)"},
    {"date": "2026-10-21", "findings": 6, "status": "Completed (sample)"},
    {"date": "2026-10-14", "findings": 5, "status": "Completed (sample)"},
]

CATEGORIES = ["Contact Details", "Social Profiles and Images", "Breached Credentials",
              "Public Records", "Possible Impersonation"]

# Questionnaire questions (answers are 0 = safest ... 2 = riskiest)
QUESTIONS = [
    "Do you use the same username across multiple platforms?",
    "Is your social media profile publicly accessible?",
    "Do you share personal information publicly?",
    "Do you regularly review your privacy settings?",
    "Do you know what personal information about you is publicly available?",
]

SAMPLE_CASES = [
    {"id": "CASE-001", "title": "Fake profile using my name", "date": "2026-10-20", "status": "Open"},
    {"id": "CASE-002", "title": "Photo posted without permission", "date": "2026-10-15", "status": "Under Review"},
    {"id": "CASE-003", "title": "Phone number shared on a forum", "date": "2026-10-02", "status": "Resolved"},
]


# ---------------------------------------------------------------
# ROUTES (one function per page)
# ---------------------------------------------------------------

@app.route("/")
def home():
    # Send visitors to the login page first
    return redirect(url_for("login"))


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html", page_title="Dashboard", user=SAMPLE_USER,
                           stats=SAMPLE_STATS, notifications=SAMPLE_NOTIFICATIONS)


@app.route("/monitoring")
def monitoring():
    return render_template("monitoring.html", page_title="Monitoring Setup", user=SAMPLE_USER)


@app.route("/scan-results")
def scan_results():
    return render_template("scan_results.html", page_title="Scan Results", user=SAMPLE_USER,
                           stats=SAMPLE_STATS, findings=SAMPLE_FINDINGS,
                           history=SAMPLE_SCAN_HISTORY, categories=CATEGORIES)


@app.route("/questionnaire")
def questionnaire():
    return render_template("questionnaire.html", page_title="Questionnaire", user=SAMPLE_USER,
                           questions=QUESTIONS)


@app.route("/cases")
def cases():
    return render_template("cases.html", page_title="Case Management", user=SAMPLE_USER,
                           cases=SAMPLE_CASES, findings=SAMPLE_FINDINGS[:2], categories=CATEGORIES)


@app.route("/settings")
def settings():
    return render_template("settings.html", page_title="Settings", user=SAMPLE_USER)


if __name__ == "__main__":
    # debug=True reloads the server automatically when you edit files
    app.run(debug=True)
