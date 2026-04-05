import os
import random
import json
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, render_template, request, session, redirect, url_for
from werkzeug.security import generate_password_hash, check_password_hash
import google.generativeai as genai

load_dotenv()

# ---------------- CONFIG ----------------
api_key = os.getenv("GEMINI_API_KEY")
if api_key:
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel("gemini-1.5-flash")
    print("✅ Gemini API loaded")
else:
    model = None
    print("⚠️ No Gemini API key - using fallback")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "cyberguard_secret_2024")

USERS_FILE = "users.json"
SCORES_FILE = "scores.json"

# ---------------- HELPERS ----------------
def load_json(file):
    if os.path.exists(file):
        with open(file) as f:
            return json.load(f)
    return {}

def save_json(file, data):
    with open(file, "w") as f:
        json.dump(data, f, indent=2)

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

# ---------------- AI URL CHECK ----------------
def analyze_url_ai(url):
    if not model:
        return None
    try:
        prompt = f"""You are a cybersecurity expert. Analyze this URL.
URL: {url}
Respond in this exact format only:
VERDICT: [SAFE/SUSPICIOUS/DANGEROUS]
RISK_SCORE: [0-100]
REASON: [One sentence explanation]
TIPS: [One security tip]"""
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Gemini error: {e}")
        return None

# ---------------- FALLBACK ----------------
def rule_based_check(url):
    score = 0
    reasons = []
    if len(url) > 75: score += 2; reasons.append("URL too long")
    if not url.startswith("https://"): score += 2; reasons.append("No HTTPS")
    if "@" in url: score += 3; reasons.append("Contains @")
    if url.count('.') > 3: score += 2; reasons.append("Too many subdomains")
    for word in ["login","verify","bank","secure","account","update","confirm"]:
        if word in url.lower(): score += 2; reasons.append(f"Keyword: {word}")
    if score >= 6: verdict, risk = "DANGEROUS", min(90, score*10)
    elif score >= 3: verdict, risk = "SUSPICIOUS", min(60, score*10)
    else: verdict, risk = "SAFE", max(5, score*5)
    reason = ", ".join(reasons) if reasons else "No major threats detected"
    return f"VERDICT: {verdict}\nRISK_SCORE: {risk}\nREASON: {reason}\nTIPS: Always verify URLs before clicking"

def parse_result(raw):
    parsed = {}
    for line in raw.strip().split("\n"):
        if ":" in line:
            key, val = line.split(":", 1)
            parsed[key.strip()] = val.strip()
    return parsed

# ---------------- AUTH ----------------
@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        users = load_json(USERS_FILE)
        if username in users:
            return render_template("register.html", error="Username already exists")
        users[username] = {
            "password": generate_password_hash(password),
            "created": datetime.now().isoformat(),
            "total_score": 0,
            "simulations_completed": 0,
            "urls_scanned": 0
        }
        save_json(USERS_FILE, users)
        session["user"] = username
        return redirect(url_for("dashboard"))
    return render_template("register.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        users = load_json(USERS_FILE)
        if username in users and check_password_hash(users[username]["password"], password):
            session["user"] = username
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# ---------------- HOME ----------------
@app.route("/", methods=["GET","POST"])
def home():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        ai_result = analyze_url_ai(url)
        raw = ai_result if ai_result else rule_based_check(url)
        source = "🤖 AI Analysis" if ai_result else "🧠 Smart Detection"
        p = parse_result(raw)
        result = {
            "source": source,
            "verdict": p.get("VERDICT", "UNKNOWN"),
            "risk": int(p.get("RISK_SCORE", 50)),
            "reason": p.get("REASON", "Analysis complete"),
            "tips": p.get("TIPS", "Stay safe online"),
            "url": url
        }
        if "user" in session:
            users = load_json(USERS_FILE)
            users[session["user"]]["urls_scanned"] = users[session["user"]].get("urls_scanned", 0) + 1
            save_json(USERS_FILE, users)
            scores = load_json(SCORES_FILE)
            if session["user"] not in scores:
                scores[session["user"]] = []
            scores[session["user"]].append({
                "type": "url_scan",
                "url": url,
                "verdict": result["verdict"],
                "risk": result["risk"],
                "date": datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            save_json(SCORES_FILE, scores)
    return render_template("index.html", result=result)

# ---------------- TRAINING ----------------
questions = [
    {"q":"Email asks to verify your bank account urgently.","correct":"spam","explanation":"Urgency + sensitive info = phishing.","category":"Email"},
    {"q":"Message says you won a lottery and must click a link.","correct":"spam","explanation":"Unexpected rewards are scams.","category":"Social"},
    {"q":"Email from support@amaz0n.com asking for your login.","correct":"spam","explanation":"Fake domain with '0' instead of 'o'.","category":"Email"},
    {"q":"WhatsApp link offering free Netflix subscription.","correct":"spam","explanation":"Free offers requiring clicks are phishing.","category":"Social"},
    {"q":"Caller asks you to share your OTP over phone.","correct":"spam","explanation":"Never share OTP with anyone.","category":"Phone"},
    {"q":"SMS: KYC pending, click this link immediately.","correct":"spam","explanation":"Urgent SMS with links are scams.","category":"SMS"},
    {"q":"Your account will be blocked unless you act now.","correct":"spam","explanation":"Fear tactics = phishing.","category":"Email"},
    {"q":"Unknown number sends you a suspicious link.","correct":"spam","explanation":"Never click links from unknown numbers.","category":"Phone"},
    {"q":"Job offer asking for upfront payment.","correct":"spam","explanation":"Legitimate jobs never ask for payment.","category":"Email"},
    {"q":"Instagram DM asking you to verify your account.","correct":"spam","explanation":"Fake verification scam.","category":"Social"},
    {"q":"College email about your exam schedule.","correct":"not_spam","explanation":"Official communication from known source.","category":"Email"},
    {"q":"Bank app notification inside the official app.","correct":"not_spam","explanation":"Notifications within official apps are safe.","category":"App"},
    {"q":"Amazon order confirmation email.","correct":"not_spam","explanation":"Expected email after placing an order.","category":"Email"},
    {"q":"Professor message about assignment deadline.","correct":"not_spam","explanation":"Message from a known sender.","category":"Email"},
    {"q":"OTP received after you requested a login.","correct":"not_spam","explanation":"You initiated this action.","category":"SMS"},
    {"q":"Google security alert for your account login.","correct":"not_spam","explanation":"Google sends alerts for new logins.","category":"Email"},
    {"q":"Friend message about your weekend plans.","correct":"not_spam","explanation":"Normal conversation from known contact.","category":"Social"},
    {"q":"Payment receipt email after online purchase.","correct":"not_spam","explanation":"Expected receipt from your transaction.","category":"Email"},
    {"q":"LinkedIn notification about a job match.","correct":"not_spam","explanation":"Relevant update from a platform you use.","category":"App"},
    {"q":"Food delivery notification for your active order.","correct":"not_spam","explanation":"Expected service notification.","category":"App"},
]

@app.route("/training", methods=["GET","POST"])
def training():
    session.setdefault("score", 0)
    session.setdefault("question_index", 0)
    session.setdefault("answered", False)
    if "shuffled_questions" not in session:
        shuffled = questions.copy()
        random.shuffle(shuffled)
        session["shuffled_questions"] = shuffled
    shuffled = session["shuffled_questions"]
    if session["question_index"] >= len(shuffled):
        session["question_index"] = 0
    q = shuffled[session["question_index"]]
    result = explanation = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "next":
            session["question_index"] += 1
            session["answered"] = False
            return redirect("/training")
        if not session["answered"]:
            answer = request.form.get("answer")
            if answer == q.get("correct"):
                session["score"] += 10
                result = "correct"
            else:
                session["score"] -= 5
                result = "wrong"
            explanation = q.get("explanation", "")
            session["answered"] = True
            if "user" in session:
                users = load_json(USERS_FILE)
                users[session["user"]]["total_score"] = session["score"]
                save_json(USERS_FILE, users)
                scores = load_json(SCORES_FILE)
                if session["user"] not in scores:
                    scores[session["user"]] = []
                scores[session["user"]].append({
                    "type": "quiz",
                    "result": result,
                    "category": q.get("category", "General"),
                    "score": session["score"],
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M")
                })
                save_json(SCORES_FILE, scores)
    return render_template("training.html",
        question=q.get("q",""),
        result=result,
        explanation=explanation,
        score=session["score"],
        answered=session["answered"],
        index=session["question_index"]+1,
        total=len(shuffled),
        category=q.get("category","General")
    )

# ---------------- SIMULATIONS ----------------
simulations = [
    {"id":1,"title":"Fake Bank Alert","from_email":"security@bankofind1a.com","subject":"🚨 URGENT: Your account has been compromised!","body":"Dear Customer,\n\nWe detected suspicious activity on your account. Your account will be SUSPENDED in 24 hours unless you verify your identity immediately.\n\nClick the button below to verify now. Failure to act will result in permanent account closure.","cta":"Verify Account Now","red_flags":["Fake domain (ind1a uses number '1')","Urgency and fear tactics","Threatens permanent closure","Generic greeting 'Dear Customer'"],"verdict":"PHISHING","explanation":"Classic phishing. The domain swaps 'i' for '1'. Urgency is created to stop you from thinking clearly."},
    {"id":2,"title":"Free Netflix Offer","from_email":"offers@netflix-freepremium.xyz","subject":"You've been selected for FREE Netflix! 🎉","body":"Congratulations!\n\nYou have been randomly selected for 12 months of Netflix Premium FREE!\n\nThis offer expires in 2 hours. Only 3 spots left.\n\nEnter your card details to activate (for verification only - you won't be charged).","cta":"Claim Free Netflix","red_flags":["Suspicious .xyz domain","Too good to be true","Artificial urgency","Asks for card details"],"verdict":"PHISHING","explanation":"Netflix never gives free subscriptions via email. The .xyz domain, fake urgency, and request for card details are all red flags."},
    {"id":3,"title":"IT Department Password Reset","from_email":"it-support@company-helpdesk.net","subject":"Action Required: Reset Your Password","body":"Hello,\n\nOur security system detected that your password hasn't been changed in 90 days.\n\nFor security compliance, please reset your password within 48 hours.\n\nIf you don't reset, your account access will be revoked.","cta":"Reset Password Now","red_flags":["External domain not company's official domain","Unsolicited password reset","Threatens account revocation","Creates time pressure"],"verdict":"PHISHING","explanation":"Real IT departments use the company's own domain. External domains like 'company-helpdesk.net' are impersonation attempts."},
    {"id":4,"title":"Package Delivery Notice","from_email":"delivery@fedex-tracking-update.com","subject":"Your package could not be delivered","body":"Dear Customer,\n\nWe attempted to deliver your package today but were unsuccessful.\n\nTo reschedule delivery, please confirm your address and pay a small redelivery fee of ₹25.\n\nYour package will be returned if not claimed within 3 days.","cta":"Reschedule Delivery","red_flags":["Fake FedEx domain","Asks for payment for redelivery","Vague about package details","Time pressure tactic"],"verdict":"PHISHING","explanation":"Courier companies never charge redelivery fees via email links. The fake domain and payment request are clear phishing signs."},
]

@app.route("/simulation")
def simulation():
    return render_template("simulation.html", simulations=simulations)

@app.route("/simulation/<int:sim_id>", methods=["GET","POST"])
def simulation_detail(sim_id):
    sim = next((s for s in simulations if s["id"] == sim_id), None)
    if not sim:
        return redirect(url_for("simulation"))
    result = None
    if request.method == "POST":
        answer = request.form.get("answer")
        result = "correct" if answer == "phishing" else "wrong"
        if "user" in session:
            users = load_json(USERS_FILE)
            if result == "correct":
                users[session["user"]]["total_score"] = users[session["user"]].get("total_score", 0) + 15
                users[session["user"]]["simulations_completed"] = users[session["user"]].get("simulations_completed", 0) + 1
            save_json(USERS_FILE, users)
            scores = load_json(SCORES_FILE)
            if session["user"] not in scores:
                scores[session["user"]] = []
            scores[session["user"]].append({
                "type": "simulation",
                "sim_title": sim["title"],
                "result": result,
                "date": datetime.now().strftime("%Y-%m-%d %H:%M")
            })
            save_json(SCORES_FILE, scores)
    return render_template("simulation_detail.html", sim=sim, result=result)

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
@login_required
def dashboard():
    username = session["user"]
    users = load_json(USERS_FILE)
    scores = load_json(SCORES_FILE)
    user_data = users.get(username, {})
    user_scores = scores.get(username, [])
    quiz_scores = [s for s in user_scores if s["type"] == "quiz"]
    sim_scores = [s for s in user_scores if s["type"] == "simulation"]
    url_scans = [s for s in user_scores if s["type"] == "url_scan"]
    score_history = []
    running = 0
    for s in user_scores:
        if s["type"] == "quiz":
            running = s.get("score", running)
            score_history.append({"date": s["date"], "score": running})
    correct_quiz = len([s for s in quiz_scores if s["result"] == "correct"])
    correct_sim = len([s for s in sim_scores if s["result"] == "correct"])
    return render_template("dashboard.html",
        username=username,
        total_score=user_data.get("total_score", 0),
        urls_scanned=user_data.get("urls_scanned", 0),
        simulations_completed=user_data.get("simulations_completed", 0),
        quiz_correct=correct_quiz,
        quiz_total=len(quiz_scores),
        sim_correct=correct_sim,
        sim_total=len(sim_scores),
        recent_scans=url_scans[-5:][::-1],
        score_history=json.dumps(score_history[-10:]),
        member_since=user_data.get("created","")[:10]
    )

# ---------------- RESET ----------------
@app.route("/reset")
def reset():
    for key in ["score","question_index","answered","shuffled_questions"]:
        session.pop(key, None)
    return redirect(url_for("training"))

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)), debug=False)