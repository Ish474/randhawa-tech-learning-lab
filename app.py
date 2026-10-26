import os
import json
import re
import secrets
import smtplib
import sqlite3
import time
import urllib.request as http_request
from email.message import EmailMessage
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, jsonify, request, send_file, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")
DB_PATH = Path(os.getenv("NULLSPACE_DB", BASE_DIR / "instance" / "nullspace.sqlite3"))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
MEDIA_DIR = DB_PATH.parent / "media"
MEDIA_DIR.mkdir(parents=True, exist_ok=True)
MAX_UPLOAD_BYTES = 25 * 1024 * 1024
ALLOWED_MEDIA = {
    "image/jpeg": "image", "image/png": "image", "image/gif": "image", "image/webp": "image",
    "video/mp4": "video", "video/webm": "video", "video/quicktime": "video",
}
DEFAULT_SETTINGS = {
    "site_name": "Randhawa's Tech Learning Lab",
    "tagline": "Learn. Build. Ship with confidence.",
    "copyright": "© 2026 Randhawa's Tech Learning Lab. All rights reserved.",
    "logo_url": "",
    "logo_alt": "Randhawa's Tech Learning Lab logo",
}
RATE_LIMITS = {"auth": (10, 900), "write": (120, 60), "read": (240, 60), "upload": (20, 3600)}
rate_buckets = defaultdict(deque)

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("NULLSPACE_SECRET_KEY", "dev-only-change-this-secret"),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("NULLSPACE_COOKIE_SECURE", "0") == "1",
    SESSION_COOKIE_NAME="randhawa_session",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 7,
    MAX_CONTENT_LENGTH=32 * 1024 * 1024,
)


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def rate_bucket_for_request():
    path = request.path
    if path.startswith("/api/auth/"):
        return "auth"
    if path.startswith("/api/admin/media") and request.method == "POST":
        return "upload"
    return "write" if request.method not in {"GET", "HEAD", "OPTIONS"} else "read"


@app.before_request
def security_guard():
    if request.path.startswith("/api/"):
        bucket_name = rate_bucket_for_request()
        limit, window = RATE_LIMITS[bucket_name]
        bucket_key = (request.remote_addr or "unknown", bucket_name)
        now = time.monotonic()
        bucket = rate_buckets[bucket_key]
        while bucket and bucket[0] <= now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            return jsonify({"error": "Too many requests. Try again later."}), 429, {"Retry-After": str(window)}
        bucket.append(now)
        if request.method not in {"GET", "HEAD", "OPTIONS"} and request.path not in {"/health"}:
            supplied = request.headers.get("X-CSRF-Token", "")
            expected = csrf_token()
            if not supplied or not secrets.compare_digest(supplied, expected):
                return jsonify({"error": "CSRF validation failed"}), 403


@app.after_request
def security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if request.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


DEFAULT_COURSES = [
    {
        "id": "python", "name": "Python", "tone": "python", "level": "Beginner",
        "description": "Learn to make small programs that solve real problems.",
        "modules": [
            ("Values, variables, and print", "A value is data and a variable gives that data a useful name.", "name = \"Nova\"\nprint(name)", "Print one sentence about yourself.", "What keyword displays a value?", "print", ["print", "show", "echo", "write"], "Python uses print to display a value."),
            ("Decisions and loops", "Conditions choose a path and loops repeat a path.", "score = 72\nif score >= 60:\n    print(\"pass\")", "Add a second score and test it.", "Which keyword starts a condition?", "if", ["if", "when", "check", "case"], "Python uses a two-letter keyword to choose a path."),
            ("Functions that do one job", "A function is a named recipe that can accept inputs.", "def banner(name):\n    return f\"Hi {name}\"", "Write a function that converts minutes to seconds.", "Which keyword defines a function?", "def", ["def", "func", "make", "recipe"], "The keyword is short for define."),
            ("Lists and dictionaries", "Lists keep values in order; dictionaries connect keys to values.", "room = {\"name\": \"lab\", \"points\": 120}", "Create a dictionary for a challenge.", "What kind of brackets start a dictionary?", "{}", ["{}", "[]", "()", "<>"], "Dictionaries use curly braces."),
            ("Build a command-line tool", "A useful tool accepts input, transforms it, and gives a clear result.", "target = input(\"Target: \")\nprint(target)", "Make a notes tool that asks for a topic.", "Which function reads typed input?", "input", ["input", "read", "scan", "ask"], "Python has a function named after the action."),
        ],
    },
    {
        "id": "web", "name": "Web development", "tone": "web", "level": "Beginner",
        "description": "Build thoughtful webpages with HTML, CSS, and JavaScript.",
        "modules": [
            ("HTML gives meaning", "HTML elements describe the structure and meaning of a page.", "<main>\n  <h1>Welcome</h1>\n</main>", "Add a heading and one paragraph.", "Which tag creates the largest heading?", "<h1>", ["<h1>", "<head>", "<title>", "<hero>"], "The number one heading is the most important."),
            ("CSS gives shape", "CSS controls layout, color, type, and responsive behavior.", ".card {\n  color: tomato;\n}", "Change a card color and spacing.", "Which property changes text color?", "color", ["color", "paint", "font-color", "ink"], "It is named after the visual attribute."),
            ("JavaScript gives behavior", "Browser JavaScript listens for events and changes the page state.", "button.addEventListener(\"click\", openRoom)", "Make a button update one label.", "Which event fires when a button is pressed?", "click", ["click", "press", "tap", "submit"], "The browser calls it a click."),
            ("HTTP in the wild", "Requests carry intent, a path, headers, and sometimes a body.", "fetch(\"/api/me\", { method: \"GET\" })", "Read a request and name its method.", "Which method normally reads data?", "GET", ["GET", "SEND", "READ", "OPEN"], "It is the standard read request."),
            ("Ship a responsive page", "A page is ready when its layout, labels, focus order, and inputs work at every width.", "@media (max-width: 600px) {\n  .grid { display: block; }\n}", "Check the page on a narrow screen.", "Which rule targets a smaller viewport?", "@media", ["@media", "@screen", "@small", "@view"], "Responsive CSS uses a media query."),
        ],
    },
    {
        "id": "linux", "name": "Linux systems", "tone": "linux", "level": "Beginner",
        "description": "Understand the machine beneath the screen through small safe observations.",
        "modules": [
            ("Where am I?", "The shell is a text conversation with the operating system.", "pwd\nls\ncd /tmp", "Use pwd and ls in the sandbox.", "Which command shows your current folder?", "pwd", ["pwd", "where", "place", "locate"], "It means print working directory."),
            ("Files and folders", "Linux treats many things as files, which makes small tools compose well.", "mkdir notes\ntouch notes/today.txt\ncat notes/today.txt", "Create a lab-notes folder and file.", "Which command lists nearby files?", "ls", ["ls", "look", "dirlist", "files"], "It is a tiny two-letter command."),
            ("Permissions without fear", "Read, write, and execute are separate abilities assigned to users and groups.", "ls -l script.sh\nchmod u+x script.sh", "Explain what execute permission enables.", "Which command changes file permissions?", "chmod", ["chmod", "chperm", "allow", "access"], "The command name means change mode."),
            ("Processes and logs", "Processes are running programs; logs help reconstruct what happened.", "ps aux\njournalctl -n 20", "Find one process and describe it.", "Which command lists running processes?", "ps", ["ps", "proc", "jobs", "run"], "The short command starts with process status."),
            ("Small shell scripts", "A script is a saved list of commands with a clear purpose and safe inputs.", "#!/usr/bin/env bash\necho \"hello\"", "Write a script that prints a useful note.", "Which shell commonly runs this script?", "bash", ["bash", "shell", "shh", "terminal"], "The interpreter name appears after env."),
        ],
    },
    {
        "id": "security", "name": "Cybersecurity", "tone": "security", "level": "Beginner",
        "description": "Find the flaw, fix the flaw, and practice within a safe boundary.",
        "modules": [
            ("Threats and controls", "A threat is a possible unwanted event; a control reduces its likelihood or impact.", "asset -> threat -> control", "Name one asset and one control.", "What does a control reduce?", "risk", ["risk", "code", "speed", "color"], "Controls reduce the chance or impact of harm."),
            ("Read an HTTP exchange", "Methods express intent, paths identify resources, and status codes summarize results.", "GET /api/users HTTP/1.1\nHTTP/1.1 200 OK", "Identify the path and status code.", "What does a 404 response mean?", "not found", ["not found", "success", "redirect", "server error"], "The server could not find the requested resource."),
            ("Authentication vs authorization", "Authentication answers who a user is; authorization answers what they may do.", "who are you? -> may you edit?", "Separate identity from permission.", "What decides what an identified user may do?", "authorization", ["authorization", "authentication", "encoding", "routing"], "Roles and permissions belong to this step."),
            ("Safe logs", "Useful logs record actor, action, time, result, and a safe identifier without secrets.", "actor + action + time + result", "Design one safe log entry.", "What should never appear in ordinary logs?", "password", ["password", "action", "time", "result"], "Never record secrets such as passwords or tokens."),
            ("Ethical boundaries", "Good security work has scope, an owned target, minimal tests, evidence, and cleanup.", "scope -> test -> evidence -> reset", "Write a safe test boundary.", "What should you define before testing?", "scope", ["scope", "payload", "exploit", "speed"], "Start by writing what is in and out of bounds."),
        ],
    },
    {
        "id": "java", "name": "Java", "tone": "web", "level": "Beginner",
        "description": "Build a strong Java foundation with types, methods, objects, and collections.",
        "modules": [
            ("Your first Java program", "Java programs start in a class and the main method is the entry point.", "public class Main {\n  public static void main(String[] args) {}\n}", "Change the greeting and run it.", "Which method starts a basic Java program?", "main", ["main", "start", "run", "open"], "The JVM enters through the main method."),
            ("Types and control flow", "Java asks you to name the type of every value.", "int score = 72;\nboolean passed = score >= 60;", "Add a loop for five numbers.", "Which type stores true or false?", "boolean", ["boolean", "truth", "bit", "logic"], "It represents a two-state value."),
            ("Methods and objects", "Classes describe kinds of things; objects are real instances of them.", "Room room = new Room();\nroom.open();", "Add a points field to Room.", "Which keyword creates an object?", "new", ["new", "make", "object", "build"], "Java uses a three-letter keyword."),
            ("Collections and exceptions", "Collections hold many values and exceptions describe unexpected situations.", "ArrayList<String> tools = new ArrayList<>();", "Store three learning paths in a list.", "Which collection is ordered and resizable?", "ArrayList", ["ArrayList", "Array", "QueueList", "Many"], "Its name says it is a list backed by an array."),
            ("Build a console quest", "A small text adventure combines input, decisions, methods, and state.", "Scanner input = new Scanner(System.in);", "Add a second choice to the quest.", "Which class reads console input?", "Scanner", ["Scanner", "Reader", "Input", "Console"], "Java provides this utility class in java.util."),
        ],
    },
    {
        "id": "reverse", "name": "C / C++ foundations", "tone": "linux", "level": "Beginner",
        "description": "Write clear programs and understand every layer from memory to executable.",
        "modules": [
            ("Compile the signal", "The compiler checks source and turns it into object code; the linker builds the executable.", "g++ main.cpp -o main", "Compile a small program and read the output.", "Which tool turns source into an executable?", "compiler", ["compiler", "browser", "link", "loader"], "The compiler translates source code."),
            ("Types and control flow", "A type tells the compiler how to interpret a value and its operations.", "int score = 72;\nif (score >= 60) {}", "Add braces and a second condition.", "Which type stores a whole number?", "int", ["int", "num", "whole", "integer"], "C uses a short version of integer."),
            ("Functions that do one job", "Passing inputs and returning outputs makes calculations testable and reusable.", "int double_it(int value) {\n  return value * 2;\n}", "Write a function that adds two scores.", "Which keyword sends a value back?", "return", ["return", "send", "give", "yield"], "The function returns its result to the caller."),
            ("Pointers and references", "A pointer stores an address; dereferencing reads the value at that address.", "int value = 7;\nint *ptr = &value;", "Trace the address and the value.", "Which symbol gets a variable's address?", "&", ["&", "*", "%", "$"], "The ampersand asks where the value lives."),
            ("Classes and containers", "A class is a contract and standard containers manage common collection lifetimes.", "std::vector<int> scores = {70, 90};", "Add one score and print the vector.", "Which container grows as items are added?", "vector", ["vector", "array", "stack", "block"], "The standard vector is a growable sequence."),
        ],
    },
]


def db_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.execute("PRAGMA foreign_keys = ON")
    connection.row_factory = sqlite3.Row
    return connection


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def initialize_database():
    connection = db_connection()
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            phone TEXT NOT NULL DEFAULT '',
            email_verified INTEGER NOT NULL DEFAULT 0,
            phone_verified INTEGER NOT NULL DEFAULT 0,
            active INTEGER NOT NULL DEFAULT 1,
            role TEXT NOT NULL DEFAULT 'learner',
            xp INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS progress (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id TEXT NOT NULL,
            room_index INTEGER NOT NULL,
            completed_at TEXT NOT NULL,
            UNIQUE(user_id, course_id, room_index),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS game_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            course_id TEXT NOT NULL,
            room_index INTEGER NOT NULL,
            score INTEGER NOT NULL DEFAULT 0,
            completed_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS courses (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            tone TEXT NOT NULL DEFAULT 'web',
            level TEXT NOT NULL DEFAULT 'Beginner',
            video_url TEXT NOT NULL DEFAULT '',
            video_title TEXT NOT NULL DEFAULT '',
            web_url TEXT NOT NULL DEFAULT '',
            web_title TEXT NOT NULL DEFAULT '',
            published INTEGER NOT NULL DEFAULT 1,
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS modules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            course_id TEXT NOT NULL,
            title TEXT NOT NULL,
            time TEXT NOT NULL DEFAULT '15 MIN',
            explain TEXT NOT NULL,
            code TEXT NOT NULL DEFAULT '',
            task TEXT NOT NULL DEFAULT '',
            objective TEXT NOT NULL DEFAULT '',
            outcome TEXT NOT NULL DEFAULT '',
            steps_json TEXT NOT NULL DEFAULT '[]',
            question TEXT NOT NULL DEFAULT '',
            answer TEXT NOT NULL DEFAULT '',
            answers_json TEXT NOT NULL DEFAULT '[]',
            hint TEXT NOT NULL DEFAULT '',
            game_mode TEXT NOT NULL DEFAULT 'duel',
            sort_order INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(course_id) REFERENCES courses(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS site_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            media_type TEXT NOT NULL,
            mime_type TEXT NOT NULL,
            size INTEGER NOT NULL,
            uploaded_by INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS otp_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel TEXT NOT NULL,
            destination TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            expires_at TEXT NOT NULL,
            used_at TEXT,
            created_at TEXT NOT NULL
        );
        """
    )
    user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)").fetchall()}
    if "phone" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN phone TEXT NOT NULL DEFAULT ''")
    if "email_verified" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
    if "phone_verified" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN phone_verified INTEGER NOT NULL DEFAULT 0")
    if "active" not in user_columns:
        connection.execute("ALTER TABLE users ADD COLUMN active INTEGER NOT NULL DEFAULT 1")
    module_columns = {row["name"] for row in connection.execute("PRAGMA table_info(modules)").fetchall()}
    if "question_type" not in module_columns:
        connection.execute("ALTER TABLE modules ADD COLUMN question_type TEXT NOT NULL DEFAULT 'choice'")
    admin_email = os.getenv("MASTER_ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("MASTER_ADMIN_PASSWORD", "")
    if admin_email and admin_password:
        existing_admin = connection.execute(
            "SELECT id FROM users WHERE email = ?", (admin_email,)
        ).fetchone()
        if existing_admin is None:
            connection.execute(
                "INSERT INTO users (username, email, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
                ("Master Admin", admin_email, generate_password_hash(admin_password), utc_now()),
            )
    seed_default_courses(connection)
    for key, value in DEFAULT_SETTINGS.items():
        connection.execute(
            "INSERT OR IGNORE INTO site_settings (key, value, updated_at) VALUES (?, ?, ?)",
            (key, value, utc_now()),
        )
    connection.commit()
    connection.close()


def seed_default_courses(connection):
    for course_order, course in enumerate(DEFAULT_COURSES):
        now = utc_now()
        connection.execute(
            """INSERT OR IGNORE INTO courses
            (id, name, description, tone, level, video_url, video_title, web_url, web_title, sort_order, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                course["id"], course["name"], course["description"], course["tone"], course["level"],
                "", "", "", "", course_order, now, now,
            ),
        )
        existing_module = connection.execute(
            "SELECT id FROM modules WHERE course_id = ? LIMIT 1", (course["id"],)
        ).fetchone()
        if existing_module is not None:
            continue
        for module_order, item in enumerate(course["modules"]):
            title, explain, code, task, question, answer, answers, hint = item
            connection.execute(
                """INSERT INTO modules
                (course_id, title, time, explain, code, task, objective, outcome, steps_json, question, answer, answers_json, hint, question_type, game_mode, sort_order, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    course["id"], title, "15 MIN", explain, code, task,
                    question, answer, json.dumps(["Read the objective.", "Study the example.", "Try the task."]),
                    question, answer, json.dumps(answers), hint, ["choice", "code", "sequence", "debug", "match"][module_order], ["duel", "boss", "race", "defense", "duel"][module_order], module_order, now, now,
                ),
            )


def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    connection = db_connection()
    user = connection.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    connection.close()
    return user


def public_user(user):
    if user is None:
        return None
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "email_verified": bool(user["email_verified"]),
        "active": bool(user["active"]),
        "role": user["role"],
        "xp": user["xp"],
        "created_at": user["created_at"],
    }


def error(message, status=400):
    return jsonify({"error": message}), status


def strong_password(password):
    return len(password) >= 10 and any(char.islower() for char in password) and any(char.isupper() for char in password) and any(char.isdigit() for char in password)


def otp_expiry():
    return datetime.fromtimestamp(time.time() + 600, timezone.utc).isoformat()


def deliver_email_otp(destination, code):
    host = os.getenv("OTP_SMTP_HOST", "").strip()
    if not host:
        return os.getenv("OTP_DEV_MODE", "0") == "1"
    message = EmailMessage()
    message["Subject"] = "Your Randhawa's Tech Lab verification code"
    message["From"] = os.getenv("OTP_SMTP_FROM", os.getenv("OTP_SMTP_USER", "")).strip()
    message["To"] = destination
    message.set_content(f"Your six-digit verification code is {code}. It expires in 10 minutes.")
    port = int(os.getenv("OTP_SMTP_PORT", "587"))
    with smtplib.SMTP(host, port, timeout=15) as server:
        if os.getenv("OTP_SMTP_TLS", "1") == "1":
            server.starttls()
        user = os.getenv("OTP_SMTP_USER", "").strip()
        if user:
            server.login(user, os.getenv("OTP_SMTP_PASSWORD", ""))
        server.send_message(message)
    return True


def create_otp(channel, destination):
    code = f"{secrets.randbelow(1_000_000):06d}"
    connection = db_connection()
    connection.execute("UPDATE otp_codes SET used_at = ? WHERE channel = ? AND destination = ? AND used_at IS NULL", (utc_now(), channel, destination))
    connection.execute("INSERT INTO otp_codes (channel, destination, code_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)", (channel, destination, generate_password_hash(code), otp_expiry(), utc_now()))
    connection.commit()
    connection.close()
    try:
        delivered = deliver_email_otp(destination, code)
    except Exception:
        delivered = False
    if not delivered:
        connection = db_connection()
        connection.execute("UPDATE otp_codes SET used_at = ? WHERE channel = ? AND destination = ? AND used_at IS NULL", (utc_now(), channel, destination))
        connection.commit()
        connection.close()
        return None
    return code


def verify_otp(channel, destination, code):
    connection = db_connection()
    row = connection.execute("SELECT * FROM otp_codes WHERE channel = ? AND destination = ? AND used_at IS NULL ORDER BY id DESC LIMIT 1", (channel, destination)).fetchone()
    if row is None or datetime.fromisoformat(row["expires_at"]) <= datetime.now(timezone.utc) or row["attempts"] >= 5:
        connection.close()
        return False
    if not check_password_hash(row["code_hash"], str(code or "").strip()):
        connection.execute("UPDATE otp_codes SET attempts = attempts + 1 WHERE id = ?", (row["id"],))
        connection.commit()
        connection.close()
        return False
    connection.execute("UPDATE otp_codes SET used_at = ? WHERE id = ?", (utc_now(), row["id"]))
    connection.commit()
    connection.close()
    return True


def require_user():
    user = current_user()
    if user is None:
        return None, error("Authentication required", 401)
    return user, None


def require_admin():
    user, failure = require_user()
    if failure:
        return None, failure
    if user["role"] != "admin":
        return None, error("Admin role required", 403)
    return user, None


@app.get("/")
def index():
    return send_file(BASE_DIR / "webpage.html")


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "randhawa-tech-learning-lab"})


@app.get("/api/me")
def me():
    return jsonify({"user": public_user(current_user()), "csrf_token": csrf_token()})


@app.post("/api/auth/otp/request")
def request_otp():
    body = request.get_json(silent=True) or {}
    channel = str(body.get("channel", "")).strip().lower()
    destination = str(body.get("destination", "")).strip().lower()
    if channel != "email" or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", destination):
        return error("Enter a valid email address")
    code = create_otp(channel, destination)
    if code is None:
        return error("OTP delivery is not configured or failed. Set SMTP for email or Twilio for SMS.", 503)
    if os.getenv("OTP_DEV_MODE", "0") == "1":
        return jsonify({"ok": True, "channel": channel, "destination": destination, "expires_in": 600, "dev_code": code})
    return jsonify({"ok": True, "channel": channel, "destination": destination, "expires_in": 600})


@app.post("/api/auth/otp/verify")
def verify_requested_otp():
    body = request.get_json(silent=True) or {}
    channel = str(body.get("channel", "")).strip().lower()
    destination = str(body.get("destination", "")).strip().lower()
    if channel != "email" or not destination or not verify_otp(channel, destination, body.get("code")):
        return error("That verification code is invalid or expired", 400)
    verified_contacts = dict(session.get("verified_contacts", {}))
    verified_contacts[channel] = destination
    session["verified_contacts"] = verified_contacts
    return jsonify({"ok": True, "channel": channel, "destination": destination})


@app.post("/api/auth/register")
def register():
    body = request.get_json(silent=True) or {}
    username = str(body.get("username", "")).strip()
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    if not re.fullmatch(r"[A-Za-z0-9_ -]{2,32}", username):
        return error("Username must be 2-32 letters, numbers, spaces, underscores, or hyphens")
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        return error("Enter a valid email address")
    if not strong_password(password):
        return error("Password must be at least 10 characters with upper, lower, and numeric characters")
    verified_contacts = session.get("verified_contacts", {})
    if verified_contacts.get("email") != email:
        return error("Verify your email before creating an account")
    connection = db_connection()
    try:
        cursor = connection.execute(
            "INSERT INTO users (username, email, password_hash, email_verified, created_at) VALUES (?, ?, ?, 1, ?)",
            (username, email, generate_password_hash(password), utc_now()),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        connection.close()
        return error("An account with that email already exists", 409)
    user = connection.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
    connection.close()
    session.clear()
    session["user_id"] = user["id"]
    return jsonify({"user": public_user(user), "csrf_token": csrf_token()}), 201


@app.post("/api/auth/login")
def login():
    body = request.get_json(silent=True) or {}
    email = str(body.get("email", "")).strip().lower()
    password = str(body.get("password", ""))
    connection = db_connection()
    user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    connection.close()
    if user is None or not user["active"] or not check_password_hash(user["password_hash"], password):
        return error("Email or password is incorrect", 401)
    session.clear()
    session["user_id"] = user["id"]
    return jsonify({"user": public_user(user), "csrf_token": csrf_token()})


@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify({"ok": True, "csrf_token": csrf_token()})


@app.get("/api/progress")
def get_progress():
    user, failure = require_user()
    if failure:
        return failure
    connection = db_connection()
    rows = connection.execute(
        "SELECT course_id, room_index, completed_at FROM progress WHERE user_id = ? ORDER BY completed_at DESC",
        (user["id"],),
    ).fetchall()
    connection.close()
    return jsonify({"progress": [dict(row) for row in rows]})


@app.post("/api/progress")
def save_progress():
    user, failure = require_user()
    if failure:
        return failure
    body = request.get_json(silent=True) or {}
    course_id = str(body.get("course_id", "")).strip()
    try:
        room_index = int(body.get("room_index"))
    except (TypeError, ValueError):
        return error("room_index must be an integer")
    if not re.fullmatch(r"[a-z0-9_-]{2,24}", course_id) or not 0 <= room_index <= 99:
        return error("Invalid room progress payload")
    connection = db_connection()
    connection.execute(
        "INSERT INTO progress (user_id, course_id, room_index, completed_at) VALUES (?, ?, ?, ?) ON CONFLICT(user_id, course_id, room_index) DO UPDATE SET completed_at = excluded.completed_at",
        (user["id"], course_id, room_index, utc_now()),
    )
    connection.commit()
    connection.close()
    return jsonify({"ok": True})


@app.post("/api/game/complete")
def complete_game():
    user, failure = require_user()
    if failure:
        return failure
    body = request.get_json(silent=True) or {}
    course_id = str(body.get("course_id", "")).strip()
    try:
        room_index = int(body.get("room_index"))
        score = max(0, min(int(body.get("score", 0)), 1000))
    except (TypeError, ValueError):
        return error("Invalid game result")
    connection = db_connection()
    connection.execute(
        "INSERT INTO game_runs (user_id, course_id, room_index, score, completed_at) VALUES (?, ?, ?, ?, ?)",
        (user["id"], course_id, room_index, score, utc_now()),
    )
    connection.execute("UPDATE users SET xp = xp + ? WHERE id = ?", (score, user["id"]))
    connection.commit()
    updated_user = connection.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()
    connection.close()
    return jsonify({"ok": True, "user": public_user(updated_user)})


@app.get("/api/admin/users")
def admin_users():
    _, failure = require_admin()
    if failure:
        return failure
    connection = db_connection()
    users = connection.execute(
        "SELECT id, username, email, role, xp, active, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
    connection.close()
    return jsonify({"users": [dict(user) for user in users]})


@app.patch("/api/admin/users/<int:user_id>")
def update_admin_user(user_id):
    admin, failure = require_admin()
    if failure:
        return failure
    body = request.get_json(silent=True) or {}
    changes = []
    values = []
    if "role" in body:
        role = str(body["role"]).strip().lower()
        if role not in {"learner", "admin"}:
            return error("Role must be learner or admin")
        changes.append("role = ?")
        values.append(role)
    if "active" in body:
        if user_id == admin["id"] and not bool(body["active"]):
            return error("You cannot deactivate your own admin account")
        changes.append("active = ?")
        values.append(1 if bool(body["active"]) else 0)
    if "xp" in body:
        try:
            xp = max(0, min(int(body["xp"]), 10_000_000))
        except (TypeError, ValueError):
            return error("XP must be a non-negative number")
        changes.append("xp = ?")
        values.append(xp)
    if not changes:
        return error("No user changes supplied")
    connection = db_connection()
    values.append(user_id)
    cursor = connection.execute(f"UPDATE users SET {', '.join(changes)} WHERE id = ?", values)
    connection.commit()
    user = connection.execute("SELECT id, username, email, role, xp, active, created_at FROM users WHERE id = ?", (user_id,)).fetchone()
    connection.close()
    if cursor.rowcount == 0 or user is None:
        return error("User not found", 404)
    return jsonify({"user": dict(user)})


@app.delete("/api/admin/users/<int:user_id>")
def delete_admin_user(user_id):
    admin, failure = require_admin()
    if failure:
        return failure
    if user_id == admin["id"]:
        return error("You cannot delete your own admin account")
    connection = db_connection()
    cursor = connection.execute("DELETE FROM users WHERE id = ?", (user_id,))
    connection.commit()
    connection.close()
    if cursor.rowcount == 0:
        return error("User not found", 404)
    return jsonify({"ok": True})


def decode_json_list(value):
    try:
        decoded = json.loads(value or "[]")
    except (TypeError, json.JSONDecodeError):
        decoded = []
    return decoded if isinstance(decoded, list) else []


def course_payload(connection, course):
    modules = connection.execute(
        "SELECT * FROM modules WHERE course_id = ? ORDER BY sort_order, id", (course["id"],)
    ).fetchall()
    return {
        "id": course["id"],
        "name": course["name"],
        "description": course["description"],
        "tone": course["tone"],
        "level": course["level"],
        "video": course["video_url"],
        "videoTitle": course["video_title"],
        "web": course["web_url"],
        "webTitle": course["web_title"],
        "published": bool(course["published"]),
        "sort_order": course["sort_order"],
        "modules": [
            {
                "id": module["id"],
                "title": module["title"],
                "time": module["time"],
                "explain": module["explain"],
                "code": module["code"],
                "task": module["task"],
                "objective": module["objective"],
                "outcome": module["outcome"],
                "steps": decode_json_list(module["steps_json"]),
                "question": module["question"],
                "answer": module["answer"],
                "answers": decode_json_list(module["answers_json"]),
                "hint": module["hint"],
                "question_type": module["question_type"],
                "game_mode": module["game_mode"],
                "sort_order": module["sort_order"],
            }
            for module in modules
        ],
    }


def all_courses(include_unpublished=False):
    connection = db_connection()
    query = "SELECT * FROM courses"
    params = ()
    if not include_unpublished:
        query += " WHERE published = 1"
    query += " ORDER BY sort_order, name"
    courses = [course_payload(connection, row) for row in connection.execute(query, params).fetchall()]
    connection.close()
    return courses


def body_text(body, key, default="", limit=4000):
    value = str(body.get(key, default)).strip()
    return value[:limit]


def list_value(value):
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value or "").splitlines() if item.strip()]


def validate_course_id(course_id):
    return bool(re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,31}", course_id))


@app.get("/api/courses")
def public_courses():
    return jsonify({"courses": all_courses()})


def site_settings_payload(connection):
    settings = dict(DEFAULT_SETTINGS)
    rows = connection.execute("SELECT key, value FROM site_settings").fetchall()
    settings.update({row["key"]: row["value"] for row in rows})
    return settings


@app.get("/api/site")
def public_site_settings():
    connection = db_connection()
    settings = site_settings_payload(connection)
    connection.close()
    return jsonify({"settings": settings})


@app.put("/api/admin/settings")
def update_site_settings():
    _, failure = require_admin()
    if failure:
        return failure
    body = request.get_json(silent=True) or {}
    allowed = {"site_name": 120, "tagline": 240, "copyright": 240, "logo_url": 500, "logo_alt": 160}
    connection = db_connection()
    now = utc_now()
    for key, limit in allowed.items():
        if key in body:
            value = str(body[key]).strip()[:limit]
            connection.execute(
                "INSERT INTO site_settings (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
                (key, value, now),
            )
    connection.commit()
    settings = site_settings_payload(connection)
    connection.close()
    return jsonify({"settings": settings})


def media_payload(row):
    return {
        "id": row["id"], "url": f"/media/{row['filename']}", "filename": row["filename"],
        "original_name": row["original_name"], "media_type": row["media_type"],
        "mime_type": row["mime_type"], "size": row["size"], "created_at": row["created_at"],
    }


@app.get("/media/<path:filename>")
def serve_media(filename):
    return send_from_directory(MEDIA_DIR, filename, max_age=86400)


@app.get("/api/admin/media")
def admin_media():
    _, failure = require_admin()
    if failure:
        return failure
    connection = db_connection()
    rows = connection.execute("SELECT * FROM media ORDER BY created_at DESC").fetchall()
    connection.close()
    return jsonify({"media": [media_payload(row) for row in rows]})


@app.post("/api/admin/media")
def upload_media():
    _, failure = require_admin()
    if failure:
        return failure
    uploaded = request.files.get("file")
    if uploaded is None or not uploaded.filename:
        return error("Choose an image or video file")
    mime_type = (uploaded.mimetype or "").lower()
    media_type = ALLOWED_MEDIA.get(mime_type)
    safe_name = secure_filename(uploaded.filename)
    extension = Path(safe_name).suffix.lower()
    if media_type is None or not safe_name or extension not in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".mp4", ".webm", ".mov"}:
        return error("Only JPG, PNG, GIF, WEBP, MP4, WEBM, and MOV files are allowed")
    filename = f"{secrets.token_hex(16)}{extension}"
    destination = MEDIA_DIR / filename
    uploaded.save(destination)
    size = destination.stat().st_size
    if size > MAX_UPLOAD_BYTES or size == 0:
        destination.unlink(missing_ok=True)
        return error("Media must be between 1 byte and 25 MB")
    user = current_user()
    connection = db_connection()
    cursor = connection.execute(
        "INSERT INTO media (filename, original_name, media_type, mime_type, size, uploaded_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (filename, safe_name[:180], media_type, mime_type, size, user["id"], utc_now()),
    )
    connection.commit()
    row = connection.execute("SELECT * FROM media WHERE id = ?", (cursor.lastrowid,)).fetchone()
    connection.close()
    return jsonify({"media": media_payload(row)}), 201


@app.delete("/api/admin/media/<int:media_id>")
def delete_media(media_id):
    _, failure = require_admin()
    if failure:
        return failure
    connection = db_connection()
    row = connection.execute("SELECT * FROM media WHERE id = ?", (media_id,)).fetchone()
    if row is None:
        connection.close()
        return error("Media not found", 404)
    connection.execute("DELETE FROM media WHERE id = ?", (media_id,))
    connection.commit()
    connection.close()
    (MEDIA_DIR / row["filename"]).unlink(missing_ok=True)
    return jsonify({"ok": True})


@app.get("/api/admin/courses")
def admin_courses():
    _, failure = require_admin()
    if failure:
        return failure
    return jsonify({"courses": all_courses(include_unpublished=True)})


@app.post("/api/admin/courses")
def create_course():
    _, failure = require_admin()
    if failure:
        return failure
    body = request.get_json(silent=True) or {}
    course_id = body_text(body, "id", limit=32).lower()
    name = body_text(body, "name", limit=120)
    description = body_text(body, "description", limit=1000)
    if not validate_course_id(course_id):
        return error("Course ID must be 2-32 lowercase letters, numbers, hyphens, or underscores")
    if not name or not description:
        return error("Course name and description are required")
    connection = db_connection()
    try:
        now = utc_now()
        connection.execute(
            """INSERT INTO courses
            (id, name, description, tone, level, video_url, video_title, web_url, web_title, published, sort_order, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                course_id, name, description, body_text(body, "tone", "web", 24), body_text(body, "level", "Beginner", 40),
                body_text(body, "video", limit=500), body_text(body, "videoTitle", limit=160),
                body_text(body, "web", limit=500), body_text(body, "webTitle", limit=160),
                int(bool(body.get("published", True))), int(body.get("sort_order", 999)), now, now,
            ),
        )
        connection.commit()
    except sqlite3.IntegrityError:
        connection.close()
        return error("A course with that ID already exists", 409)
    course = connection.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    payload = course_payload(connection, course)
    connection.close()
    return jsonify({"course": payload}), 201


@app.put("/api/admin/courses/<course_id>")
def update_course(course_id):
    _, failure = require_admin()
    if failure:
        return failure
    body = request.get_json(silent=True) or {}
    connection = db_connection()
    existing = connection.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    if existing is None:
        connection.close()
        return error("Course not found", 404)
    now = utc_now()
    connection.execute(
        """UPDATE courses SET name = ?, description = ?, tone = ?, level = ?, video_url = ?, video_title = ?,
        web_url = ?, web_title = ?, published = ?, sort_order = ?, updated_at = ? WHERE id = ?""",
        (
            body_text(body, "name", existing["name"], 120), body_text(body, "description", existing["description"], 1000),
            body_text(body, "tone", existing["tone"], 24), body_text(body, "level", existing["level"], 40),
            body_text(body, "video", existing["video_url"], 500), body_text(body, "videoTitle", existing["video_title"], 160),
            body_text(body, "web", existing["web_url"], 500), body_text(body, "webTitle", existing["web_title"], 160),
            int(bool(body.get("published", existing["published"]))), int(body.get("sort_order", existing["sort_order"])), now, course_id,
        ),
    )
    connection.commit()
    course = connection.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    payload = course_payload(connection, course)
    connection.close()
    return jsonify({"course": payload})


@app.delete("/api/admin/courses/<course_id>")
def delete_course(course_id):
    _, failure = require_admin()
    if failure:
        return failure
    connection = db_connection()
    cursor = connection.execute("DELETE FROM courses WHERE id = ?", (course_id,))
    connection.commit()
    connection.close()
    if cursor.rowcount == 0:
        return error("Course not found", 404)
    return jsonify({"ok": True})


def module_payload(body, existing=None):
    existing = existing or {}
    def field(key, fallback="", limit=4000):
        return body_text(body, key, existing[key] if key in existing else fallback, limit)
    choices = list_value(body.get("answers", existing.get("answers", [])))
    answer = field("answer", limit=300)
    if len(choices) < 2 or answer not in choices:
        raise ValueError("Add at least two answer choices and include the correct answer")
    steps = list_value(body.get("steps", existing.get("steps", []))) or ["Read the objective.", "Study the example.", "Try the task."]
    question_type = field("question_type", "choice", 24)
    if question_type not in {"choice", "code", "sequence", "debug", "match"}:
        raise ValueError("Unknown question type")
    return {
        "title": field("title", limit=160), "time": field("time", "15 MIN", 40), "explain": field("explain"),
        "code": field("code"), "task": field("task"), "objective": field("objective"), "outcome": field("outcome"),
        "steps": steps, "question": field("question"), "answer": answer, "answers": choices,
        "hint": field("hint"), "question_type": question_type, "game_mode": field("game_mode", "duel", 24),
    }


def local_question_content(module, course_name):
    module = dict(module)
    module_type = module.get("question_type", "choice")
    title = module.get("title", "this room")
    task = module.get("task", "complete the practice task")
    explanation = module.get("explain", "Use the example and objective to choose the strongest answer.")
    answer = module.get("answer", "").strip()
    choices = decode_json_list(module.get("answers_json", "[]")) if "answers_json" in module else module.get("answers", [])
    choices = [str(choice).strip() for choice in choices if str(choice).strip()]
    steps = decode_json_list(module.get("steps_json", "[]")) if "steps_json" in module else module.get("steps", [])
    if module_type == "sequence":
        question = f'Arrange the moves for "{title}" so the operator can complete the {course_name} mission.'
        choices = steps or choices
        hint = f"Start with the smallest setup move, then follow the example before the final task: {task}"
    elif module_type == "code":
        question = f'Read the example in "{title}". Which choice best explains the code you are about to use?'
        hint = f"Look at the code and connect it to the room outcome: {module.get('outcome', title)}."
    elif module_type == "debug":
        question = f'The "{title}" room has a bug in its first attempt while trying to {task.lower()} Which choice repairs the core idea?'
        hint = f"Compare the failed assumption with the explanation: {explanation[:180]}"
    elif module_type == "match":
        question = f'Which concept matches this explanation from "{title}": {explanation}'
        hint = f"Use the room objective and the example before choosing: {module.get('objective', task)}"
    else:
        question = f'You are on the "{title}" mission. Which answer best proves the skill behind this task: {task}'
        hint = f"Use the room outcome and example: {module.get('outcome', explanation[:160])}"
    return {"question": question, "answer": answer, "answers": choices, "hint": hint}


def ai_question_content(module, course_name):
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        return None
    module_type = module["question_type"]
    prompt = {
        "course": course_name,
        "module_title": module["title"],
        "module_explanation": module["explain"],
        "example_code": module["code"],
        "practice_task": module["task"],
        "objective": module["objective"],
        "outcome": module["outcome"],
        "steps": decode_json_list(module["steps_json"]),
        "question_type": module_type,
        "instruction": "Create one original educational game challenge. Return strict JSON with question, answer, answers (exactly four choices), and hint. The answer must exactly match one choice. Do not repeat generic wording or use trick questions.",
    }
    request_body = json.dumps({
        "model": os.getenv("OPENAI_MODEL", "gpt-4o-mini"),
        "temperature": 0.8,
        "response_format": {"type": "json_object"},
        "messages": [{"role": "system", "content": "You write concise, age-appropriate technical learning game challenges."}, {"role": "user", "content": json.dumps(prompt)}],
    }).encode()
    http_request_object = http_request.Request("https://api.openai.com/v1/chat/completions", data=request_body, method="POST", headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    try:
        with http_request.urlopen(http_request_object, timeout=20) as response:
            payload = json.loads(response.read())
        content = json.loads(payload["choices"][0]["message"]["content"])
        answer = str(content.get("answer", "")).strip()
        answers = [str(choice).strip() for choice in content.get("answers", []) if str(choice).strip()]
        if not content.get("question") or not answer or len(answers) != 4 or answer not in answers:
            return None
        return {"question": str(content["question"]).strip()[:800], "answer": answer[:300], "answers": answers, "hint": str(content.get("hint", "Review the example and objective.")).strip()[:500]}
    except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


@app.post("/api/admin/courses/<course_id>/generate-questions")
def generate_course_questions(course_id):
    _, failure = require_admin()
    if failure:
        return failure
    connection = db_connection()
    course = connection.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone()
    if course is None:
        connection.close()
        return error("Course not found", 404)
    modules = connection.execute("SELECT * FROM modules WHERE course_id = ? ORDER BY sort_order, id", (course_id,)).fetchall()
    generated = 0
    for module in modules:
        content = ai_question_content(module, course["name"]) or local_question_content(module, course["name"])
        valid_content = len(content["answers"]) >= 2 if module["question_type"] == "sequence" else bool(content["answer"]) and len(content["answers"]) >= 2 and content["answer"] in content["answers"]
        if not valid_content:
            continue
        connection.execute(
            "UPDATE modules SET question = ?, answer = ?, answers_json = ?, hint = ?, updated_at = ? WHERE id = ?",
            (content["question"], content["answer"], json.dumps(content["answers"]), content["hint"], utc_now(), module["id"]),
        )
        generated += 1
    connection.commit()
    payload = course_payload(connection, course)
    connection.close()
    return jsonify({"course": payload, "generated": generated, "provider": "openai" if os.getenv("OPENAI_API_KEY", "").strip() else "local"})


@app.post("/api/admin/courses/<course_id>/modules")
def create_module(course_id):
    _, failure = require_admin()
    if failure:
        return failure
    body = request.get_json(silent=True) or {}
    connection = db_connection()
    if connection.execute("SELECT id FROM courses WHERE id = ?", (course_id,)).fetchone() is None:
        connection.close()
        return error("Course not found", 404)
    try:
        values = module_payload(body)
    except ValueError as problem:
        connection.close()
        return error(str(problem))
    next_order = connection.execute("SELECT COALESCE(MAX(sort_order), -1) + 1 FROM modules WHERE course_id = ?", (course_id,)).fetchone()[0]
    now = utc_now()
    cursor = connection.execute(
        """INSERT INTO modules (course_id, title, time, explain, code, task, objective, outcome, steps_json, question, answer, answers_json, hint, question_type, game_mode, sort_order, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (course_id, values["title"], values["time"], values["explain"], values["code"], values["task"], values["objective"], values["outcome"], json.dumps(values["steps"]), values["question"], values["answer"], json.dumps(values["answers"]), values["hint"], values["question_type"], values["game_mode"], next_order, now, now),
    )
    connection.commit()
    module = connection.execute("SELECT * FROM modules WHERE id = ?", (cursor.lastrowid,)).fetchone()
    payload = course_payload(connection, connection.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone())
    connection.close()
    return jsonify({"course": payload, "module_id": module["id"]}), 201


@app.put("/api/admin/courses/<course_id>/modules/<int:module_id>")
def update_module(course_id, module_id):
    _, failure = require_admin()
    if failure:
        return failure
    body = request.get_json(silent=True) or {}
    connection = db_connection()
    module = connection.execute("SELECT * FROM modules WHERE id = ? AND course_id = ?", (module_id, course_id)).fetchone()
    if module is None:
        connection.close()
        return error("Module not found", 404)
    existing = dict(module)
    existing["steps"] = decode_json_list(existing.pop("steps_json"))
    existing["answers"] = decode_json_list(existing.pop("answers_json"))
    try:
        values = module_payload(body, existing)
    except ValueError as problem:
        connection.close()
        return error(str(problem))
    connection.execute(
        """UPDATE modules SET title = ?, time = ?, explain = ?, code = ?, task = ?, objective = ?, outcome = ?, steps_json = ?, question = ?, answer = ?, answers_json = ?, hint = ?, question_type = ?, game_mode = ?, updated_at = ? WHERE id = ?""",
        (values["title"], values["time"], values["explain"], values["code"], values["task"], values["objective"], values["outcome"], json.dumps(values["steps"]), values["question"], values["answer"], json.dumps(values["answers"]), values["hint"], values["question_type"], values["game_mode"], utc_now(), module_id),
    )
    connection.commit()
    payload = course_payload(connection, connection.execute("SELECT * FROM courses WHERE id = ?", (course_id,)).fetchone())
    connection.close()
    return jsonify({"course": payload})


@app.delete("/api/admin/courses/<course_id>/modules/<int:module_id>")
def delete_module(course_id, module_id):
    _, failure = require_admin()
    if failure:
        return failure
    connection = db_connection()
    cursor = connection.execute("DELETE FROM modules WHERE id = ? AND course_id = ?", (module_id, course_id))
    connection.commit()
    connection.close()
    if cursor.rowcount == 0:
        return error("Module not found", 404)
    return jsonify({"ok": True})


initialize_database()

if __name__ == "__main__":
    app.run(host=os.getenv("NULLSPACE_HOST", "127.0.0.1"), port=int(os.getenv("NULLSPACE_PORT", "5000")), debug=False)
