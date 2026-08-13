import streamlit as st
from pypdf import PdfReader
import os
import json
import time
import sqlite3
import hashlib
import secrets
from pathlib import Path
from dotenv import load_dotenv
from google import genai
from streamlit_agraph import agraph, Node, Edge, Config
import streamlit.components.v1 as components

# ============================================================
# USER ACCOUNTS
# ============================================================
DB_PATH = str(Path(__file__).resolve().parent / "users.db")

# ============================================================
# CHAT HISTORY DATABASE
# ============================================================

def init_chat_tables():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    cur = conn.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            title TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS chat_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER NOT NULL,
            role TEXT NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(chat_id) REFERENCES chats(id) ON DELETE CASCADE
        )
    """)

    conn.commit()
    conn.close()


def create_chat(username, title="New Chat"):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO chats (username, title) VALUES (?, ?)",
        (username, title)
    )
    chat_id = cur.lastrowid
    conn.commit()
    conn.close()
    return chat_id


def save_chat_message(chat_id, role, content):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO chat_messages (chat_id, role, content) VALUES (?, ?, ?)",
        (chat_id, role, content)
    )
    cur.execute(
        "UPDATE chats SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (chat_id,)
    )
    conn.commit()
    conn.close()


def get_user_chats(username, search_text=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    if search_text.strip():
        like = f"%{search_text.strip()}%"
        cur.execute("""
            SELECT DISTINCT c.id, c.title, c.created_at, c.updated_at
            FROM chats c
            LEFT JOIN chat_messages m ON c.id = m.chat_id
            WHERE c.username = ?
              AND (c.title LIKE ? OR m.content LIKE ?)
            ORDER BY c.updated_at DESC
        """, (username, like, like))
    else:
        cur.execute("""
            SELECT id, title, created_at, updated_at
            FROM chats
            WHERE username = ?
            ORDER BY updated_at DESC
        """, (username,))

    rows = cur.fetchall()
    conn.close()
    return rows


def get_chat_messages(chat_id, username):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        SELECT m.role, m.content, m.created_at
        FROM chat_messages m
        JOIN chats c ON c.id = m.chat_id
        WHERE m.chat_id = ? AND c.username = ?
        ORDER BY m.id ASC
    """, (chat_id, username))
    rows = cur.fetchall()
    conn.close()
    return rows


def rename_chat(chat_id, username, title):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "UPDATE chats SET title = ?, updated_at = CURRENT_TIMESTAMP "
        "WHERE id = ? AND username = ?",
        (title.strip()[:80] or "New Chat", chat_id, username)
    )
    conn.commit()
    conn.close()


def delete_chat(chat_id, username):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        DELETE FROM chat_messages
        WHERE chat_id = ?
          AND EXISTS (
              SELECT 1 FROM chats
              WHERE chats.id = ? AND chats.username = ?
          )
    """, (chat_id, chat_id, username))

    cur.execute(
        "DELETE FROM chats WHERE id = ? AND username = ?",
        (chat_id, username)
    )

    conn.commit()
    conn.close()


def generate_chat_title(message):
    cleaned = " ".join(message.split()).strip()
    if not cleaned:
        return "New Chat"
    return cleaned[:60] + ("..." if len(cleaned) > 60 else "")


def get_or_create_current_chat(username):
    chat_id = st.session_state.get("current_chat_id")

    if chat_id is not None:
        chats = get_user_chats(username)
        if any(row[0] == chat_id for row in chats):
            return chat_id

    chat_id = create_chat(username, "New Chat")
    st.session_state.current_chat_id = chat_id
    return chat_id



def init_database():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

init_database()
init_chat_tables()

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        120000
    ).hex()
    return password_hash, salt

def create_user(username, email, password):
    password_hash, salt = hash_password(password)
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (username, email, password_hash, salt) VALUES (?, ?, ?, ?)",
            (username.strip(), email.strip().lower(), password_hash, salt)
        )
        conn.commit()
        conn.close()
        return True, "Account created successfully."
    except sqlite3.IntegrityError:
        return False, "That username or email is already registered."
    except Exception as e:
        return False, f"Could not create account: {e}"

def verify_user(identifier, password):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT username, email, password_hash, salt FROM users WHERE username = ? OR email = ?",
        (identifier.strip(), identifier.strip().lower())
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return False, None

    username, email, stored_hash, salt = row
    password_hash, _ = hash_password(password, salt)

    if secrets.compare_digest(password_hash, stored_hash):
        return True, {"username": username, "email": email}

    return False, None

def render_auth_page():
    st.markdown("""
    <style>
    .auth-wrap {
        max-width: 460px;
        margin: 7vh auto 0;
    }
    .auth-logo {
        width: 64px;
        height: 64px;
        border-radius: 19px;
        display: flex;
        align-items: center;
        justify-content: center;
        margin: 0 auto 18px;
        background: linear-gradient(135deg,#6C63FF,#8B5CF6);
        color: white;
        font-size: 31px;
        box-shadow: 0 14px 35px rgba(108,99,255,.25);
    }
    .auth-title {
        text-align: center;
        font-size: 30px;
        font-weight: 800;
        letter-spacing: -.6px;
    }
    .auth-subtitle {
        text-align: center;
        color: #7B8190;
        font-size: 13px;
        margin: 7px 0 25px;
    }
    .auth-card {
        background: rgba(255,255,255,.96);
        border: 1px solid #E7E8EF;
        border-radius: 22px;
        padding: 28px;
        box-shadow: 0 18px 55px rgba(25,28,55,.09);
    }
    </style>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="auth-wrap">
        <div class="auth-logo">📚</div>
        <div class="auth-title">AI Notes Studio</div>
        <div class="auth-subtitle">Your personal AI-powered learning workspace</div>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.get("theme") == "🌙 Dark":
        st.markdown("""
        <style>
        .auth-card {
            background:#171A24 !important;
            border-color:#292D3B !important;
        }
        .auth-title { color:#F5F6FA !important; }
        .auth-subtitle { color:#9DA4B5 !important; }
        </style>
        """, unsafe_allow_html=True)

    st.markdown('<div class="auth-card">', unsafe_allow_html=True)

    tab_login, tab_register = st.tabs(["🔐 Login", "✨ Create Account"])

    with tab_login:
        st.markdown("### Welcome back")
        identifier = st.text_input(
            "Username or email",
            placeholder="Enter your username or email",
            key="login_identifier"
        )
        password = st.text_input(
            "Password",
            type="password",
            placeholder="Enter your password",
            key="login_password"
        )

        if st.button("🔓 Login", use_container_width=True, key="login_button"):
            if not identifier.strip() or not password:
                st.warning("Please enter your username/email and password.")
            else:
                valid, user = verify_user(identifier, password)
                if valid:
                    st.session_state.authenticated = True
                    st.session_state.current_user = user
                    st.session_state.page = "🏠 Dashboard"
                    st.success("Login successful.")
                    st.rerun()
                else:
                    st.error("Incorrect username/email or password.")

    with tab_register:
        st.markdown("### Create your account")
        new_username = st.text_input(
            "Username",
            placeholder="Choose a username",
            key="register_username"
        )
        new_email = st.text_input(
            "Email",
            placeholder="you@example.com",
            key="register_email"
        )
        new_password = st.text_input(
            "Password",
            type="password",
            placeholder="At least 8 characters",
            key="register_password"
        )
        confirm_password = st.text_input(
            "Confirm password",
            type="password",
            placeholder="Repeat your password",
            key="register_confirm"
        )

        if st.button("✨ Create Account", use_container_width=True, key="register_button"):
            if not new_username.strip() or not new_email.strip() or not new_password:
                st.warning("Please fill in all fields.")
            elif len(new_password) < 8:
                st.warning("Password must contain at least 8 characters.")
            elif new_password != confirm_password:
                st.error("Passwords do not match.")
            elif "@" not in new_email or "." not in new_email:
                st.warning("Please enter a valid email address.")
            else:
                created, message = create_user(
                    new_username,
                    new_email,
                    new_password
                )
                if created:
                    st.success("Account created! Open the Login tab to sign in.")
                else:
                    st.error(message)

    st.markdown("</div>", unsafe_allow_html=True)

    st.markdown(
        '<div class="footer">🔒 Your account is protected with password hashing.</div>',
        unsafe_allow_html=True
    )

# Initialize database before authentication.
init_database()

# ============================================================
# PAGE CONFIG
# ============================================================
st.set_page_config(
    page_title="AI Notes Studio",
    page_icon="📚",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ============================================================
# LOAD ENVIRONMENT
# ============================================================
load_dotenv()
API_KEY = os.getenv("GEMINI_API_KEY")

# ============================================================
# PROFESSIONAL DESIGN SYSTEM
# ============================================================
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

:root {
    --primary: #6C63FF;
    --primary-dark: #5548e8;
    --accent: #8B5CF6;
    --bg: #F7F8FC;
    --card: #FFFFFF;
    --text: #171923;
    --muted: #6B7280;
    --border: #E7E8EF;
    --soft: #F1F2FF;
    --success: #16A34A;
    --shadow: 0 10px 35px rgba(25, 28, 55, 0.07);
}

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 0%, rgba(108,99,255,.08), transparent 25%),
        radial-gradient(circle at 90% 10%, rgba(139,92,246,.07), transparent 25%),
        var(--bg);
    color: var(--text);
}

.block-container {
    max-width: 1450px;
    padding: 1.5rem 2.2rem 4rem;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: rgba(255,255,255,.92);
    border-right: 1px solid var(--border);
}

section[data-testid="stSidebar"] > div {
    padding-top: 1.2rem;
}

.brand {
    padding: 8px 8px 20px;
}

.brand-row {
    display: flex;
    align-items: center;
    gap: 12px;
}

.brand-icon {
    width: 44px;
    height: 44px;
    border-radius: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: linear-gradient(135deg, #6C63FF, #8B5CF6);
    color: white;
    font-size: 22px;
    box-shadow: 0 8px 20px rgba(108,99,255,.25);
}

.brand-name {
    font-size: 17px;
    font-weight: 800;
    color: #171923;
}

.brand-sub {
    font-size: 11px;
    color: #8A8F9D;
    margin-top: 2px;
}

.sidebar-label {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .12em;
    color: #9AA0AD;
    font-weight: 700;
    margin: 12px 8px 8px;
}

/* Sidebar navigation buttons */
section[data-testid="stSidebar"] .stButton > button {
    text-align: left !important;
    justify-content: flex-start !important;
    background: transparent;
    border: 1px solid transparent;
    color: #3F4350;
    margin: 3px 0;
}

section[data-testid="stSidebar"] .stButton > button:hover {
    background: #F2F2FF;
    border-color: rgba(108,99,255,.15);
    color: #5548E8;
    transform: translateX(2px);
}
/* Top bar */
.topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 22px;
}

.eyebrow {
    color: var(--primary);
    font-size: 12px;
    font-weight: 800;
    letter-spacing: .12em;
    text-transform: uppercase;
}

.page-title {
    font-size: 34px;
    line-height: 1.15;
    font-weight: 800;
    letter-spacing: -.8px;
    margin: 4px 0;
}

.page-subtitle {
    color: var(--muted);
    font-size: 14px;
    margin: 0;
}

/* Hero */
.hero {
    position: relative;
    overflow: hidden;
    border-radius: 24px;
    padding: 38px;
    margin: 8px 0 24px;
    background:
        radial-gradient(circle at 85% 20%, rgba(255,255,255,.22), transparent 25%),
        linear-gradient(135deg, #5147E8 0%, #765BEF 48%, #9A68F4 100%);
    color: white;
    box-shadow: 0 18px 45px rgba(92,76,220,.20);
}

.hero:after {
    content: "";
    position: absolute;
    width: 240px;
    height: 240px;
    border-radius: 50%;
    right: -80px;
    bottom: -100px;
    background: rgba(255,255,255,.09);
}

.hero h1 {
    font-size: 38px;
    margin: 0 0 9px;
    letter-spacing: -.9px;
    font-weight: 800;
}

.hero p {
    margin: 0;
    opacity: .88;
    font-size: 15px;
    max-width: 640px;
}

.hero-badge {
    display: inline-block;
    padding: 6px 10px;
    border-radius: 999px;
    background: rgba(255,255,255,.14);
    border: 1px solid rgba(255,255,255,.18);
    font-size: 11px;
    font-weight: 700;
    margin-bottom: 15px;
}

/* Cards */
.card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 22px;
    box-shadow: var(--shadow);
    margin-bottom: 18px;
}

.card-title {
    font-weight: 750;
    font-size: 16px;
    margin-bottom: 5px;
}

.card-subtitle {
    color: var(--muted);
    font-size: 12px;
}

/* Metrics */
.metric-card {
    background: white;
    border: 1px solid var(--border);
    border-radius: 17px;
    padding: 18px;
    box-shadow: var(--shadow);
    min-height: 105px;
}

.metric-icon {
    font-size: 20px;
    margin-bottom: 8px;
}

.metric-value {
    font-size: 22px;
    font-weight: 800;
}

.metric-label {
    color: var(--muted);
    font-size: 12px;
    margin-top: 2px;
}

/* Feature cards */
.feature-card {
    background: white;
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 20px;
    min-height: 145px;
    box-shadow: var(--shadow);
}

.feature-icon {
    font-size: 24px;
    margin-bottom: 11px;
}

.feature-title {
    font-size: 15px;
    font-weight: 750;
}

.feature-text {
    font-size: 12px;
    color: var(--muted);
    line-height: 1.55;
    margin-top: 5px;
}

/* Upload */
[data-testid="stFileUploader"] {
    background: white;
    border: 1.5px dashed #C9CBE3;
    border-radius: 18px;
    padding: 16px;
    box-shadow: var(--shadow);
}

[data-testid="stFileUploader"]:hover {
    border-color: var(--primary);
}

/* Buttons */
.stButton > button {
    width: 100%;
    min-height: 43px;
    border-radius: 11px;
    border: 1px solid var(--border);
    font-weight: 700;
    transition: all .18s ease;
}

.stButton > button:hover {
    border-color: rgba(108,99,255,.4);
    color: var(--primary);
    transform: translateY(-1px);
    box-shadow: 0 8px 20px rgba(40,40,80,.08);
}

/* Inputs */
.stTextInput input,
.stTextArea textarea,
.stSelectbox div[data-baseweb="select"] > div {
    border-radius: 11px !important;
}

/* Expanders */
[data-testid="stExpander"] {
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
}

/* Tabs */
button[data-baseweb="tab"] {
    font-weight: 700;
}

/* Alerts */
[data-testid="stAlert"] {
    border-radius: 13px;
}

/* Divider */
hr {
    border: 0;
    border-top: 1px solid var(--border);
    margin: 28px 0;
}

/* Chat */
[data-testid="stChatMessage"] {
    border-radius: 16px;
    margin-bottom: 10px;
}

[data-testid="stChatInput"] {
    border-radius: 16px;
}

/* Footer */
.footer {
    text-align: center;
    color: #9297A4;
    font-size: 11px;
    padding: 25px 0 5px;
}

/* Dark mode */
body.dark-app .stApp { background: #0E1017; color: #F4F5F7; }
</style>
""", unsafe_allow_html=True)

# ============================================================
# SESSION STATE
# ============================================================
defaults = {
    "page": "🏠 Dashboard",
    "notes_text": "",
    "file_name": "",
    "summary": "",
    "important_points": "",
    "key_topics": "",
    "quiz_data": None,
    "quiz_version": 0,
    "quiz_submitted": False,
    "quiz_score": 0,
    "flashcards": None,
    "flashcard_index": 0,
    "show_answer": False,
    "diagram_data": None,
    "toc_data": None,
    "theme": "☀️ Light",
    "authenticated": False,
    "current_user": None,
    "study_history": [],
    "current_chat_id": None,
    "chat_search": "",
}
for key, value in defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

# Show login/register before loading the main application.
if not st.session_state.authenticated:
    render_auth_page()
    st.stop()

# ============================================================
# SIDEBAR
# ============================================================
with st.sidebar:
    st.markdown("""
    <div class="brand">
        <div class="brand-row">
            <div class="brand-icon">📚</div>
            <div>
                <div class="brand-name">AI Notes Studio</div>
                <div class="brand-sub">Smart learning workspace</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    current_user = st.session_state.current_user or {}
    st.markdown(
        f"""
        <div class="account-card" style="
            padding:10px 12px;
            margin:0 0 15px;
            border:1px solid #E7E8EF;
            border-radius:14px;
            background:rgba(108,99,255,.05);">
            <div style="font-size:10px;color:#9297A4;text-transform:uppercase;font-weight:800;">
                Signed in as
            </div>
            <div style="font-weight:750;font-size:13px;margin-top:3px;">
                👤 {current_user.get("username", "User")}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="sidebar-label">Recent Chats</div>', unsafe_allow_html=True)

    sidebar_username = (st.session_state.current_user or {}).get("username", "")
    recent_chats = get_user_chats(sidebar_username)[:5]

    if recent_chats:
        for chat_id, title, created_at, updated_at in recent_chats:
            if st.button(
                f"💬 {title[:25]}",
                key=f"quick_chat_{chat_id}",
                use_container_width=True,
            ):
                st.session_state.current_chat_id = chat_id
                st.session_state.page = "💬 Chat"
                st.rerun()
    else:
        st.caption("No chats yet.")

    if st.button(
        "➕ New Chat",
        key="sidebar_new_chat",
        use_container_width=True,
    ):
        st.session_state.current_chat_id = None
        st.session_state.page = "💬 Chat"
        st.rerun()

    st.markdown('<div class="sidebar-label">Workspace</div>', unsafe_allow_html=True)

    # REAL CLICKABLE NAVIGATION
    # Streamlit buttons are used instead of HTML anchors/radio styling.
    pages = [
        ("🏠", "Dashboard"),
        ("💬", "Chat"),
        ("🕘", "Chat History"),
        ("📄", "My Notes"),
        ("🤖", "AI Summary"),
        ("⭐", "Important Points"),
        ("📚", "Key Topics"),
        ("🎯", "Quiz"),
        ("🃏", "Flashcards"),
        ("🧠", "Concept Map"),
        ("🔎", "Search Notes"),
        ("📑", "Contents"),
        ("🗂️", "History"),
        ("🔊", "Listen"),
        ("⚙️", "Settings"),
    ]

    for icon, name in pages:
        page_name = f"{icon} {name}"
        is_active = st.session_state.page == page_name

        if is_active:
            st.markdown(
                f"""
                <div style="
                    background:linear-gradient(90deg,rgba(108,99,255,.14),rgba(139,92,246,.07));
                    border:1px solid rgba(108,99,255,.20);
                    color:#5B50E6;
                    border-radius:12px;
                    padding:10px 12px;
                    margin:4px 0;
                    font-weight:750;
                    font-size:14px;">
                    {page_name}
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            if st.button(
                page_name,
                key=f"sidebar_nav_{name.lower().replace(' ', '_')}",
                use_container_width=True,
            ):
                st.session_state.page = page_name
                st.rerun()

    st.markdown("---")

    if st.button("🚪 Log out", use_container_width=True, key="logout_button"):
        st.session_state.authenticated = False
        st.session_state.current_user = None
        st.session_state.page = "🏠 Dashboard"
        st.rerun()

    st.markdown('<div class="sidebar-label">Appearance</div>', unsafe_allow_html=True)
    st.session_state.theme = st.radio(
        "Theme",
        ["☀️ Light", "🌙 Dark"],
        index=0 if st.session_state.theme == "☀️ Light" else 1,
        label_visibility="collapsed",
        key="appearance_selector",
    )

    st.markdown("---")
    if st.session_state.file_name:
        st.markdown(
            f"""
            <div class="card" style="padding:14px;">
                <div style="font-size:11px;color:#8A8F9D;">CURRENT NOTE</div>
                <div style="font-weight:700;font-size:12px;margin-top:5px;">
                    📄 {st.session_state.file_name}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.caption("Upload a PDF to unlock your AI study tools.")

# ============================================================
# COMPLETE DARK / LIGHT THEME
# ============================================================
if st.session_state.theme == "🌙 Dark":
    st.markdown("""
    <style>
    /* ---------- GLOBAL DARK ---------- */
    .stApp {
        background:
            radial-gradient(circle at 10% 0%, rgba(108,99,255,.10), transparent 25%),
            radial-gradient(circle at 90% 10%, rgba(139,92,246,.08), transparent 25%),
            #0B0D13 !important;
        color: #F4F5F7 !important;
    }

    .block-container {
        color: #F4F5F7 !important;
    }

    /* ---------- SIDEBAR ---------- */
    section[data-testid="stSidebar"] {
        background: #11141C !important;
        border-right: 1px solid #252A38 !important;
    }

    section[data-testid="stSidebar"] .stButton > button {
        color: #D9DCE5 !important;
        background: transparent !important;
        border-color: transparent !important;
    }

    section[data-testid="stSidebar"] .stButton > button:hover {
        color: #FFFFFF !important;
        background: #1D2130 !important;
        border-color: #30364A !important;
    }

    /* ---------- TEXT ---------- */
    .page-title,
    .brand-name,
    .card-title,
    .metric-value,
    .feature-title,
    h1, h2, h3, h4, h5, h6,
    p, label {
        color: #F4F5F7 !important;
    }

    .page-subtitle,
    .brand-sub,
    .card-subtitle,
    .feature-text,
    .metric-label,
    .sidebar-label {
        color: #9DA4B5 !important;
    }

    .eyebrow {
        color: #8E86FF !important;
    }

    /* ---------- CARDS ---------- */
    .card,
    .metric-card,
    .feature-card {
        background: #161922 !important;
        border-color: #292E3C !important;
        color: #F4F5F7 !important;
        box-shadow: 0 12px 35px rgba(0,0,0,.22) !important;
    }

    /* ---------- FILE UPLOADER ---------- */
    [data-testid="stFileUploader"] {
        background: #161922 !important;
        border-color: #3A4052 !important;
        color: #F4F5F7 !important;
    }

    [data-testid="stFileUploader"] section {
        background: #161922 !important;
        border-color: #3A4052 !important;
    }

    [data-testid="stFileUploader"] small,
    [data-testid="stFileUploader"] span {
        color: #B8BECC !important;
    }

    /* ---------- BUTTONS ---------- */
    .stButton > button {
        background: #181C27 !important;
        color: #E8EAF0 !important;
        border-color: #303646 !important;
    }

    .stButton > button:hover {
        background: #222738 !important;
        color: #FFFFFF !important;
        border-color: #6C63FF !important;
    }

    /* ---------- INPUTS ---------- */
    .stTextInput input,
    .stTextArea textarea {
        background: #151822 !important;
        color: #F4F5F7 !important;
        border-color: #303646 !important;
    }

    .stTextInput input::placeholder,
    .stTextArea textarea::placeholder {
        color: #72798A !important;
    }

    /* ---------- SELECTBOX ---------- */
    div[data-baseweb="select"] > div {
        background: #151822 !important;
        color: #F4F5F7 !important;
        border-color: #303646 !important;
    }

    div[data-baseweb="select"] span {
        color: #F4F5F7 !important;
    }

    /* ---------- RADIO / CHECKBOX ---------- */
    div[role="radiogroup"] label,
    div[data-testid="stCheckbox"] label {
        color: #E5E7EC !important;
    }

    /* ---------- EXPANDERS ---------- */
    [data-testid="stExpander"] {
        background: #161922 !important;
        border-color: #292E3C !important;
    }

    [data-testid="stExpander"] summary,
    [data-testid="stExpander"] summary p {
        color: #F4F5F7 !important;
    }

    /* ---------- TABS ---------- */
    button[data-baseweb="tab"] {
        color: #BFC4D1 !important;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        color: #9A91FF !important;
    }

    /* ---------- METRICS ---------- */
    [data-testid="stMetricValue"] {
        color: #F4F5F7 !important;
    }

    [data-testid="stMetricLabel"] {
        color: #9DA4B5 !important;
    }

    /* ---------- ALERTS ---------- */
    [data-testid="stAlert"] {
        background: #171B25 !important;
        border-color: #303646 !important;
    }

    /* ---------- PROGRESS ---------- */
    div[data-testid="stProgress"] > div {
        background: #292E3C !important;
    }

    /* ---------- CHAT ---------- */
    [data-testid="stChatMessage"] {
        background: #161922 !important;
        border: 1px solid #292E3C !important;
    }

    [data-testid="stChatInput"] {
        background: #161922 !important;
        border-color: #303646 !important;
    }

    /* ---------- FOOTER ---------- */
    .footer {
        color: #737A8B !important;
    }

    /* ---------- DIVIDER ---------- */
    hr {
        border-top-color: #292E3C !important;
    }

    /* ---------- TABLE / DATA ---------- */
    [data-testid="stDataFrame"],
    [data-testid="stTable"] {
        background: #161922 !important;
    }
    </style>
    """, unsafe_allow_html=True)

# ============================================================
# AI

# ============================================================
if not API_KEY:
    st.error("❌ GEMINI_API_KEY was not found in your .env file.")
    st.info("Create a .env file beside app.py and add: GEMINI_API_KEY=your_key")
    st.stop()

client = genai.Client(api_key=API_KEY)

def generate_ai_response(prompt):
    """
    Use currently available Gemini models with a small fallback chain.
    Gemini 3.1 Flash-Lite is a current text-capable model suitable for
    high-volume lightweight tasks; Gemini 3 Flash Preview is a fallback.
    """
    models = [
        "gemini-3.1-flash-lite",
        "gemini-3-flash-preview",
    ]
    last_error = None

    for model_name in models:
        for attempt in range(2):
            try:
                response = client.models.generate_content(
                    model=model_name,
                    contents=prompt,
                )
                if getattr(response, "text", None):
                    return response.text
                raise RuntimeError(f"{model_name} returned an empty response.")
            except Exception as e:
                last_error = e
                error_text = str(e)
                if "503" in error_text and attempt == 0:
                    time.sleep(3)
                    continue
                break

    raise RuntimeError(
        "Gemini could not generate a response. "
        f"Last error: {last_error}"
    )

def clean_json(text):
    text = text.strip()
    if text.startswith("```json"):
        text = text[7:]
    elif text.startswith("```"):
        text = text[3:]
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()

def require_notes():
    if not st.session_state.notes_text.strip():
        st.warning("📤 Upload a PDF from **My Notes** first.")
        return False
    return True

# ============================================================
# PDF UPLOAD / PROCESS
# ============================================================
def process_pdf(uploaded_file):
    reader = PdfReader(uploaded_file)
    text = ""
    for page in reader.pages:
        page_text = page.extract_text() or ""
        if page_text:
            text += page_text + "\n"
    return text, len(reader.pages)

def save_history_item(file_name, page_count, text):
    item = {
        "file_name": file_name,
        "page_count": page_count,
        "characters": len(text),
        "timestamp": time.strftime("%d %b %Y • %I:%M %p"),
        "text": text,
    }

    st.session_state.study_history = [
        old for old in st.session_state.study_history
        if old["file_name"] != file_name
    ]
    st.session_state.study_history.insert(0, item)
    st.session_state.study_history = st.session_state.study_history[:10]

# ============================================================
# TOP BAR
# ============================================================
st.markdown("""
<div class="topbar">
    <div>
        <div class="eyebrow">AI-powered study workspace</div>
        <div class="page-title">Learn smarter, not harder.</div>
        <p class="page-subtitle">Turn your PDF notes into summaries, quizzes, flashcards and visual concepts.</p>
    </div>
</div>
""", unsafe_allow_html=True)

# ============================================================
# DASHBOARD
# ============================================================
if st.session_state.page == "🏠 Dashboard":

    st.markdown("""
    <div class="hero">
        <div class="hero-badge">✨ YOUR PERSONAL AI STUDY ASSISTANT</div>
        <h1>Transform your notes into knowledge.</h1>
        <p>Upload your study material and let AI help you understand, revise and practice faster.</p>
    </div>
    """, unsafe_allow_html=True)

    if not st.session_state.notes_text:
        st.markdown("""
        <div class="card">
            <div class="card-title">📄 Start with your study notes</div>
            <div class="card-subtitle">Upload a text-based PDF to unlock your complete learning workspace.</div>
        </div>
        """, unsafe_allow_html=True)

        uploaded_file = st.file_uploader(
            "Drop your PDF here",
            type=["pdf"],
            label_visibility="visible",
            key="dashboard_uploader",
        )

        if uploaded_file:
            try:
                text, pages = process_pdf(uploaded_file)
                if text.strip():
                    st.session_state.notes_text = text
                    st.session_state.file_name = uploaded_file.name
                    st.session_state.page_count = pages
                    save_history_item(uploaded_file.name, pages, text)
                    st.success(f"✅ {uploaded_file.name} is ready.")
                    st.rerun()
                else:
                    st.error("The PDF does not contain readable text.")
            except Exception as e:
                st.error(f"Could not read the PDF: {e}")

    else:
        page_count = st.session_state.get("page_count", 0)
        metrics = [
            ("📄", str(page_count), "Pages"),
            ("🤖", "Ready" if st.session_state.summary else "Not generated", "AI Summary"),
            ("🎯", "10" if st.session_state.quiz_data else "—", "Quiz questions"),
            ("🃏", "10" if st.session_state.flashcards else "—", "Flashcards"),
        ]
        cols = st.columns(4)
        for col, (icon, value, label) in zip(cols, metrics):
            with col:
                st.markdown(
                    f"""
                    <div class="metric-card">
                        <div class="metric-icon">{icon}</div>
                        <div class="metric-value">{value}</div>
                        <div class="metric-label">{label}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        st.markdown("### ✨ AI Learning Tools")

        features = [
            ("🤖", "AI Summary", "Convert long notes into a clear, exam-friendly summary.", "🤖 AI Summary"),
            ("⭐", "Important Points", "Extract the most important facts from your notes.", "⭐ Important Points"),
            ("📚", "Key Topics", "Discover the main topics and subtopics to study.", "📚 Key Topics"),
            ("🎯", "Quiz", "Practice with 10 AI-generated multiple-choice questions.", "🎯 Quiz"),
            ("🃏", "Flashcards", "Revise important concepts using interactive cards.", "🃏 Flashcards"),
            ("🧠", "Concept Map", "See relationships between concepts visually.", "🧠 Concept Map"),
        ]

        cols = st.columns(3)
        for i, (icon, title, description, target) in enumerate(features):
            with cols[i % 3]:
                st.markdown(
                    f"""
                    <div class="feature-card">
                        <div class="feature-icon">{icon}</div>
                        <div class="feature-title">{title}</div>
                        <div class="feature-text">{description}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if st.button(f"Open {title} →", key=f"dashboard_{i}"):
                    st.session_state.page = target
                    st.rerun()

        st.markdown("### 📄 Current Study Material")
        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">📘 {st.session_state.file_name}</div>
                <div class="card-subtitle">{len(st.session_state.notes_text):,} characters extracted from your notes.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ============================================================
# CHAT
# ============================================================
elif st.session_state.page == "💬 Chat":

    current_user = st.session_state.current_user or {}
    username = current_user.get("username", "User")

    # Create or validate the current chat.
    chat_id = get_or_create_current_chat(username)
    messages = get_chat_messages(chat_id, username)

    # Find title for header.
    user_chats = get_user_chats(username)
    current_title = "New Chat"
    for row in user_chats:
        if row[0] == chat_id:
            current_title = row[1]
            break

    st.markdown(
        f"""
        <div class="card">
            <div class="card-title">💬 {current_title}</div>
            <div class="card-subtitle">
                Ask questions, explain concepts, or study your uploaded notes with AI.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Chat controls
    col1, col2, col3 = st.columns([1, 1, 1])

    with col1:
        if st.button("➕ New Chat", key="chat_new_button", use_container_width=True):
            st.session_state.current_chat_id = create_chat(username, "New Chat")
            st.rerun()

    with col2:
        if st.button("✏️ Rename Chat", key="chat_rename_button", use_container_width=True):
            st.session_state.show_rename_box = True

    with col3:
        if st.button("🗑️ Delete Chat", key="chat_delete_button", use_container_width=True):
            delete_chat(chat_id, username)
            st.session_state.current_chat_id = None
            st.success("Chat deleted.")
            st.rerun()

    if st.session_state.get("show_rename_box", False):
        rename_col1, rename_col2 = st.columns([3, 1])
        with rename_col1:
            new_chat_name = st.text_input(
                "New chat name",
                value=current_title if current_title != "New Chat" else "",
                placeholder="Example: Machine Learning Revision",
                key="chat_rename_input",
            )
        with rename_col2:
            st.write("")
            st.write("")
            if st.button("Save", key="save_chat_name", use_container_width=True):
                rename_chat(chat_id, username, new_chat_name)
                st.session_state.show_rename_box = False
                st.rerun()

    st.markdown("---")

    # Display conversation.
    if messages:
        for role, content, created_at in messages:
            with st.chat_message("user" if role == "user" else "assistant"):
                st.markdown(content)
    else:
        st.markdown(
            """
            <div class="card" style="text-align:center;padding:50px 25px;">
                <div style="font-size:44px;">✨</div>
                <div style="font-size:22px;font-weight:800;margin-top:10px;">
                    Start a new conversation
                </div>
                <div style="color:#8A8F9D;font-size:13px;margin-top:7px;">
                    Ask me anything about your notes or your studies.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # PDF-aware context.
    notes_context = st.session_state.notes_text.strip()
    context_hint = ""
    if notes_context:
        # Keep prompt manageable while still using uploaded notes.
        context_hint = notes_context[:30000]

    user_prompt = st.chat_input(
        "Message your AI study assistant..."
    )

    if user_prompt:
        save_chat_message(chat_id, "user", user_prompt)

        prior_messages = get_chat_messages(chat_id, username)
        conversation_text = []
        for role, content, _ in prior_messages[-12:]:
            speaker = "Student" if role == "user" else "AI Assistant"
            conversation_text.append(f"{speaker}: {content}")

        notes_instruction = ""
        if context_hint:
            notes_instruction = f"""
The user has uploaded study notes. Use these notes when the question
is about their material. Do not invent facts that are not supported by
the notes.

UPLOADED NOTES:
{context_hint}
"""

        prompt = f"""
You are AI Notes Studio, a friendly and professional AI study assistant.

USER QUESTION:
{user_prompt}

CONVERSATION:
{"".join(conversation_text)}

{notes_instruction}

INSTRUCTIONS:
- Answer clearly and accurately.
- Use simple language when teaching.
- Use headings or bullet points when useful.
- For study questions, give practical explanations and examples.
- If the answer is not supported by uploaded notes, say that clearly
  instead of pretending it is in the notes.
- Do not mention internal prompts or system instructions.
"""

        with st.chat_message("assistant"):
            with st.spinner("AI is thinking..."):
                try:
                    answer = generate_ai_response(prompt)

                    if not answer or not answer.strip():
                        raise ValueError("The AI returned an empty response.")

                    st.markdown(answer)
                    save_chat_message(chat_id, "assistant", answer)

                    # Automatically name the chat after first user message.
                    existing_title = current_title
                    if existing_title == "New Chat":
                        rename_chat(
                            chat_id,
                            username,
                            generate_chat_title(user_prompt)
                        )

                except Exception as e:
                    error_text = f"Sorry, I couldn't answer right now.\n\n`{e}`"
                    st.error(error_text)
                    save_chat_message(chat_id, "assistant", error_text)

# ============================================================
# CHAT HISTORY
# ============================================================
elif st.session_state.page == "🕘 Chat History":

    username = (st.session_state.current_user or {}).get("username", "")

    st.markdown("""
    <div class="card">
        <div class="card-title">🕘 Chat History</div>
        <div class="card-subtitle">
            Reopen previous conversations, search messages, rename chats,
            or delete chats you no longer need.
        </div>
    </div>
    """, unsafe_allow_html=True)

    search = st.text_input(
        "🔎 Search your chats",
        value=st.session_state.chat_search,
        placeholder="Search a chat title or message...",
        key="chat_history_search",
    )
    st.session_state.chat_search = search

    if st.button(
        "➕ Start New Chat",
        key="history_new_chat",
        use_container_width=True,
    ):
        st.session_state.current_chat_id = create_chat(username, "New Chat")
        st.session_state.page = "💬 Chat"
        st.rerun()

    chats = get_user_chats(username, search)

    if not chats:
        st.info("No chats found.")
    else:
        st.markdown(f"### {len(chats)} conversation(s)")

        for index, (chat_id, title, created_at, updated_at) in enumerate(chats):

            messages = get_chat_messages(chat_id, username)
            preview = ""
            for role, content, _ in messages:
                if role == "user":
                    preview = " ".join(content.split())
                    break

            st.markdown(
                f"""
                <div class="card" style="padding:18px;">
                    <div style="display:flex;gap:14px;align-items:flex-start;">
                        <div style="
                            width:44px;height:44px;border-radius:13px;
                            background:linear-gradient(135deg,#6C63FF,#8B5CF6);
                            color:#fff;display:flex;align-items:center;
                            justify-content:center;font-size:20px;">
                            💬
                        </div>
                        <div style="flex:1;">
                            <div style="font-size:16px;font-weight:800;">
                                {title}
                            </div>
                            <div style="font-size:12px;color:#8A8F9D;margin-top:5px;">
                                {preview[:130] if preview else "No messages yet"}
                            </div>
                            <div style="font-size:11px;color:#9AA0AD;margin-top:8px;">
                                Last updated: {updated_at}
                            </div>
                        </div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            c1, c2, c3 = st.columns([1, 1, 1])

            with c1:
                if st.button(
                    "📖 Open",
                    key=f"history_chat_open_{chat_id}",
                    use_container_width=True,
                ):
                    st.session_state.current_chat_id = chat_id
                    st.session_state.page = "💬 Chat"
                    st.rerun()

            with c2:
                if st.button(
                    "✏️ Rename",
                    key=f"history_chat_rename_{chat_id}",
                    use_container_width=True,
                ):
                    st.session_state.rename_chat_id = chat_id
                    st.rerun()

            with c3:
                if st.button(
                    "🗑️ Delete",
                    key=f"history_chat_delete_{chat_id}",
                    use_container_width=True,
                ):
                    delete_chat(chat_id, username)
                    if st.session_state.current_chat_id == chat_id:
                        st.session_state.current_chat_id = None
                    st.success("Chat deleted.")
                    st.rerun()

            if st.session_state.get("rename_chat_id") == chat_id:
                rename_value = st.text_input(
                    "New title",
                    value=title,
                    key=f"history_rename_input_{chat_id}",
                )
                if st.button(
                    "Save title",
                    key=f"history_save_rename_{chat_id}",
                    use_container_width=True,
                ):
                    rename_chat(chat_id, username, rename_value)
                    st.session_state.rename_chat_id = None
                    st.rerun()

# ============================================================
# MY NOTES
# ============================================================
elif st.session_state.page == "📄 My Notes":

    st.markdown("""
    <div class="card">
        <div class="card-title">📄 My Notes</div>
        <div class="card-subtitle">Upload or review the study material used by the AI tools.</div>
    </div>
    """, unsafe_allow_html=True)

    uploaded_file = st.file_uploader(
        "Upload PDF notes",
        type=["pdf"],
        key="notes_uploader",
    )

    if uploaded_file:
        try:
            text, pages = process_pdf(uploaded_file)
            if text.strip():
                st.session_state.notes_text = text
                st.session_state.file_name = uploaded_file.name
                st.session_state.page_count = pages
                save_history_item(uploaded_file.name, pages, text)
                st.session_state.summary = ""
                st.session_state.important_points = ""
                st.session_state.key_topics = ""
                st.session_state.quiz_data = None
                st.session_state.flashcards = None
                st.session_state.diagram_data = None
                st.session_state.toc_data = None
                st.success("✅ New PDF loaded successfully.")
            else:
                st.error("No readable text was found in this PDF.")
        except Exception as e:
            st.error(f"Could not read PDF: {e}")

    if st.session_state.notes_text:
        st.markdown("### 📘 Current File")
        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">📄 {st.session_state.file_name}</div>
                <div class="card-subtitle">{st.session_state.get("page_count", 0)} pages • {len(st.session_state.notes_text):,} characters</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        with st.expander("👀 View extracted notes"):
            st.text_area(
                "Extracted text",
                st.session_state.notes_text,
                height=420,
                label_visibility="collapsed",
                key="notes_preview",
            )

        st.markdown("### 📑 Page-wise Notes")
        try:
            uploaded_file_for_pages = None
            if uploaded_file:
                uploaded_file_for_pages = uploaded_file
            if uploaded_file_for_pages:
                reader = PdfReader(uploaded_file_for_pages)
                for number, page in enumerate(reader.pages, 1):
                    page_text = page.extract_text() or ""
                    with st.expander(f"📄 Page {number}"):
                        if page_text.strip():
                            st.write(page_text)
                        else:
                            st.warning("No readable text found on this page.")
            else:
                st.info("Upload the PDF again on this page to inspect individual pages.")
        except Exception as e:
            st.error(f"Could not read pages: {e}")
    else:
        st.info("Upload a PDF to begin.")

# ============================================================
# AI SUMMARY
# ============================================================
elif st.session_state.page == "🤖 AI Summary":

    st.markdown("""
    <div class="card">
        <div class="card-title">🤖 AI Summary</div>
        <div class="card-subtitle">Get a simple, structured summary designed for revision.</div>
    </div>
    """, unsafe_allow_html=True)

    if require_notes():
        if st.button("✨ Generate AI Summary", key="professional_summary_button"):
            with st.spinner("AI is creating your summary..."):
                try:
                    prompt = f"""
You are a helpful study assistant.

Read the following student notes and create a clear,
easy-to-understand summary.

Rules:
- Keep the important information.
- Use simple language.
- Do not add information that is not in the notes.
- Make the summary useful for exam preparation.
- Use headings and bullet points where useful.

STUDENT NOTES:
{st.session_state.notes_text}
"""
                    st.session_state.summary = generate_ai_response(prompt)
                    st.success("Summary created successfully.")
                except Exception as e:
                    st.error(f"Could not create the summary: {e}")

        if st.session_state.summary:
            st.markdown("### ✨ Your Summary")
            st.markdown(
                f'<div class="card">{st.session_state.summary}</div>',
                unsafe_allow_html=True,
            )

# ============================================================
# IMPORTANT POINTS
# ============================================================
elif st.session_state.page == "⭐ Important Points":

    st.markdown("""
    <div class="card">
        <div class="card-title">⭐ Important Points</div>
        <div class="card-subtitle">Focus on the facts most useful for exam preparation.</div>
    </div>
    """, unsafe_allow_html=True)

    if require_notes():
        if st.button("🔍 Generate Important Points", key="professional_points_button"):
            with st.spinner("Finding important points..."):
                try:
                    prompt = f"""
Read these student notes and identify the 10 most important
points for exam preparation.

Rules:
- Give exactly 10 points if enough information is available.
- If the notes contain fewer important points, give only supported points.
- Number the points clearly.
- Keep each point short and clear.
- Use only information from the notes.
- Do not write a general summary.

STUDENT NOTES:
{st.session_state.notes_text}
"""
                    st.session_state.important_points = generate_ai_response(prompt)
                    st.success("Important points generated.")
                except Exception as e:
                    st.error(f"Could not generate important points: {e}")

        if st.session_state.important_points:
            st.markdown("### 📌 Exam Essentials")
            st.markdown(
                f'<div class="card">{st.session_state.important_points}</div>',
                unsafe_allow_html=True,
            )

# ============================================================
# KEY TOPICS
# ============================================================
elif st.session_state.page == "📚 Key Topics":

    st.markdown("""
    <div class="card">
        <div class="card-title">📚 Key Topics</div>
        <div class="card-subtitle">Identify the major topics and subtopics inside your notes.</div>
    </div>
    """, unsafe_allow_html=True)

    if require_notes():
        if st.button("📚 Generate Key Topics", key="professional_topics_button"):
            with st.spinner("Finding main topics..."):
                try:
                    prompt = f"""
Read the following student notes.

Identify the main topics and subtopics that a student should study.

Rules:
- Give 5 to 10 key topics if enough information is available.
- Number them clearly.
- Use short topic names.
- Do not write long explanations.
- Use only information found in the notes.
- Do not add outside information.

STUDENT NOTES:
{st.session_state.notes_text}
"""
                    st.session_state.key_topics = generate_ai_response(prompt)
                    st.success("Key topics generated.")
                except Exception as e:
                    st.error(f"Could not generate key topics: {e}")

        if st.session_state.key_topics:
            st.markdown("### 🧭 Study Roadmap")
            st.markdown(
                f'<div class="card">{st.session_state.key_topics}</div>',
                unsafe_allow_html=True,
            )

# ============================================================
# QUIZ
# ============================================================
elif st.session_state.page == "🎯 Quiz":

    st.markdown("""
    <div class="card">
        <div class="card-title">🎯 AI Quiz</div>
        <div class="card-subtitle">Test your understanding with 10 multiple-choice questions.</div>
    </div>
    """, unsafe_allow_html=True)

    if require_notes():
        if st.button("🎯 Generate 10 MCQs", key="professional_quiz_button"):
            with st.spinner("Creating your quiz..."):
                try:
                    prompt = f"""
Create exactly 10 multiple-choice questions from the following student notes.

Return ONLY valid JSON.

Use this exact structure:
[
  {{
    "question": "Question text",
    "options": ["Option A", "Option B", "Option C", "Option D"],
    "answer": "A"
  }}
]

Rules:
- Exactly 10 questions.
- Exactly 4 options per question.
- Correct answer must be A, B, C, or D.
- Use only the student notes.
- Do not add outside information.

STUDENT NOTES:
{st.session_state.notes_text}
"""
                    result = clean_json(generate_ai_response(prompt))
                    st.session_state.quiz_data = json.loads(result)
                    st.session_state.quiz_version += 1
                    st.session_state.quiz_submitted = False
                    st.success("10 questions generated.")
                except Exception as e:
                    st.error(f"Could not generate the quiz: {e}")

        if st.session_state.quiz_data:
            quiz_data = st.session_state.quiz_data
            version = st.session_state.quiz_version

            st.markdown("### 📝 Answer the Questions")
            st.info("Select one answer for every question, then submit your quiz.")

            for i, question in enumerate(quiz_data):
                st.markdown(
                    f'<div class="card"><div class="card-title">{i+1}. {question["question"]}</div></div>',
                    unsafe_allow_html=True,
                )
                st.radio(
                    "Choose your answer",
                    [
                        f"A. {question['options'][0]}",
                        f"B. {question['options'][1]}",
                        f"C. {question['options'][2]}",
                        f"D. {question['options'][3]}",
                    ],
                    index=None,
                    key=f"professional_quiz_{version}_{i}",
                )

            if st.button("✅ Submit Quiz", key=f"professional_submit_{version}"):
                score = 0
                unanswered = 0

                for i, question in enumerate(quiz_data):
                    selected = st.session_state.get(f"professional_quiz_{version}_{i}")
                    if selected is None:
                        unanswered += 1
                        continue
                    if selected[0] == question["answer"]:
                        score += 1

                st.session_state.quiz_score = score
                st.session_state.quiz_submitted = True

                percentage = (score / len(quiz_data)) * 100

                st.markdown("### 🏆 Your Result")
                c1, c2, c3 = st.columns(3)
                with c1:
                    st.metric("Score", f"{score} / {len(quiz_data)}")
                with c2:
                    st.metric("Percentage", f"{percentage:.0f}%")
                with c3:
                    st.metric("Unanswered", str(unanswered))

                st.progress(int(percentage))

                if percentage == 100:
                    st.success("🏆 Perfect score! Excellent work.")
                elif percentage >= 80:
                    st.success("🌟 Excellent! Keep it up.")
                elif percentage >= 60:
                    st.info("👍 Good job. Keep practicing.")
                elif percentage >= 40:
                    st.warning("📚 Keep studying. You can improve.")
                else:
                    st.error("💪 Keep practicing and try again.")

            if st.session_state.quiz_submitted:
                if st.button("🔄 Generate a New Quiz", key="professional_retry_quiz"):
                    st.session_state.quiz_data = None
                    st.session_state.quiz_submitted = False
                    st.rerun()

# ============================================================
# FLASHCARDS
# ============================================================
elif st.session_state.page == "🃏 Flashcards":

    st.markdown("""
    <div class="card">
        <div class="card-title">🃏 AI Flashcards</div>
        <div class="card-subtitle">Turn your notes into quick revision cards.</div>
    </div>
    """, unsafe_allow_html=True)

    if require_notes():
        if st.button("🃏 Generate 10 Flashcards", key="professional_flashcards_button"):
            with st.spinner("Creating flashcards..."):
                try:
                    prompt = f"""
Create exactly 10 study flashcards from the following student notes.

Return ONLY valid JSON:
[
  {{
    "question": "Question here",
    "answer": "Answer here"
  }}
]

Rules:
- Exactly 10 flashcards.
- One question and one answer per card.
- Useful for exam preparation.
- Answers should be short and clear.
- Use only the notes.

STUDENT NOTES:
{st.session_state.notes_text}
"""
                    result = clean_json(generate_ai_response(prompt))
                    st.session_state.flashcards = json.loads(result)
                    st.session_state.flashcard_index = 0
                    st.session_state.show_answer = False
                    st.success("10 flashcards generated.")
                except Exception as e:
                    st.error(f"Could not generate flashcards: {e}")

        if st.session_state.flashcards:
            cards = st.session_state.flashcards
            index = st.session_state.flashcard_index
            current = cards[index]

            st.markdown(
                f"""
                <div style="text-align:center;color:#6C63FF;font-weight:800;margin:15px 0;">
                    CARD {index+1} OF {len(cards)}
                </div>
                """,
                unsafe_allow_html=True,
            )

            st.markdown(
                f"""
                <div class="card" style="min-height:260px;text-align:center;
                    display:flex;flex-direction:column;justify-content:center;
                    padding:40px;">
                    <div style="font-size:12px;color:#8A8F9D;text-transform:uppercase;
                        letter-spacing:.1em;font-weight:700;">QUESTION</div>
                    <div style="font-size:25px;font-weight:800;margin-top:18px;">
                        {current["question"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            if not st.session_state.show_answer:
                if st.button("👀 Show Answer", key=f"professional_show_{index}"):
                    st.session_state.show_answer = True
                    st.rerun()
            else:
                st.markdown(
                    f"""
                    <div class="card" style="border-color:rgba(108,99,255,.25);
                        background:linear-gradient(135deg,rgba(108,99,255,.08),rgba(139,92,246,.05));">
                        <div style="font-size:12px;color:#6C63FF;text-transform:uppercase;
                            font-weight:800;">ANSWER</div>
                        <div style="font-size:18px;font-weight:650;margin-top:10px;">
                            {current["answer"]}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                if st.button("🙈 Hide Answer", key=f"professional_hide_{index}"):
                    st.session_state.show_answer = False
                    st.rerun()

            st.progress((index + 1) / len(cards))

            c1, c2, c3 = st.columns(3)
            with c1:
                if st.button("⬅️ Previous", key=f"professional_prev_{index}"):
                    if index > 0:
                        st.session_state.flashcard_index -= 1
                        st.session_state.show_answer = False
                        st.rerun()
            with c2:
                if st.button("🔄 Restart", key="professional_restart_cards"):
                    st.session_state.flashcard_index = 0
                    st.session_state.show_answer = False
                    st.rerun()
            with c3:
                if st.button("Next ➡️", key=f"professional_next_{index}"):
                    if index < len(cards) - 1:
                        st.session_state.flashcard_index += 1
                        st.session_state.show_answer = False
                        st.rerun()

# ============================================================
# CONCEPT MAP
# ============================================================
elif st.session_state.page == "🧠 Concept Map":

    st.markdown("""
    <div class="card">
        <div class="card-title">🧠 AI Concept Map</div>
        <div class="card-subtitle">
            Turn your notes into a clean, professional visual learning map.
        </div>
    </div>
    """, unsafe_allow_html=True)

    if require_notes():

        if st.button(
            "✨ Design My Concept Map",
            key="professional_diagram_button",
            use_container_width=True,
        ):
            with st.spinner("AI is designing your concept map..."):
                try:
                    prompt = f"""
Create a professional concept map from these student notes.

Return ONLY valid JSON in this exact structure:

{{
  "title": "Main Topic",
  "nodes": [
    {{"id": "1", "label": "Main Topic", "group": "main"}},
    {{"id": "2", "label": "Topic", "group": "topic"}},
    {{"id": "3", "label": "Concept", "group": "concept"}},
    {{"id": "4", "label": "Example", "group": "example"}}
  ],
  "edges": [
    {{"source": "1", "target": "2", "label": "contains"}},
    {{"source": "2", "target": "3", "label": "includes"}}
  ]
}}

Rules:
- Create 6 to 14 nodes.
- The first node must be the main topic.
- Use groups ONLY: main, topic, concept, example.
- Use short labels.
- Avoid duplicate nodes.
- Connect related ideas.
- Use only information from the notes.
- Return JSON only. No Markdown.

STUDENT NOTES:
{st.session_state.notes_text}
"""
                    result = clean_json(generate_ai_response(prompt))
                    st.session_state.diagram_data = json.loads(result)
                    st.success("✅ Professional concept map created.")
                except Exception as e:
                    st.error(f"Could not generate the concept map: {e}")

        if st.session_state.diagram_data:
            data = st.session_state.diagram_data

            st.markdown(
                f"""
                <div class="card" style="
                    background:linear-gradient(135deg,rgba(108,99,255,.08),rgba(139,92,246,.05));
                    border-color:rgba(108,99,255,.20);">
                    <div style="font-size:11px;text-transform:uppercase;
                        letter-spacing:.1em;color:#6C63FF;font-weight:800;">
                        VISUAL STUDY MAP
                    </div>
                    <div style="font-size:25px;font-weight:800;margin-top:7px;">
                        🧠 {data.get("title", "Concept Map")}
                    </div>
                    <div style="font-size:12px;color:#8A8F9D;margin-top:6px;">
                        {len(data.get("nodes", []))} concepts •
                        {len(data.get("edges", []))} connections
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            size_map = {
                "main": 42,
                "topic": 32,
                "concept": 25,
                "example": 20,
            }

            nodes = [
                Node(
                    id=str(n["id"]),
                    label=n["label"],
                    size=size_map.get(n.get("group", "concept"), 25),
                    title=n.get("group", "concept").title(),
                )
                for n in data.get("nodes", [])
            ]

            edges = [
                Edge(
                    source=str(e["source"]),
                    target=str(e["target"]),
                    label=e.get("label", ""),
                )
                for e in data.get("edges", [])
            ]

            config = Config(
                width=1000,
                height=650,
                directed=True,
                physics=True,
                hierarchical=False,
            )

            st.markdown("### 🎨 Visual Diagram")
            agraph(nodes=nodes, edges=edges, config=config)

            st.markdown("### 📋 Concepts")
            for node in data.get("nodes", []):
                group = node.get("group", "concept").title()
                st.markdown(
                    f"""
                    <div class="card" style="padding:12px 16px;margin-bottom:8px;">
                        <span style="color:#6C63FF;font-weight:800;">{group}</span>
                        <span style="font-weight:650;margin-left:10px;">
                            {node["label"]}
                        </span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

# ============================================================
# SEARCH NOTES
# ============================================================
elif st.session_state.page == "🔎 Search Notes":

    st.markdown("""
    <div class="card">
        <div class="card-title">🔎 Search Your Notes</div>
        <div class="card-subtitle">Find words, concepts or topics instantly inside your uploaded PDF.</div>
    </div>
    """, unsafe_allow_html=True)

    if require_notes():
        query = st.text_input(
            "Search",
            placeholder="Try: machine learning, neural network, regression...",
            key="professional_search",
        )

        if query.strip():
            matches = [
                line.strip()
                for line in st.session_state.notes_text.splitlines()
                if line.strip() and query.lower() in line.lower()
            ]

            if matches:
                st.success(f"Found {len(matches)} matching lines.")
                for i, match in enumerate(matches[:50], 1):
                    st.markdown(
                        f"""
                        <div class="card" style="padding:14px 18px;">
                            <b>{i}.</b> {match}
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
            else:
                st.warning(f"No results found for '{query}'.")

# ============================================================
# TABLE OF CONTENTS
# ============================================================
elif st.session_state.page == "📑 Contents":

    st.markdown("""
    <div class="card">
        <div class="card-title">📑 Table of Contents</div>
        <div class="card-subtitle">Create a clean study roadmap from your notes.</div>
    </div>
    """, unsafe_allow_html=True)

    if require_notes():
        if st.button("📑 Generate Table of Contents", key="professional_toc_button"):
            with st.spinner("Creating your table of contents..."):
                try:
                    prompt = f"""
Read the following student notes.

Create a Table of Contents containing the main topics and important sections.

Return ONLY valid JSON:
[
  "Introduction",
  "Main Topic",
  "Subtopic"
]

Rules:
- Give 5 to 15 topics.
- Use short topic names.
- Keep the original meaning.
- Arrange topics in the order they appear.
- Do not add information not in the notes.

STUDENT NOTES:
{st.session_state.notes_text}
"""
                    st.session_state.toc_data = json.loads(
                        clean_json(generate_ai_response(prompt))
                    )
                    st.success("Table of contents generated.")
                except Exception as e:
                    st.error(f"Could not generate the contents: {e}")

        if st.session_state.toc_data:
            for i, topic in enumerate(st.session_state.toc_data, 1):
                st.markdown(
                    f"""
                    <div class="card" style="padding:14px 18px;">
                        <span style="color:#6C63FF;font-weight:800;">{i:02}</span>
                        <span style="font-weight:700;margin-left:12px;">{topic}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

# ============================================================
# LISTEN
# ============================================================
elif st.session_state.page == "🔊 Listen":

    st.markdown("""
    <div class="card">
        <div class="card-title">🔊 Listen to Your Summary</div>
        <div class="card-subtitle">Use your browser's speech engine to listen while revising.</div>
    </div>
    """, unsafe_allow_html=True)

    summary = st.session_state.summary

    if not summary:
        st.warning("Please generate the AI Summary first.")
    else:
        st.markdown(
            f'<div class="card">{summary}</div>',
            unsafe_allow_html=True,
        )

        def speak_text(value):
            safe = (
                value.replace("\\", "\\\\")
                .replace("`", "\\`")
                .replace("${", "\\${")
            )
            components.html(
                f"""
                <script>
                window.speechSynthesis.cancel();
                const speech = new SpeechSynthesisUtterance(`{safe}`);
                speech.rate = 0.9;
                speech.pitch = 1;
                speech.volume = 1;
                window.speechSynthesis.speak(speech);
                </script>
                """,
                height=0,
            )

        def stop_speech():
            components.html(
                """
                <script>
                window.speechSynthesis.cancel();
                </script>
                """,
                height=0,
            )

        c1, c2 = st.columns(2)
        with c1:
            if st.button("🔊 Play Summary", key="professional_play"):
                speak_text(summary)
                st.success("Summary is playing.")
        with c2:
            if st.button("⏹️ Stop", key="professional_stop"):
                stop_speech()
                st.info("Speech stopped.")

# ============================================================
# STUDY HISTORY
# ============================================================
elif st.session_state.page == "🗂️ History":

    st.markdown("""
    <div class="card">
        <div class="card-title">🗂️ Study History</div>
        <div class="card-subtitle">
            Return to your recently studied notes without uploading them again.
        </div>
    </div>
    """, unsafe_allow_html=True)

    history = st.session_state.get("study_history", [])

    if not history:
        st.markdown("""
        <div class="card" style="text-align:center;padding:48px 25px;">
            <div style="font-size:44px;">📂</div>
            <div style="font-size:20px;font-weight:800;margin-top:10px;">
                No study history yet
            </div>
            <div style="color:#8A8F9D;font-size:13px;margin-top:6px;">
                Upload a PDF and it will automatically appear here.
            </div>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown(f"### Recent Study Files · {len(history)}")

        for i, item in enumerate(history):
            st.markdown(
                f"""
                <div class="card" style="padding:18px;">
                    <div style="font-size:22px;">📄</div>
                    <div style="font-size:15px;font-weight:800;margin-top:8px;">
                        {item["file_name"]}
                    </div>
                    <div style="color:#8A8F9D;font-size:12px;margin-top:5px;">
                        {item["page_count"]} pages •
                        {item["characters"]:,} characters •
                        {item["timestamp"]}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            c1, c2 = st.columns(2)

            with c1:
                if st.button(
                    "📖 Open Notes",
                    key=f"history_open_{i}",
                    use_container_width=True,
                ):
                    st.session_state.notes_text = item["text"]
                    st.session_state.file_name = item["file_name"]
                    st.session_state.page_count = item["page_count"]
                    st.session_state.summary = ""
                    st.session_state.important_points = ""
                    st.session_state.key_topics = ""
                    st.session_state.quiz_data = None
                    st.session_state.flashcards = None
                    st.session_state.diagram_data = None
                    st.session_state.toc_data = None
                    st.session_state.page = "📄 My Notes"
                    st.rerun()

            with c2:
                if st.button(
                    "🗑️ Remove",
                    key=f"history_remove_{i}",
                    use_container_width=True,
                ):
                    st.session_state.study_history.pop(i)
                    st.rerun()

        st.markdown("---")
        if st.button(
            "🧹 Clear All History",
            key="clear_history_button",
            use_container_width=True,
        ):
            st.session_state.study_history = []
            st.rerun()

# ============================================================
# SETTINGS
# ============================================================
elif st.session_state.page == "⚙️ Settings":

    st.markdown("""
    <div class="card">
        <div class="card-title">⚙️ Settings</div>
        <div class="card-subtitle">Manage your study workspace appearance and current session.</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### 🎨 Appearance")
    theme_choice = st.radio(
        "Theme",
        ["☀️ Light", "🌙 Dark"],
        index=0 if st.session_state.theme == "☀️ Light" else 1,
        key="settings_theme",
    )

    if theme_choice != st.session_state.theme:
        st.session_state.theme = theme_choice
        st.rerun()

    st.markdown("### 📊 Current Session")
    c1, c2 = st.columns(2)
    with c1:
        st.metric("Notes loaded", "Yes" if st.session_state.notes_text else "No")
    with c2:
        st.metric("Current file", st.session_state.file_name or "None")

    if st.button("🗑️ Clear Current Study Session", key="clear_session"):
        keep = {"page": st.session_state.page, "theme": st.session_state.theme}
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.session_state.update(defaults)
        st.session_state.update(keep)
        st.success("Session cleared.")
        st.rerun()

# ============================================================
# FOOTER
# ============================================================
st.markdown("""
<div class="footer">
    📚 AI Notes Studio &nbsp;•&nbsp; Learn smarter with AI
</div>
""", unsafe_allow_html=True)