# SOAR Sentinel — Full Stack Mini Project

**Submitted as:** Full Stack Web Development Mini Project
**Domain:** Cybersecurity / Security Operations
**Type:** Role-based web application with database backend

---

## 1. Project Title
**SOAR Sentinel — A Local Security Orchestration, Automation and Response (SOAR) Analyst Workspace**

## 2. What is it? (Abstract / Introduction)
SOAR Sentinel is a **web-based security incident management workspace**. In real
companies, security teams receive hundreds of alerts daily and use a "SOAR" platform to
collect them, investigate the indicators, follow response procedures, and get human approval
before acting. SOAR Sentinel is a **safe, self-contained learning version** of such a platform.

It lets an analyst **log incidents, auto-extract suspicious indicators (IP/domain/URL/hash),
assign owners, take notes, and request response actions that a human must approve** — all inside a
secure, modern web interface backed by a database.

> **Safety note (important for the viva):** This is an *educational demo*. It uses **simulated
enrichment** (no real threat feeds) and performs **no destructive/real-world actions** (no account
lockouts, no network blocks). Response actions are only *proposals* that a human approves.

## 3. Problem Statement & Why this project? (Motivation)
- Security teams are overwhelmed by alerts and need a **central place** to track them.
- Manual investigation is error-prone; **automation + human-in-the-loop** reduces mistakes.
- Beginners rarely get to safely experiment with SOAR tools, which touch live systems.
- **Goal:** Build a **full stack** app that demonstrates real-world architecture — authentication,
  authorization, databases, CRUD, automation logic, and an interactive UI — while staying **safe**.

## 4. Objectives
1. Implement **secure login** with password hashing and role-based access.
2. Store data in a **relational database** and perform full CRUD operations.
3. Add **automation** (auto-triage: indicator extraction + playbook suggestion).
4. Enforce **human-in-the-loop approval** for any response action.
5. Deliver a **modern, responsive, interactive UI** with dark/light theme.
6. Maintain an **audit trail** of all actions.

## 5. What does it do? (Features / Modules)
| # | Module | What it does |
|---|--------|--------------|
| 1 | **Authentication & Authorization** | Sign-in, hashed passwords, 3 roles (Admin, Analyst, Viewer), login throttling |
| 2 | **Incident Management (CRUD)** | Create, view, search, filter, and update incidents |
| 3 | **Case Investigation Page** | Per-incident detail: assignment, status, notes timeline |
| 4 | **Indicator Auto-Extraction (Automation)** | Regex-based extraction of IPv4, domain, URL, email, SHA-256, MD5 |
| 5 | **Simulated Enrichment** | Assigns a verdict (Malicious/Internal/Unknown) to each indicator |
| 6 | **Auto-Triage & Priority** | Scores priority (P1–P4) and suggests a playbook automatically |
| 7 | **Playbooks (Dry-run)** | View structured response workflows as safe previews — nothing executes |
| 8 | **Human-in-the-Loop Approvals** | Analysts *request* an action; Admin *approves/rejects* it |
| 9 | **Alert Ingestion Webhook** | Token-authenticated API that creates a case from an external alert (SIEM-style) |
| 10 | **Audit Log** | Records logins, changes, approvals, and ingested alerts |
| 11 | **Reports** | Visual severity/status breakdowns of incidents |
| 12 | **Interactive UI** | Dark/light theme, responsive layout, assistant panel, live "test alert" |

## 6. Tech Stack (and WHY each was chosen)
| Layer | Technology | Why we used it |
|-------|-----------|----------------|
| **Frontend** | HTML5, CSS3, JavaScript | Standard web fundamentals; CSS gives full design control without extra dependencies |
| **Templating** | Jinja2 (with Flask) | Renders dynamic HTML pages server-side; keeps code DRY with template inheritance |
| **Backend** | Python + Flask | Lightweight, beginner-friendly web framework; ideal for a mini project; easy to read |
| **Security** | Werkzeug | Built-in password hashing (pbkdf2) and safe password verification |
| **Database** | SQLite (via Python `sqlite3`) | Zero-setup, file-based relational DB — perfect for local demos; uses standard SQL |
| **CLI** | Click (ships with Flask) | Powers admin commands like `create-admin` and `seed-demo` |
| **API** | Flask JSON endpoints (`/api/...`) | Enables the webhook + "send test alert" feature (REST-style) |

**One-line answer:** *"It's a Python + Flask backend with a SQLite database and an HTML/CSS/JavaScript frontend."*

## 7. System Architecture & Working (How it works)
```
  Browser (HTML/CSS/JS)
        │  HTTP request (form or fetch)
        ▼
  Flask Application (app.py)  ── routes + auth + automation logic
        │  SQL
        ▼
  SQLite Database (soar.db)   ── incidents, users, observables, notes, approvals, audit
```
**Flow example (auto-triage):**
1. Analyst creates an incident with details, OR a SIEM sends an alert to the webhook.
2. Backend scans the text → extracts indicators → enriches them (simulated).
3. It scores a priority and suggests a matching playbook.
4. Case is saved to the database with its indicators.
5. Analyst requests a response action → Admin approves/rejects in the Approvals page.
6. Every step is written to the **audit log**.

## 8. Database Design (Tables)
| Table | Purpose |
|-------|---------|
| `users` | Accounts (username, hashed password, role, active) |
| `incidents` | Case records (title, severity, source, status, assignee, playbook, priority, timestamps) |
| `observables` | Extracted indicators (type, value, verdict, context) |
| `notes` | Investigation timeline entries per incident |
| `approvals` | Requested response actions + human decision |
| `audit` | Immutable record of all actions |
| `login_attempts` | Supports login rate-limiting |

## 9. Security Features (strong viva points)
- **Password hashing** with Werkzeug (pbkdf2) — no plaintext passwords stored.
- **Role-based access control** enforced on every route.
- **CSRF protection** on all POST requests (constant-time token compare).
- **Login throttling** (5 attempts / 15 minutes) + generic error messages.
- **Security headers**: CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, HSTS.
- **Input validation** on all forms and the ingestion API.
- **Human-in-the-loop**: no automated destructive action is ever performed.

## 10. How to Run (Setup — for demo)
```
# 1. Install dependencies
pip install -r requirements.txt

# 2. Create the first admin (you choose a password)
flask --app app create-admin

# 3. (Optional) add sample data
flask --app app seed-demo

# 4. Start the server
python app.py

# 5. Open in browser
http://127.0.0.1:5000
```
> **Quick demo account (already created on this machine):** username `admin`, password `Admin12345!demo`
> Or simply **double-click `start.bat`** to launch automatically.

## 11. Testing
- Manual + automated smoke test confirmed: login, dashboard, incident creation, case detail,
  approvals, and the ingestion API all work end-to-end.
- Static validation: all routes resolve, CSRF present, all UI classes styled, no encoding issues.

## 12. Future Scope (Improvements)
- Connect to a **real threat-intelligence API** for live enrichment.
- Add **email/Slack notifications** on high-priority incidents.
- Migrate to **PostgreSQL** and a production server (Gunicorn) for scale.
- Add a real **playbook execution engine** behind approval gates.
- Dashboards with charts and time-series analytics.

## 13. Conclusion
SOAR Sentinel demonstrates a **complete full stack workflow**: a secure Python/Flask backend,
an SQLite relational database, and an interactive HTML/CSS/JavaScript frontend — combined with
practical **automation** (indicator extraction + auto-triage) and responsible **human-in-the-loop**
security. It is safe to demo, easy to run, and models how real security operations tools behave.

---
*Prepared by: [Your Name] · [Class/Roll No.] · [Guide/Teacher Name]*

---

# Appendix A — Users & Working (Hinglish Explanation)

### 👤 End User kaun hai?
**End user = jo banda is app ko browser mein khol ke use karta hai** — matlab ek *Security Analyst*
ya *Admin* (jise SOC team bolte hain). Ye woh banda hota hai jo rozana security alerts dekhta hai,
incidents investigate karta hai, aur decision leta hai ki kya karna hai.

### 🧑‍💼 Project mein kaun-kaun use karta hai (3 roles):
| Role | Hinglish mein kaam | Kya kar sakta hai |
|------|--------------------|-------------------|
| **Viewer** | Sirf dekhne wala | Dashboard, incidents, reports **dekh** sakta hai. Kuch **badal nahi** sakta. |
| **Analyst** | Case solve karne wala | Incident create kare, indicator add kare, note likhe, response action **request** kare. |
| **Admin** | Boss / final decision | Sab kuch + naye users banaye + analyst ki request **approve/reject** kare. |

**Ek line mein:** *"Analyst kaam karta hai, Admin decide karta hai, Viewer sirf dekhta hai."*

### ⚙️ Working kaise hoti hai? (Step by Step — Hinglish)
1. **Login** – User apne username/password se login karta hai. Password database mein
   *hashed* (encrypted) form mein save hota hai, safe rehta hai.
2. **Dashboard** – Login ke baad Overview page khulta hai: total incidents, kitne open,
   investigating, resolved — sab numbers dikhte hain.
3. **Incident create** – Analyst naya incident daalta hai (jaise "Suspicious PowerShell"),
   ya koi bahar se (SIEM) alert webhook pe bhejta hai.
4. **Automation (Robot kaam)** – Jaise hi incident banta hai, system khud text ko padh ke
   indicators (IP, domain, hash) nikaalta hai, unhe check karta hai (simulated enrichment),
   priority (P1–P4) set karta hai, aur sahi playbook suggest karta hai. *Ye automation hai.*
5. **Investigate** – Analyst case detail page pe jaata hai: indicator dekhta hai, owner assign
   karta hai, timeline mein notes likhta hai.
6. **Approval (Insaan ka faisla)** – Analyst response action *request* karta hai (jaise
   "account disable karo"). Ye turant nahi hota — Admin usse **approve ya reject** karta hai.
   *Isliye kehte hain "human-in-the-loop" — final faisla insaan leta hai, robot nahi.*
7. **Reports + Audit** – Saara kaam record hota hai (audit log), aur reports mein data ka
   summary dikhta hai.

### 🔁 Data kahan jaata hai? (Simple flow)
```
Browser (user)  →  Flask app (logic + automation)  →  SQLite database (saved data)
```
User form bharta hai → Flask process karta hai → database mein save hota hai → page refresh hoke
naya data dikhta hai.

### 🛡️ Safety (viva mein zaroor bolna)
Ye ek **safe demo** hai — koi real system ya account nahi hota. Enrichment **simulated** hai,
aur response action sirf **proposal** hota hai jo Admin approve kare. Isliye ye practice karne ke liye safe hai.