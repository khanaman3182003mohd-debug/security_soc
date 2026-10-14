# SOAR Sentinel deployment — Hindi/Hinglish step-by-step
# Recommended: Render (Flask + SQLite sabse aasan yahan chalta hai)

===========================================================================
## ✅ SABSE PEHLE: Render vs Vercel — kaunsa chunein?
===========================================================================

| Cheez | Render (Recommended ✅) | Vercel |
|-------|-------------------------|--------|
| Flask support | Full, server hamesha chalu | Serverless — thoda tricky |
| SQLite database | Chalta hai (par restart pe reset) | ❌ Filesystem read-only — SQLite reliable NAHI |
| Setup | Bahut aasan | Mushkil |
| Free plan | Haan (so jaata hai 15 min baad) | Haan |

**Meri salah:** Is project ke liye **Render** use karo. 
Vercel pe SQLite save nahi hota (serverless hai, files temp hota hai), 
isliye data gayab ho jaata hai. Render pe bhi SQLite restart pe reset hota hai, 
par kam se kam app smoothly chalti hai.

Agar sirf **demo / project dikhana** hai → **Render** best hai.

===========================================================================
## 🚀 TARIKA 1: RENDER (Recommended)
===========================================================================

### Step 1 — Code ko GitHub pe daalo
Render GitHub se code leta hai. Pehle code GitHub pe push karo:
1. github.com pe naya repository banao (naam: soar-sentinel)
2. Project folder mein terminal kholo (VS Code mein Ctrl+`) aur:
   ```
   git init
   git add .
   git commit -m "SOAR Sentinel"
   git branch -M main
   git remote add origin https://github.com/<tumhara-username>/soar-sentinel.git
   git push -u origin main
   ```
   ⚠️ Note: `instance/` aur `.vscode/` GitHub pe nahi jaayenge (gitignore mein hain).

### Step 2 — Render pe deploy
1. https://render.com pe sign up karo (GitHub se login karo)
2. **New +** → **Web Service**
3. Apna GitHub repo select karo: `soar-sentinel`
4. Settings bharo:
   - **Name:** soar-sentinel
   - **Region:** Singapore (aapke paas) ya koi bhi
   - **Runtime:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `bash render-start.sh`
   - **Instance Type:** Free
5. **Environment Variables** add karo (Advanced section mein):
   - `SECRET_KEY` = koi bhi lamba random string (jaise: mysecretkey12345xyz)
   - `PYTHON_VERSION` = 3.11.0
6. **Create Web Service** dabao
7. 2-3 minute mein app live ho jaayegi → Render aapko ek URL dega:
   `https://soar-sentinel.onrender.com`

### Step 3 — Pehli baar admin banana (Render shell mein)
Render free pe shell nahi milti easily. Isliye app khud first-run pe 
admin bana legi (agar koi user na ho). Default:
- username: `admin`
- password: `Admin12345!demo`
(isse deploy ke baad turant badal lena — Admin page se naya user banao)

⚠️ Render free plan: 15 minute idle rehne ke baad app "so jaata hai". 
Pehli request pe 30-50 second laga sakta hai jaagne mein. Normal hai.

===========================================================================
## 🟠 TARIKA 2: VERCEL (mushkil, data save nahi hota — behtar hai Render use karo)
===========================================================================
⚠️ Vercel serverless hai — SQLite file save nahi hoti, isliye har request pe 
data reset ho sakta hai. Isliye Vercel sirf "UI dikhane" ke liye theek hai, 
kaam karne ke liye NAHI.

Agar phir bhi karna hai:
1. GitHub pe code push karo (upar wale steps)
2. https://vercel.com pe sign up (GitHub se)
3. **Add New** → **Project** → apna repo import karo
4. Framework Preset: **Other**
5. Build Command: (khaali chhodo)
6. Output Directory: (khaali chhodo)
7. **Environment Variables:**
   - `SECRET_KEY` = koi random string
8. **Deploy** dabao
9. Vercel aapko URL dega: `https://soar-sentinel.vercel.app`

(vercel.json + api/index.py maine already bana diye hain — ye kaam karega.)

===========================================================================
## 🔑 IMPORTANT — Deployment se pehle ye badlav
===========================================================================
1. `SECRET_KEY` set karo (Render/Vercel dono mein env variable se)
   - bina iske har restart pe sessions/CSRF tootega
2. Default admin password turant badlo (live hone ke baad)
3. `debug=True` already OFF hai (app.py mein) — theek hai

===========================================================================
## ❓ Aksar aane wali problem
===========================================================================
- "Application error" → Logs dekho (Render dashboard → Logs tab)
- 500 error → SECRET_KEY set kiya ki nahi check karo
- Static/CSS nahi dikh raha → render-start.sh mein `--collect-static`? 
  (nahi, Flask static apne aap serve karta hai; bas path sahi hona chahiye)

===========================================================================
## 💡 Agar aage badhana ho (production-grade)
===========================================================================
- Database ko **PostgreSQL** pe le jao (Render free PostgreSQL deta hai)
  taaki data permanently save rahe (SQLite free host pe reset hota rehta hai)
- Uske liye `psycopg` install + DATABASE_URL env se connect karna padega

**Short answer: abhi ke liye Render use karo, sabse aasan hai.**