# VS Code mein kaise chalayein — SOAR Sentinel

## Sabse aasaan tarika (1 click) ▶️
1. VS Code mein is project ko khola hua hai (ho jaata hai).
2. Left side mein **Run and Debug** icon dabao (▶️ bug wala icon) — ya `Ctrl + Shift + D`.
3. Upar dropdown se choose karo: **"Run + Open Browser"**.
4. Green **▶ Start Debugging** button dabao (ya bas `F5`).
5. Browser apne aap khul jaayega → `http://127.0.0.1:5000/login`.
6. Login: username `admin`, password `Admin12345!demo`.

> Browser apne aap nahi khula? Manually kholo: **http://localhost:5000**

## Doosra tarika (Terminal se) 💻
1. VS Code mein terminal kholo: `Ctrl + `` (backtick key).
2. Ye command chalao:
   ```
   python app.py
   ```
3. Jab `Running on http://127.0.0.1:5000` dikhe, browser mein **http://localhost:5000** kholo.

## Band kaise karein? 🛑
- Terminal mein jahan chal raha hai wahan `Ctrl + C` dabao.
- Ya VS Code ka red **Stop** (■) button dabao (debug mode mein).

## Agar "Address already in use" error aaye 😟
Matlab port 5000 pehle se busy hai. Fix:
1. Terminal band karke naya kholo, ya
2. Task Manager khol ke `python.exe` end karo, ya
3. Naya terminal khol ke `SOAR_PORT=5001 python app.py` chalo, ya
4. App ko auto-retry karne ke liye `python app.py` dobara try karo — yeh next free port par chal jayega.

## Python select karna (agar red lines dikhein) ⚙️
1. `Ctrl + Shift + P` → type karo `Python: Select Interpreter`.
2. Choose karo: `Python 3.15` (jo `.vscode/settings.json` mein already set hai).

## Demo account
- Username: `admin`
- Password: `Admin12345!demo`

## Nayi shuruaat (fresh database chahiye toh)
```
flask --app app create-admin      # naya admin banao (password poochega)
flask --app app seed-demo         # sample data daalo
```
