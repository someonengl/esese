from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time, random, os

app = FastAPI()

# ✅ Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
async def root():
    return {"message": "Backend is running"}

# Storage
DATA_FILE = "data.txt"
user_passwords = {}
user_memo = {}

# ✅ Load data safely
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        for line in f:
            parts = line.strip().split()
            if not parts:
                continue
            if parts[0] == "U" and len(parts) == 3:
                user_passwords[parts[1]] = parts[2]
            elif parts[0] == "M" and len(parts) == 4:
                user_memo.setdefault(parts[1], {})[parts[2]] = parts[3]

def crypt(s: str) -> str:
    seed = time.time() + random.random()
    res = 0
    for c in s:
        res = ord(c) + (res << 4) + (res << 10) - res + (ord(c) ^ res) + int(seed)
    return str(res)

def save_data():
    with open(DATA_FILE, "w") as f:
        for u, p in user_passwords.items():
            f.write(f"U {u} {p}\n")
        for u, memos in user_memo.items():
            for k, v in memos.items():
                f.write(f"M {u} {k} {v}\n")

class UserInput(BaseModel):
    action: str
    username: str
    password: str = ""
    key: str = ""
    value: str = ""

@app.post("/")
async def handle(req: UserInput):
    u = req.username.strip()
    p = req.password.strip()
    k = req.key.strip()
    v = req.value.strip()

    if req.action == "register":
        if not u or not p:
            return {"success": False, "message": "Username and password are required."}
        if u in user_passwords:
            return {"success": False, "message": f"User '{u}' already exists."}
        user_passwords[u] = p
        user_memo[u] = {}
        save_data()
        return {"success": True, "message": f"User '{u}' registered successfully."}

    if req.action == "login":
        if user_passwords.get(u) == p:
            return {"success": True, "message": f"Welcome, {u}!"}
        return {"success": False, "message": "Incorrect username or password."}

    if req.action == "save":
        if k in user_memo.get(u, {}):
            return {"success": False, "message": f"The key '{k}' already exists."}
        h = crypt(k)
        user_memo.setdefault(u, {})[k] = h
        user_memo[u][h] = k
        save_data()
        return {"success": True, "message": f"Key '{k}' saved."}

    if req.action == "renew":
        if k not in user_memo.get(u, {}):
            return {"success": False, "message": f"Key '{k}' not found."}
        h = crypt(k)
        user_memo[u][k] = h
        user_memo[u][h] = k
        save_data()
        return {"success": True, "message": f"Key '{k}' renewed."}

    if req.action == "give":
        val = user_memo.get(u, {}).get(v)
        if val:
            return {"success": True, "result": val}
        return {"success": False, "message": f"No value found for key '{v}'."}

    return {"success": False, "message": "Unknown action."}
