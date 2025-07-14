from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import asyncio, hashlib, os, time, random

app = FastAPI()

# --- Enable CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Data storage ---
DATA_FILE = "data.txt"
user_passwords: dict[str, str] = {}
user_memo: dict[str, dict[str, str]] = {}
file_lock = asyncio.Lock()

# --- Hash function (replaces broken 'crypt') ---
def sha(s: str) -> str:
    return hashlib.md5(s.encode()).hexdigest()

# --- Load data on startup ---
if os.path.exists(DATA_FILE):
    with open(DATA_FILE) as f:
        for raw in f:
            parts = raw.rstrip("\n").split(" ", 3)
            if parts and parts[0] == "U" and len(parts) == 3:
                user_passwords[parts[1]] = parts[2]
            elif parts and parts[0] == "M" and len(parts) == 4:
                user_memo.setdefault(parts[1], {})[parts[2]] = parts[3]

# --- Safe append to file ---
async def append(line: str):
    async with file_lock:
        with open(DATA_FILE, "a") as f:
            f.write(line)

# --- Request schema ---
class UserInput(BaseModel):
    action: str
    username: str
    password: str = ""
    key: str = ""
    value: str = ""

# --- Require valid login ---
def must_login(u: str, p: str):
    if user_passwords.get(u) != p:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

# --- Main API handler ---
@app.post("/")
async def handle(req: UserInput):
    u, p, k, v = req.username.strip(), req.password.strip(), req.key.strip(), req.value.strip()

    if req.action == "register":
        if not u or not p:
            return {"success": False, "message": "Username and password are required."}
        if u in user_passwords:
            return {"success": False, "exists": True, "message": f"User '{u}' already exists."}
        user_passwords[u] = p
        user_memo[u] = {}
        await append(f"U {u} {p}\n")
        return {"success": True, "message": f"User '{u}' registered successfully."}

    must_login(u, p)

    if req.action == "login":
        return {"success": True, "message": f"Welcome, {u}!"}

    if req.action == "save":
        if k in user_memo.get(u, {}):
            return {"success": False, "message": f"The key '{k}' already exists."}
        h = sha(k)
        user_memo.setdefault(u, {})[k] = h
        user_memo[u][h] = k
        await append(f"M {u} {k} {h}\nM {u} {h} {k}\n")
        return {"success": True, "message": f"Key '{k}' saved."}

    if req.action == "renew":
        if k not in user_memo.get(u, {}):
            return {"success": False, "message": f"Key '{k}' not found."}
        h = sha(k + str(time.time()) + str(random.random()))
        user_memo[u][k] = h
        user_memo[u][h] = k
        await append(f"M {u} {k} {h}\nM {u} {h} {k}\n")
        return {"success": True, "message": f"Key '{k}' renewed."}

    if req.action == "give":
        val = user_memo.get(u, {}).get(v)
        if val:
            return {"success": True, "result": val}
        return {"success": False, "message": f"No value found for key '{v}'."}

    return {"success": False, "message": "Unknown action."}

# --- Root route ---
@app.get("/")
async def root():
    return {"message": "Backend is running"}

# --- ✅ Heartbeat to keep app alive ---
@app.on_event("startup")
async def keep_alive():
    async def heartbeat():
        while True:
            await asyncio.sleep(45)
            print("[Heartbeat] App is still running.")
    asyncio.create_task(heartbeat())
