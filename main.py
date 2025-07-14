from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time, random, os, asyncio

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
user_passwords: dict[str, str] = {}              # username -> password
user_memo: dict[str, dict[str, str]] = {}        # username -> {key: value}

# --- Load everything on startup ---
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        for raw in f:
            parts = raw.rstrip("\n").split(" ", 3)
            if not parts:
                continue
            tag = parts[0]
            if tag == "U" and len(parts) == 3:
                user_passwords[parts[1]] = parts[2]
            elif tag == "M" and len(parts) == 4:
                user_memo.setdefault(parts[1], {})[parts[2]] = parts[3]

# --- Append helper ---
def record(line: str) -> None:
    with open(DATA_FILE, "a") as f:
        f.write(line)

# --- Simple pseudo-hash ---
def crypt(s: str) -> str:
    seed = time.time() + random.random()
    res = 0
    for c in s:
        res = ord(c) + (res << 4) + (res << 10) - res + (ord(c) ^ res) + int(seed)
    return str(res)

# --- Heartbeat to keep app alive ---
@app.on_event("startup")
async def keep_alive():
    async def heartbeat():
        while True:
            await asyncio.sleep(45)
            _ = os.path.exists(DATA_FILE)  # Do something trivial
            print("[Heartbeat] App is still running.")
    asyncio.create_task(heartbeat())

# --- Root route ---
@app.get("/")
async def root():
    return {"message": "Backend is running"}

# --- Request schema ---
class UserInput(BaseModel):
    action: str
    username: str
    password: str = ""
    key: str = ""
    value: str = ""

# --- Main POST handler ---
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
        record(f"U {u} {p}\n")
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
        record(f"M {u} {k} {h}\n")
        record(f"M {u} {h} {k}\n")
        return {"success": True, "message": f"Key '{k}' saved."}

    if req.action == "renew":
        if k not in user_memo.get(u, {}):
            return {"success": False, "message": f"Key '{k}' not found."}
        h = crypt(k)
        user_memo[u][k] = h
        user_memo[u][h] = k
        record(f"M {u} {k} {h}\n")
        record(f"M {u} {h} {k}\n")
        return {"success": True, "message": f"Key '{k}' renewed."}

    if req.action == "give":
        val = user_memo.get(u, {}).get(v)
        if val:
            return {"success": True, "result": val}
        return {"success": False, "message": f"No value found for key '{v}'."}

    return {"success": False, "message": "Unknown action."}
