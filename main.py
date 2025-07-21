from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import hashlib, random, time, asyncio

# -----------------------------------------------------------------
# FastAPI & CORS
# -----------------------------------------------------------------
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------------
# In-memory state (no persistence)
# ------------------------------------------------------------------
user_passwords: dict[str, str] = {}
user_memo: dict[str, dict[str, str]] = {}

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------
def sha(s: str) -> str:                 # deterministic hash
    return hashlib.md5(s.encode()).hexdigest()

def must_login(u: str, p: str) -> None:
    if user_passwords.get(u) != p:
        raise HTTPException(status_code=401,
                            detail="Incorrect username or password")

# ------------------------------------------------------------------
# Pydantic model
# ------------------------------------------------------------------
class UserInput(BaseModel):
    action: str
    username: str
    password: str = ""
    key: str = ""
    value: str = ""

# ------------------------------------------------------------------
# Main endpoint
# ------------------------------------------------------------------
@app.post("/")
async def handle(req: UserInput):
    u, p, k, v = (req.username.strip(),
                  req.password.strip(),
                  req.key.strip(),
                  req.value.strip())

    # 1️⃣ REGISTER ---------------------------------------------------
    if req.action == "register":
        if not u or not p:
            return {"success": False,
                    "message": "Username and password are required."}
        if u in user_passwords:
            return {"success": False, "exists": True,
                    "message": f"User '{u}' already exists."}
        user_passwords[u] = p
        user_memo[u] = {}
        return {"success": True,
                "message": f"User '{u}' registered successfully."}

    # 2️⃣ LOGIN (no auth-gate) --------------------------------------
    if req.action == "login":
        if user_passwords.get(u) == p:
            return {"success": True, "message": f"Welcome, {u}!"}
        return {"success": False,
                "message": "Incorrect username or password."}

    # All other actions require valid credentials
    must_login(u, p)

    # 3️⃣ SAVE -------------------------------------------------------
    if req.action == "save":
        if k in user_memo[u]:
            return {"success": False,
                    "message": f"The key '{k}' already exists."}
        h = sha(k)
        user_memo[u][k] = h
        user_memo[u][h] = k
        return {"success": True, "message": f"Key '{k}' saved."}

    # 4️⃣ RENEW ------------------------------------------------------
    if req.action == "renew":
        if k not in user_memo[u]:
            return {"success": False,
                    "message": f"Key '{k}' not found."}
        h = sha(k + str(time.time()) + str(random.random()))
        user_memo[u][k] = h
        user_memo[u][h] = k
        return {"success": True, "message": f"Key '{k}' renewed."}

    # 5️⃣ GIVE -------------------------------------------------------
    if req.action == "give":
        val = user_memo[u].get(v)
        if val:
            return {"success": True, "result": val}
        return {"success": False,
                "message": f"No value found for key '{v}'."}

    return {"success": False, "message": "Unknown action."}

# ------------------------------------------------------------------
# Root route
# ------------------------------------------------------------------
@app.get("/")
async def root():
    return {"message": "Backend is running"}

# ------------------------------------------------------------------
# Heartbeat (unchanged)
# ------------------------------------------------------------------
@app.on_event("startup")
async def keep_alive():
    async def heartbeat():
        while True:
            await asyncio.sleep(45)
            print("[Heartbeat] App is still running.")
    asyncio.create_task(heartbeat())
