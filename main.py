import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db
from schemas import Module, Note, Resource, Timestamp, Token, UserCreate, UserPublic

app = FastAPI(title="EduSolve API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Auth utils
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"
ACCESS_MIN = int(os.getenv("JWT_EXPIRES_MIN", "10080"))  # default 7d
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer(auto_error=False)


def to_str_id(doc):
    if not doc:
        return doc
    d = dict(doc)
    if d.get("_id") is not None:
        d["id"] = str(d.pop("_id"))
    return d


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_MIN))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security)) -> Optional[dict]:
    if creds is None:
        return None
    token = creds.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        uid: str = payload.get("sub")
        if uid is None:
            return None
        if db is None:
            return {"id": uid, "email": None, "name": None}
        doc = db.users.find_one({"_id": ObjectId(uid)})
        if not doc:
            return None
        return to_str_id(doc)
    except JWTError:
        return None


@app.on_event("startup")
def startup():
    # Seed minimal modules if DB available
    if db is None:
        return
    try:
        count = db.module.count_documents({})
        if count == 0:
            seed = [
                {
                    "title": "Calm Classroom: De-escalation Strategies for Challenging Moments",
                    "educator": "Dr. Maya Collins",
                    "duration": "12:47",
                    "views": 138200,
                    "category": "Classroom Management",
                    "videoUrl": "https://www.w3schools.com/html/mov_bbb.mp4",
                    "description": "Learn practical de-escalation steps for tense classroom situations. Build calm routines, language scripts, and follow-up strategies you can use tomorrow.",
                    "resources": [
                        {"name": "De-escalation One-Pager (PDF)", "url": "https://files.edusolve.dev/deescalation.pdf"},
                    ],
                    "timestamps": [
                        {"label": "What de-escalation is", "time": 30},
                        {"label": "Scripts you can use", "time": 210},
                        {"label": "Follow-up routines", "time": 530},
                    ],
                },
                {
                    "title": "Backward Design: Plan Assessments Before Activities",
                    "educator": "Alex Rivera",
                    "duration": "9:05",
                    "views": 85210,
                    "category": "Lesson Planning",
                    "videoUrl": "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.mp4",
                    "description": "Design units by defining success first. We walk through aligning objectives, assessments, and instruction with a quick template.",
                    "resources": [
                        {"name": "Unit Plan Template (Doc)", "url": "https://files.edusolve.dev/unit-plan-template.docx"},
                    ],
                    "timestamps": [
                        {"label": "Backward design overview", "time": 15},
                        {"label": "Creating evidence of learning", "time": 120},
                    ],
                },
            ]
            db.module.insert_many(seed)
        # Ensure email uniqueness index
        db.users.create_index("email", unique=True)
    except Exception:
        pass


class NotesUpsert(BaseModel):
    user_id: str
    content: str


class LoginPayload(BaseModel):
    email: EmailStr
    password: str


@app.get("/test")
def test():
    if db is None:
        return {"status": "error", "message": "Database not configured"}
    try:
        names = db.list_collection_names()
        return {"status": "ok", "collections": names}
    except Exception as e:
        return {"status": "error", "message": str(e)}


# Auth endpoints
@app.post("/auth/register", response_model=UserPublic)
def register(user: UserCreate):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    if db.users.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = pwd_context.hash(user.password)
    doc = {
        "name": user.name,
        "email": user.email,
        "password_hash": hashed,
        "created_at": datetime.now(timezone.utc),
    }
    res = db.users.insert_one(doc)
    return UserPublic(id=str(res.inserted_id), name=user.name, email=user.email)


@app.post("/auth/login", response_model=Token)
def login(payload: LoginPayload):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    user = db.users.find_one({"email": payload.email})
    if not user or not pwd_context.verify(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": str(user["_id"])})
    return Token(access_token=token)


@app.get("/auth/me", response_model=UserPublic)
def me(current=Depends(get_current_user)):
    if not current:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return UserPublic(id=current["id"], name=current.get("name", ""), email=current.get("email", ""))


# Modules
@app.get("/modules", response_model=List[Module])
def list_modules():
    if db is None:
        return []
    docs = [to_str_id(m) for m in db.module.find({}).sort("views", -1)]
    return docs


@app.get("/modules/{module_id}", response_model=Module)
def get_module(module_id: str):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    try:
        oid = ObjectId(module_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Module not found")
    doc = db.module.find_one({"_id": oid})
    if not doc:
        raise HTTPException(status_code=404, detail="Module not found")
    return to_str_id(doc)


@app.get("/modules/{module_id}/resources", response_model=List[Resource])
def get_resources(module_id: str):
    m = get_module(module_id)
    return m.get("resources", [])


@app.post("/modules/{module_id}/resources", response_model=List[Resource])
def add_resource(module_id: str, resource: Resource):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    try:
        oid = ObjectId(module_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Module not found")
    db.module.update_one({"_id": oid}, {"$push": {"resources": resource.model_dump()}})
    doc = db.module.find_one({"_id": oid})
    return to_str_id(doc).get("resources", [])


@app.get("/modules/{module_id}/timestamps", response_model=List[Timestamp])
def get_timestamps(module_id: str):
    m = get_module(module_id)
    return m.get("timestamps", [])


@app.post("/modules/{module_id}/timestamps", response_model=List[Timestamp])
def add_timestamp(module_id: str, ts: Timestamp):
    if db is None:
        raise HTTPException(status_code=503, detail="Database not available")
    try:
        oid = ObjectId(module_id)
    except Exception:
        raise HTTPException(status_code=404, detail="Module not found")
    db.module.update_one({"_id": oid}, {"$push": {"timestamps": ts.model_dump()}})
    doc = db.module.find_one({"_id": oid})
    return to_str_id(doc).get("timestamps", [])


# Notes: can use auth or user_id fallback
@app.get("/modules/{module_id}/notes", response_model=Note)
def get_note(module_id: str, user_id: Optional[str] = None, current=Depends(get_current_user)):
    uid = (current and current.get("id")) or user_id
    if not uid:
        raise HTTPException(status_code=400, detail="Missing user context")
    if db is None:
        return Note(id=None, module_id=module_id, user_id=uid, content="")
    doc = db.note.find_one({"module_id": module_id, "user_id": uid})
    if not doc:
        note = Note(module_id=module_id, user_id=uid, content="")
        res = db.note.insert_one({**note.model_dump()})
        note.id = str(res.inserted_id)
        return note
    d = to_str_id(doc)
    return Note(**d)


@app.post("/modules/{module_id}/notes", response_model=Note)
def upsert_note(module_id: str, payload: NotesUpsert, current=Depends(get_current_user)):
    uid = (current and current.get("id")) or payload.user_id
    if not uid:
        raise HTTPException(status_code=400, detail="Missing user context")
    if db is None:
        return Note(id=None, module_id=module_id, user_id=uid, content=payload.content)
    doc = db.note.find_one({"module_id": module_id, "user_id": uid})
    if doc:
        db.note.update_one({"_id": doc["_id"]}, {"$set": {"content": payload.content}})
        updated = db.note.find_one({"_id": doc["_id"]})
        d = to_str_id(updated)
        return Note(**d)
    else:
        note = Note(module_id=module_id, user_id=uid, content=payload.content)
        res = db.note.insert_one({**note.model_dump()})
        note.id = str(res.inserted_id)
        return note
