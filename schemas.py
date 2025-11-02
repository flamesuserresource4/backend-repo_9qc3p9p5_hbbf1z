from typing import List, Optional
from pydantic import BaseModel, EmailStr, Field


class Resource(BaseModel):
    name: str
    url: str


class Timestamp(BaseModel):
    label: str
    time: int = Field(..., ge=0, description="Time in seconds")


class Module(BaseModel):
    id: Optional[str] = None
    title: str
    educator: str
    duration: str
    views: int = 0
    category: str
    videoUrl: str
    description: str
    resources: List[Resource] = []
    timestamps: List[Timestamp] = []


class Note(BaseModel):
    id: Optional[str] = None
    module_id: str
    user_id: str
    content: str = ""


# Auth models
class UserBase(BaseModel):
    name: str
    email: EmailStr


class UserCreate(UserBase):
    password: str


class UserPublic(UserBase):
    id: str


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
