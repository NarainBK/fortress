import enum
from datetime import datetime
from typing import Optional
from sqlmodel import SQLModel, Field, create_engine, Session

# --- Enums ---
class UserRole(str, enum.Enum):
    DEVELOPER = "developer"
    MANAGER = "manager"
    AUDITOR = "auditor"

class ArtifactStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

# --- Models ---
class User(SQLModel, table=True):
    """User model with role-based access."""
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    password_hash: str
    role: UserRole = Field(default=UserRole.DEVELOPER)
    mfa_secret: Optional[str] = None  # For MFA (Google Authenticator)
    public_key_path: Optional[str] = None  # Path to stored public key
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Artifact(SQLModel, table=True):
    """Artifact model for uploaded software packages."""
    id: Optional[int] = Field(default=None, primary_key=True)
    filename: str
    file_hash: str = Field(index=True)  # SHA-256 hash
    signature: str  # Base64 encoded signature
    storage_path: str  # Path to encrypted file
    uploader_id: int = Field(foreign_key="user.id")
    status: ArtifactStatus = Field(default=ArtifactStatus.PENDING)
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)
    approved_by: Optional[int] = Field(default=None, foreign_key="user.id")
    approved_at: Optional[datetime] = None

# --- Database Setup ---
DATABASE_URL = "sqlite:///./fortress.db"
engine = create_engine(DATABASE_URL, echo=False)

def init_db():
    """Initialize the database and create all tables."""
    SQLModel.metadata.create_all(engine)

def get_session():
    """Get a database session."""
    with Session(engine) as session:
        yield session
