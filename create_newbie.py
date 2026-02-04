from sqlmodel import Session
from app.models import User, engine, UserRole
from app.auth import hash_password

def create_newbie():
    with Session(engine) as session:
        # Check if already exists
        existing = session.query(User).filter(User.username == "newbie").first()
        if existing:
            print("User 'newbie' already exists.")
            return

        user = User(
            username="newbie",
            password_hash=hash_password("password"),
            role=UserRole.DEVELOPER,
            mfa_secret=None,  # Intentionally None to trigger setup flow
            public_key_path=None
        )
        session.add(user)
        session.commit()
        print("✅ Created user 'newbie' (password: 'password') with NO MFA secret.")

if __name__ == "__main__":
    create_newbie()
