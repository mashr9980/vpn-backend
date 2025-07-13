#!/usr/bin/env python3

import sys
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine
from models import User
from auth.password import hash_password
from config import settings

def create_admin_user(username="admin", email="admin@vpn.com", password="admin123"):
    try:
        engine = create_engine(settings.DATABASE_URL)
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
        db = SessionLocal()
        
        existing_user = db.query(User).filter(User.username == username).first()
        if existing_user:
            if existing_user.is_admin:
                print(f"✅ Admin user '{username}' already exists")
                db.close()
                return True
            else:
                existing_user.is_admin = True
                db.commit()
                print(f"✅ User '{username}' upgraded to admin")
                db.close()
                return True
        
        admin_user = User(
            username=username,
            email=email,
            hashed_password=hash_password(password),
            is_admin=True,
            is_active=True
        )
        
        db.add(admin_user)
        db.commit()
        db.close()
        
        print(f"✅ Admin user created successfully!")
        print(f"   Username: {username}")
        print(f"   Email: {email}")
        print(f"   Password: {password}")
        print(f"   Role: Admin")
        print(f"\n⚠️  Please change the password after first login!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating admin user: {e}")
        return False

def create_custom_admin():
    print("=== Create Custom Admin User ===")
    
    username = input("Enter admin username (default: admin): ").strip() or "admin"
    email = input("Enter admin email (default: admin@vpn.local): ").strip() or "admin@vpn.local"
    
    password = input("Enter admin password (default: admin123): ").strip()
    if not password:
        password = "admin123"
        print("Using default password: admin123")
    
    confirm_password = input("Confirm password: ").strip()
    if password != confirm_password:
        print("❌ Passwords don't match!")
        return False
    
    return create_admin_user(username, email, password)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        if sys.argv[1] == "--custom":
            success = create_custom_admin()
        elif sys.argv[1] == "--default":
            success = create_admin_user()
        else:
            print("Usage: python create_admin.py [--default|--custom]")
            print("  --default: Create admin with default credentials")
            print("  --custom:  Create admin with custom credentials")
            sys.exit(1)
    else:
        success = create_admin_user()
    
    if success:
        print("\n🎉 Admin user setup completed!")
    else:
        print("\n❌ Admin user creation failed!")
        sys.exit(1)