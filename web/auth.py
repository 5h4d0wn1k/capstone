"""Authentication and authorization system."""

import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from loguru import logger
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from fastapi import HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

Base = declarative_base()

class User(Base):
    """User model for authentication."""
    
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password_hash = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime)
    
    def verify_password(self, password: str) -> bool:
        """Verify password against hash.
        
        Args:
            password: Password to verify
            
        Returns:
            True if password matches
        """
        return bcrypt.checkpw(
            password.encode('utf-8'),
            self.password_hash.encode('utf-8')
        )

class Role(Base):
    """Role model for authorization."""
    
    __tablename__ = "roles"
    
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)
    permissions = Column(String)  # JSON string of permissions
    
class AuthManager:
    """Authentication and authorization manager."""
    
    def __init__(self, config: Dict[str, Any], db_session: Session):
        """Initialize auth manager.
        
        Args:
            config: Auth configuration
            db_session: Database session
        """
        self.config = config
        self.db = db_session
        self.secret_key = config.get("secret_key", os.urandom(32).hex())
        self.token_expiry = config.get("token_expiry_hours", 24)
        self.security = HTTPBearer()
        
    def create_user(self, username: str, email: str, 
                   password: str, is_admin: bool = False) -> User:
        """Create new user.
        
        Args:
            username: Username
            email: Email address
            password: Plain text password
            is_admin: Whether user is admin
            
        Returns:
            Created user
            
        Raises:
            ValueError: If username or email exists
        """
        # Check if user exists
        if self.db.query(User).filter(
            (User.username == username) | (User.email == email)
        ).first():
            raise ValueError("Username or email already exists")
            
        # Hash password
        password_hash = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt()
        ).decode('utf-8')
        
        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=password_hash,
            is_admin=is_admin
        )
        
        self.db.add(user)
        self.db.commit()
        
        return user
        
    def authenticate(self, username: str, password: str) -> Optional[str]:
        """Authenticate user and return token.
        
        Args:
            username: Username
            password: Password
            
        Returns:
            JWT token if authenticated, None otherwise
        """
        # Get user
        user = self.db.query(User).filter(User.username == username).first()
        if not user or not user.verify_password(password):
            return None
            
        # Update last login
        user.last_login = datetime.utcnow()
        self.db.commit()
        
        # Generate token
        payload = {
            "sub": user.username,
            "admin": user.is_admin,
            "exp": datetime.utcnow() + timedelta(hours=self.token_expiry)
        }
        
        return jwt.encode(payload, self.secret_key, algorithm="HS256")
        
    async def verify_token(self, 
                          credentials: HTTPAuthorizationCredentials = Security(HTTPBearer())
                          ) -> Dict[str, Any]:
        """Verify JWT token.
        
        Args:
            credentials: HTTP bearer credentials
            
        Returns:
            Token payload
            
        Raises:
            HTTPException: If token invalid
        """
        try:
            payload = jwt.decode(
                credentials.credentials,
                self.secret_key,
                algorithms=["HS256"]
            )
            
            # Check if user still exists and is active
            user = self.db.query(User).filter(
                User.username == payload["sub"]
            ).first()
            
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=401,
                    detail="User inactive or deleted"
                )
                
            return payload
            
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=401,
                detail="Token expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=401,
                detail="Invalid token"
            )
            
    def require_admin(self, payload: Dict[str, Any]) -> None:
        """Check if user is admin.
        
        Args:
            payload: Token payload
            
        Raises:
            HTTPException: If user not admin
        """
        if not payload.get("admin", False):
            raise HTTPException(
                status_code=403,
                detail="Admin access required"
            )
            
    def create_role(self, name: str, description: str, 
                   permissions: List[str]) -> Role:
        """Create new role.
        
        Args:
            name: Role name
            description: Role description
            permissions: List of permission strings
            
        Returns:
            Created role
            
        Raises:
            ValueError: If role exists
        """
        # Check if role exists
        if self.db.query(Role).filter(Role.name == name).first():
            raise ValueError(f"Role {name} already exists")
            
        # Create role
        role = Role(
            name=name,
            description=description,
            permissions=",".join(permissions)
        )
        
        self.db.add(role)
        self.db.commit()
        
        return role
        
    def get_user_permissions(self, username: str) -> List[str]:
        """Get user's permissions.
        
        Args:
            username: Username
            
        Returns:
            List of permission strings
        """
        user = self.db.query(User).filter(User.username == username).first()
        if not user:
            return []
            
        # Admins have all permissions
        if user.is_admin:
            return ["*"]
            
        # Get user's roles and combine permissions
        permissions = set()
        # This would need a user_roles table in a real implementation
        
        return list(permissions)
