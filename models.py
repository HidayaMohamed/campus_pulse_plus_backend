from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from config import db


class User(db.Model):
    __tablename__ = "user"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String, unique=True, nullable=False)
    password_hash = db.Column(db.String, nullable=False)
    role = db.Column(db.String, default="student")  # student | admin

    posts = db.relationship("Post", back_populates="user", cascade="all, delete-orphan")
    comments = db.relationship(
        "Comment", back_populates="user", cascade="all, delete-orphan"
    )
    reactions = db.relationship(
        "Reaction", back_populates="user", cascade="all, delete-orphan"
    )
    admin_responses = db.relationship(
        "AdminResponse", back_populates="admin", cascade="all, delete-orphan"
    )

    def set_password(self, pw):
        self.password_hash = generate_password_hash(pw)

    def check_password(self, pw):
        return check_password_hash(self.password_hash, pw)



class Category(db.Model):
    __tablename__ = "category"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String, nullable=False)
    description = db.Column(db.String)

    posts = db.relationship("Post", back_populates="category")



