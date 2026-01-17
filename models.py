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



class Post(db.Model):
    __tablename__ = "post"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    images = db.Column(db.JSON, default=[])  # Array of image URLs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    category_id = db.Column(db.Integer, db.ForeignKey("category.id"))

    user = db.relationship("User", back_populates="posts")
    category = db.relationship("Category", back_populates="posts")

    comments = db.relationship(
        "Comment", back_populates="post", cascade="all, delete-orphan"
    )
    reactions = db.relationship(
        "Reaction", back_populates="post", cascade="all, delete-orphan"
    )
    admin_responses = db.relationship(
        "AdminResponse", back_populates="post", cascade="all, delete-orphan"
    )



class Comment(db.Model):
    __tablename__ = "comment"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(200), nullable=False)
    images = db.Column(db.JSON, default=[])  # Array of image URLs
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"))

    user = db.relationship("User", back_populates="comments")
    post = db.relationship("Post", back_populates="comments")


class Reaction(db.Model):
    __tablename__ = "reaction"

    id = db.Column(db.Integer, primary_key=True)
    reaction_type = db.Column(db.String(10), nullable=False)  # like | dislike
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    post_id = db.Column(db.Integer, db.ForeignKey("post.id"))

    user = db.relationship("User", back_populates="reactions")
    post = db.relationship("Post", back_populates="reactions")

    __table_args__ = (
        db.UniqueConstraint("user_id", "post_id", name="unique_user_post_reaction"),
    )



class AdminResponse(db.Model):
    __tablename__ = "admin_response"

    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    post_id = db.Column(db.Integer, db.ForeignKey("post.id"))
    admin_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    post = db.relationship("Post", back_populates="admin_responses")
    admin = db.relationship("User", back_populates="admin_responses")



class SecurityReport(db.Model):
    __tablename__ = "security_report"

    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)  # theft, harassment, lights, other
    description = db.Column(db.String(500), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    user = db.relationship("User", backref="security_reports")



class EscortRequest(db.Model):
    __tablename__ = "escort_request"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(300), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default="active")  # active, fulfilled, expired
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    user = db.relationship("User", backref="escort_requests")


class ChatMessage(db.Model):
    __tablename__ = "chat_message"

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(300), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    security_report_id = db.Column(db.Integer, db.ForeignKey("security_report.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))

    security_report = db.relationship("SecurityReport", backref="chat_messages")
    user = db.relationship("User", backref="chat_messages")



class UniversitySettings(db.Model):
    __tablename__ = "university_settings"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), default="Campus University")
    latitude = db.Column(db.Float, default=-1.2921)  # Nairobi default
    longitude = db.Column(db.Float, default=36.8219)
    zoom_level = db.Column(db.Integer, default=15)
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


