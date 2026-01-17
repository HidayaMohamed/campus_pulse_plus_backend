from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from functools import wraps
from datetime import timedelta, datetime
import re
import os
import logging
from dotenv import load_dotenv
from sqlalchemy import func, case


load_dotenv()


from config import db
from models import (
   User,
   Post,
   Comment,
   Reaction,
   Category,
   AdminResponse,
   SecurityReport,
   EscortRequest,
   UniversitySettings,
   ChatMessage,
)
app = Flask(__name__)




logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)




limiter = Limiter(
   get_remote_address,
   app=app,
   default_limits=["1000 per day", "200 per hour"],
   storage_uri="memory://",
)




app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URI", "sqlite:///app.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "your_secret_key")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)




app.config["SESSION_COOKIE_NAME"] = "campus_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = False 
app.config["SESSION_COOKIE_SAMESITE"] = "Lax" 
app.config["SESSION_COOKIE_DOMAIN"] = None 
app.config["SESSION_COOKIE_PATH"] = "/"

CORS(
   app,
   supports_credentials=True,
   origins=os.getenv(
       "CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173,http://localhost:5174,http://127.0.0.1:5174,http://localhost:5175,http://127.0.0.1:5175,http://localhost:5176,http://127.0.0.1:5176,http://localhost:5177,http://127.0.0.1:5177"
   ).split(","),
   methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
   allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

db.init_app(app)




@app.before_request
def make_session_permanent():
   session.permanent = True




#
def student_required(f):
   @wraps(f)
   def wrapper(*args, **kwargs):
       app.logger.info(
           f"Student check: session role = {session.get('role')}, user_id = {session.get('user_id')}"
       )
       if session.get("role") != "student":
           app.logger.warning(
               f"Access denied: role {session.get('role')} is not student"
           )
           return {"error": "Only students allowed"}, 403
       return f(*args, **kwargs)


   return wrapper

def admin_required(f):
   @wraps(f)
   def wrapper(*args, **kwargs):
       if session.get("role") != "admin":
           return {"error": "Only admins allowed"}, 403
       return f(*args, **kwargs)


   return wrapper






def is_valid_email(email):
   return re.match(r"[^@]+@[^@]+\.[^@]+", email)




@app.route("/auth/signup", methods=["POST"])
@limiter.limit("5 per minute")
def signup():
   app.logger.info(f"Signup attempt from {request.remote_addr}")
   try:
       data = request.get_json()
       if not data:
           return {"error": "Invalid JSON"}, 400


       email = data.get("email", "").strip()
       password = data.get("password", "").strip()
       if not email or not password:
           return {"error": "Email and password required"}, 400
       if not is_valid_email(email):
           return {"error": "Invalid email format"}, 400
       if len(password) < 4:
           return {"error": "Password too short"}, 400
       if User.query.filter_by(email=email).first():
           return {"error": "Email already registered"}, 400


       user = User(email=email)
       user.set_password(password)
       db.session.add(user)
       db.session.commit()


       session["user_id"] = user.id
       session["role"] = user.role
       app.logger.info(f"User {email} signed up successfully")
       return {"user": {"id": user.id, "email": user.email, "role": user.role}}, 201
   except Exception as e:
       db.session.rollback()
       app.logger.error(f"Signup error: {str(e)}")
       return {"error": "Internal server error"}, 500
@app.route("/auth/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
   app.logger.info(f"Login attempt from {request.remote_addr}")
   data = request.get_json()
   user = User.query.filter_by(email=data.get("email")).first()
   if user and user.check_password(data.get("password")):
       session["user_id"] = user.id
       session["role"] = user.role
       app.logger.info(f"User {user.email} logged in")
       return {"user": {"id": user.id, "email": user.email, "role": user.role}}, 200
   app.logger.warning(f"Failed login attempt for {data.get('email')}")
   return {"error": "Invalid credentials"}, 401




@app.route("/auth/logout", methods=["POST"])
def logout():
   session.clear()
   return {"message": "Logged out"}, 200




@app.route("/auth/current_user", methods=["GET"])
def current_user():
   uid = session.get("user_id")
   if not uid:
       return jsonify(None)
   user = User.query.get(uid)
   return {"id": user.id, "email": user.email, "role": user.role}
@app.route("/api/debug-session")
def debug_session():
   return {
       "session_user_id": session.get("user_id"),
       "session_role": session.get("role"),
       "all_session_keys": list(session.keys()),
       "is_logged_in": "user_id" in session,
   }






@app.route("/api/categories", methods=["GET"])
def get_categories():
   categories = Category.query.all()
   return jsonify(
       [{"id": c.id, "name": c.name, "description": c.description} for c in categories]
   )






@app.route("/api/posts", methods=["GET"])
def get_posts():
   try:
       category_id = request.args.get("category_id", type=int)
       query = Post.query.order_by(Post.created_at.desc())
       if category_id:
           query = query.filter_by(category_id=category_id)


       posts = query.limit(10).all()
       data = []
       for p in posts:
           likes = sum(1 for r in p.reactions if r.reaction_type == "like")
           dislikes = sum(1 for r in p.reactions if r.reaction_type == "dislike")
           admin_response = p.admin_responses[0].content if p.admin_responses else None
           data.append(
               {
                   "id": p.id,
                   "content": p.content,
                   "images": p.images,
                   "category_id": p.category_id,
                   "category_name": p.category.name,
                   "user_id": p.user_id,
                   "created_at": p.created_at,
                   "likes": likes,
                   "dislikes": dislikes,
                   "comments_count": len(p.comments),
                   "admin_response": admin_response,
               }
           )
       return jsonify(data)
   except Exception as e:
       return {"error": "Internal server error"}, 500
   
@app.route("/api/posts/<int:id>", methods=["GET"])
def get_post(id):
   post = Post.query.get_or_404(id)
   likes = sum(1 for r in post.reactions if r.reaction_type == "like")
   dislikes = sum(1 for r in post.reactions if r.reaction_type == "dislike")
   user_reaction = None
   if session.get("user_id"):
       r = Reaction.query.filter_by(post_id=id, user_id=session["user_id"]).first()
       if r:
           user_reaction = r.reaction_type
   return {
       "id": post.id,
       "content": post.content,
       "images": post.images,
       "category_id": post.category_id,
       "user_id": post.user_id,
       "created_at": post.created_at,
       "likes": likes,
       "dislikes": dislikes,
       "user_reaction": user_reaction,
       "comments": [
           {
               "id": c.id,
               "content": c.content,
               "images": c.images,
               "user_id": c.user_id,
               "created_at": c.created_at,
           }
           for c in post.comments
       ],
       "admin_response": post.admin_responses[0].content
       if post.admin_responses
       else None,
   }
@app.route("/api/posts", methods=["POST"])
def create_post():
   data = request.get_json()
   if not data.get("content"):
       return {"error": "Content required"}, 400
   image = data.get("image")
   post = Post(
       content=data["content"],
       images=[image] if image else [],
       user_id=session["user_id"],
       category_id=data.get("category_id", 1),
   )
   db.session.add(post)
   db.session.commit()
   return {"id": post.id}, 201
@app.route("/api/posts/<int:id>", methods=["DELETE"])
def delete_post(id):
   user_id = session.get("user_id")
   if not user_id:
       return {"error": "Unauthorized"}, 401
   post = Post.query.get_or_404(id)
   if post.user_id != user_id:
       return {"error": "You can only delete your own posts"}, 403
   db.session.delete(post)
   db.session.commit()
   return {"message": "Post deleted successfully"}, 200






@app.route("/api/comments", methods=["POST"])
def add_comment():
   data = request.get_json()
   image = data.get("image")
   comment = Comment(
       content=data["content"],
       images=[image] if image else [],
       post_id=data["post_id"],
       user_id=session.get("user_id"),  # None if anonymous
   )
   db.session.add(comment)
   db.session.commit()
   return {"id": comment.id}, 201




@app.route("/api/comments/<int:id>", methods=["DELETE"])
def delete_comment(id):
   comment = Comment.query.get_or_404(id)
   if session.get("user_id") != comment.user_id:
       return {"error": "Unauthorized"}, 403
   db.session.delete(comment)
   db.session.commit()
   return {"message": "Comment deleted"}, 200




@app.route("/api/comments/<int:post_id>", methods=["GET"])
def get_comments(post_id):
   comments = (
       Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at).all()
   )
   return jsonify(
       [
           {
               "id": c.id,
               "content": c.content,
               "images": c.images,
               "user_id": c.user_id,
               "created_at": c.created_at,
           }
           for c in comments
       ]
   )




@app.route("/api/reactions", methods=["POST"])
def add_reaction():
   app.logger.info(f"Reaction attempt: session user_id = {session.get('user_id')}")
   data = request.get_json()
   post_id = data["post_id"]
   reaction_type = data["reaction_type"]
   user_id = session.get("user_id")
   if not user_id:
       app.logger.warning("No user_id in session for reaction")
       return {"error": "Not logged in"}, 401
   existing = Reaction.query.filter_by(post_id=post_id, user_id=user_id).first()
   if existing:
       if existing.reaction_type == reaction_type:
           db.session.delete(existing)
           user_reaction = None
       else:
           existing.reaction_type = reaction_type
           user_reaction = reaction_type
   else:
       db.session.add(
           Reaction(post_id=post_id, user_id=user_id, reaction_type=reaction_type)
       )
       user_reaction = reaction_type
   db.session.commit()
   reactions = Reaction.query.filter_by(post_id=post_id).all()
   return {
       "likes": sum(1 for r in reactions if r.reaction_type == "like"),
       "dislikes": sum(1 for r in reactions if r.reaction_type == "dislike"),
       "user_reaction": user_reaction,
   }






@app.route("/api/admin/responses", methods=["POST"])
@admin_required
def respond_post():
   data = request.get_json()
   if not data.get("post_id"):
       return {"error": "Post ID is required"}, 400


   # Check if response already exists for this post
   existing = AdminResponse.query.filter_by(post_id=data["post_id"]).first()
   if existing:
       return {"error": "Response already exists for this post"}, 400


   response = AdminResponse(
       post_id=data["post_id"], admin_id=session["user_id"], content=data["content"]
   )
   db.session.add(response)
   db.session.commit()
   return {"message": "Admin response saved"}, 201




@app.route("/api/admin/posts/pending", methods=["GET"])
@admin_required
def pending_posts():
   posts = Post.query.all()
   return jsonify(
       [
           {"id": p.id, "content": p.content, "created_at": p.created_at}
           for p in posts
           if not p.admin_responses
       ]
   )


