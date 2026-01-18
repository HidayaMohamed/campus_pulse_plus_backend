
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
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=7)




# --- SESSION CONFIGURATION ---
app.config["SESSION_COOKIE_NAME"] = "campus_session"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_PATH"] = "/"

# Check if running on Render (Production)
if os.environ.get("PORT"):
    # Production: Must use Secure and SameSite=None for Vercel -> Render requests
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "None"
else:
    # Local development
    app.config["SESSION_COOKIE_SECURE"] = False
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# --- CORS CONFIGURATION ---
ALLOWED_ORIGINS = [
    "https://campuspulseplusfrontend-git-main-washiras-projects-fb5072e5.vercel.app",
    "https://campuspulseplusfrontend.vercel.app",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174"
]

CORS(
    app,
    supports_credentials=True,
    origins=os.getenv("CORS_ORIGINS", ",".join(ALLOWED_ORIGINS)).split(","),
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




@app.route("/")
def health_check():
    return {"status": "healthy", "message": "Campus Pulse Backend is running!"}, 200

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
    try:
        categories = Category.query.all()
        return jsonify(
            [{"id": c.id, "name": c.name, "description": c.description} for c in categories]
        )
    except Exception as e:
        app.logger.error(f"Database error in get_categories: {str(e)}")
        return {"error": "Database connection error. Please try again."}, 500






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






@app.route("/api/analytics/categories")
def category_chart():
   return jsonify(
       [
           {"name": c.name, "count": Post.query.filter_by(category_id=c.id).count()}
           for c in Category.query.all()
       ]
   )




@app.route("/api/analytics/votes")
def votes_chart():
   posts = Post.query.all()
   return jsonify(
       [
           {
               "title": p.content[:20] + ("..." if len(p.content) > 20 else ""),
               "likes": sum(1 for r in p.reactions if r.reaction_type == "like"),
               "dislikes": sum(1 for r in p.reactions if r.reaction_type == "dislike"),
           }
           for p in posts
       ]
   )




@app.route("/api/analytics")
def get_analytics():
   """Combined analytics endpoint for dashboard"""
   categories_data = [
       {"name": c.name, "count": Post.query.filter_by(category_id=c.id).count()}
       for c in Category.query.all()
   ]


   posts = Post.query.all()
   votes_data = [
       {
           "title": p.content[:20] + ("..." if len(p.content) > 20 else ""),
           "likes": sum(1 for r in p.reactions if r.reaction_type == "like"),
           "dislikes": sum(1 for r in p.reactions if r.reaction_type == "dislike"),
       }
       for p in posts
   ]


   return jsonify({
       "categories": categories_data,
       "posts": votes_data
   })




@app.route("/api/admin/stats")
@admin_required
def admin_stats():
   # Real user counts
   total_users = User.query.count()
   admin_users = User.query.filter_by(role="admin").count()
   student_users = User.query.filter_by(role="student").count()


   # Real post counts
   total_posts = Post.query.count()
   pending_posts = Post.query.filter(~Post.admin_responses.any()).count()
   responded_posts = total_posts - pending_posts


   # Real security reports
   total_security_reports = SecurityReport.query.count()
   active_security_reports = SecurityReport.query.filter(
       SecurityReport.created_at >= datetime.utcnow() - timedelta(hours=6)
   ).count()


   # Real escort requests
   total_escort_requests = EscortRequest.query.count()
   active_escort_requests = EscortRequest.query.filter(
       EscortRequest.created_at >= datetime.utcnow() - timedelta(minutes=30),
       EscortRequest.status == "active"
   ).count()


   # Real comments and reactions
   total_comments = Comment.query.count()
   total_reactions = Reaction.query.count()


   # Top category
   top_category_data = db.session.query(
       Category.name,
       db.func.count(Post.id).label('count')
   ).join(Post).group_by(Category.id, Category.name).order_by(
       db.func.count(Post.id).desc()
   ).first()


   top_category = top_category_data.name if top_category_data else "None"


   # Most liked post
   most_liked_post = db.session.query(
       Post.content,
       db.func.count(Reaction.id).label('likes')
   ).join(Reaction).filter(Reaction.reaction_type == "like").group_by(
       Post.id, Post.content
   ).order_by(db.func.count(Reaction.id).desc()).first()


   most_liked_content = most_liked_post.content[:30] + "..." if most_liked_post and len(most_liked_post.content) > 30 else (most_liked_post.content if most_liked_post else "No posts yet")


   # Recent activity (last 7 days)
   seven_days_ago = datetime.utcnow() - timedelta(days=7)
   recent_posts = Post.query.filter(Post.created_at >= seven_days_ago).count()
   recent_responses = AdminResponse.query.filter(AdminResponse.created_at >= seven_days_ago).count()
   recent_reports = SecurityReport.query.filter(SecurityReport.created_at >= seven_days_ago).count()


   return jsonify({
       "users": {
           "total": total_users,
           "admins": admin_users,
           "students": student_users
       },
       "posts": {
           "total": total_posts,
           "pending": pending_posts,
           "responded": responded_posts
       },
       "engagement": {
           "comments": total_comments,
           "reactions": total_reactions
       },
       "security": {
           "total_reports": total_security_reports,
           "active_reports": active_security_reports
       },
       "escort": {
           "total_requests": total_escort_requests,
           "active_requests": active_escort_requests
       },
       "trending": {
           "top_category": top_category,
           "most_liked_post": most_liked_content
       },
       "recent_activity": {
           "posts_week": recent_posts,
           "responses_week": recent_responses,
           "reports_week": recent_reports
       }
   })




@app.route("/api/admin/posts/detailed")
@admin_required
def get_detailed_posts():
   # Get all posts with full details for admin view
   posts = Post.query.order_by(Post.created_at.desc()).all()


   detailed_posts = []
   for post in posts:
       likes = sum(1 for r in post.reactions if r.reaction_type == "like")
       dislikes = sum(1 for r in post.reactions if r.reaction_type == "dislike")


       # Get user reaction if admin is logged in (though admin can't react)
       admin_reaction = None


       # Get admin response details
       admin_response = None
       response_date = None
       if post.admin_responses:
           admin_response = post.admin_responses[0].content
           response_date = post.admin_responses[0].created_at


       detailed_posts.append({
           "id": post.id,
           "content": post.content,
           "images": post.images,
           "category_id": post.category_id,
           "category_name": post.category.name,
           "user_id": post.user_id,
           "user_email": post.user.email if post.user else "Anonymous",
           "created_at": post.created_at,
           "likes": likes,
           "dislikes": dislikes,
           "total_reactions": likes + dislikes,
           "comments_count": len(post.comments),
           "admin_response": admin_response,
           "response_date": response_date,
           "has_response": bool(admin_response),
           "user_reaction": admin_reaction,
           "status": "responded" if admin_response else "pending"
       })


   return jsonify(detailed_posts)




@app.route("/api/admin/users", methods=["GET"])
@admin_required
def get_all_users():
   users = User.query.all()
   user_data = []


   for user in users:
       # Count user's posts, comments, reactions
       post_count = len(user.posts)
       comment_count = len(user.comments)
       reaction_count = len(user.reactions)


       # Get last activity (most recent post or comment)
       last_activity = None
       if user.posts:
           last_post = max(user.posts, key=lambda p: p.created_at)
           last_activity = last_post.created_at
       if user.comments and (not last_activity or max(user.comments, key=lambda c: c.created_at).created_at > last_activity):
           last_activity = max(user.comments, key=lambda c: c.created_at).created_at


       user_data.append({
           "id": user.id,
           "email": user.email,
           "role": user.role,
           "posts_count": post_count,
           "comments_count": comment_count,
           "reactions_count": reaction_count,
           "total_activity": post_count + comment_count + reaction_count,
           "last_activity": last_activity.isoformat() if last_activity else None,
           "joined_at": "2026-01-01T00:00:00Z"  # Placeholder since User model doesn't have created_at
       })


   return jsonify(user_data)




@app.route("/api/admin/users/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
   # Prevent admin from deleting themselves
   if user_id == session.get("user_id"):
       return {"error": "Cannot delete your own account"}, 400


   user = User.query.get_or_404(user_id)


   # Delete associated data (cascade will handle most relationships)
   # But we need to handle reactions manually since they can be null user_id
   Reaction.query.filter_by(user_id=user_id).delete()


   db.session.delete(user)
   db.session.commit()


   return {"message": f"User {user.email} deleted successfully"}




@app.route("/api/admin/streetwise-reports", methods=["GET"])
@admin_required
def get_streetwise_reports():
   # Get all security reports (both active and archived)
   security_reports = SecurityReport.query.order_by(SecurityReport.created_at.desc()).all()


   # Get all escort requests
   escort_requests = EscortRequest.query.order_by(EscortRequest.created_at.desc()).all()


   reports_data = []
   escort_data = []


   for report in security_reports:
       # Calculate age in hours
       age_hours = (datetime.utcnow() - report.created_at).total_seconds() / 3600


       reports_data.append({
           "id": report.id,
           "type": report.type,
           "description": report.description,
           "latitude": report.latitude,
           "longitude": report.longitude,
           "user_email": report.user.email if report.user else "Anonymous",
           "created_at": report.created_at.isoformat(),
           "age_hours": round(age_hours, 1),
           "is_active": age_hours <= 6,  # Active if less than 6 hours old
           "status": "active" if age_hours <= 6 else "archived"
       })


   for request in escort_requests:
       # Calculate age in minutes
       age_minutes = (datetime.utcnow() - request.created_at).total_seconds() / 60


       escort_data.append({
           "id": request.id,
           "message": request.message,
           "latitude": request.latitude,
           "longitude": request.longitude,
           "user_email": request.user.email,
           "status": request.status,
           "created_at": request.created_at.isoformat(),
           "age_minutes": round(age_minutes, 1),
           "is_active": request.status == "active" and age_minutes <= 30
       })


   return jsonify({
       "security_reports": reports_data,
       "escort_requests": escort_data,
       "summary": {
           "total_reports": len(reports_data),
           "active_reports": len([r for r in reports_data if r["is_active"]]),
           "total_requests": len(escort_data),
           "active_requests": len([r for r in escort_data if r["is_active"]])
       }
   })






@app.route("/api/security-reports", methods=["POST"])
@student_required
def create_security_report():
   data = request.get_json()
   report = SecurityReport(
       type=data["type"],
       description=data["description"],
       latitude=data["latitude"],
       longitude=data["longitude"],
       user_id=session.get("user_id"),
   )
   db.session.add(report)
   db.session.commit()
   return {"message": "Security report created"}, 201




@app.route("/api/security-reports", methods=["GET"])
@student_required
def get_security_reports():
   # Only return reports from last 6 hours with decay weights
   from datetime import datetime, timedelta


   six_hours_ago = datetime.utcnow() - timedelta(hours=6)


   reports = SecurityReport.query.filter(
       SecurityReport.created_at >= six_hours_ago
   ).all()


   # Calculate decay weight: 1.0 at 0 hours, 0.0 at 6 hours (removed from map)
   result = []
   for report in reports:
       age_hours = (datetime.utcnow() - report.created_at).total_seconds() / 3600
       # Linear decay: 1.0 at 0 hours, 0.0 at 6 hours
       decay_weight = max(0.0, 1.0 - (age_hours / 6))


       # Only include reports that haven't fully decayed (decay_weight > 0)
       if decay_weight > 0:
           result.append(
               {
                   "id": report.id,
                   "type": report.type,
                   "description": report.description,
                   "latitude": report.latitude,
                   "longitude": report.longitude,
                   "decay_weight": decay_weight,
                   "intensity": 0.8 if report.type in ["theft", "harassment"] else 0.5,
                   "age_hours": age_hours,
                   "created_at": report.created_at.isoformat(),
               }
           )


   return jsonify(result)




@app.route("/api/security-reports/archive", methods=["GET"])
def get_archived_security_reports():
   # Return reports older than 6 hours (archived/historical)
   from datetime import datetime, timedelta


   six_hours_ago = datetime.utcnow() - timedelta(hours=6)


   reports = SecurityReport.query.filter(
       SecurityReport.created_at <= six_hours_ago
   ).all()


   result = []
   for report in reports:
       age_hours = (datetime.utcnow() - report.created_at).total_seconds() / 3600
       result.append(
           {
               "id": report.id,
               "type": report.type,
               "latitude": report.latitude,
               "longitude": report.longitude,
               "description": report.description,
               "created_at": report.created_at.isoformat(),
               "age_hours": age_hours,
               "status": "archived",
           }
       )


   return jsonify(result)




@app.route("/api/escort-requests", methods=["POST"])
@student_required
def create_escort_request():
   data = request.get_json()
   user_id = session.get("user_id") 
   if not user_id:
       return {"error": "Not logged in"}, 401


   request_obj = EscortRequest(
       message=data["message"],
       latitude=data["latitude"],
       longitude=data["longitude"],
       user_id=user_id,
   )
   db.session.add(request_obj)
   db.session.commit()
   return {"message": "Escort request created"}, 201




@app.route("/api/escort-requests", methods=["GET"])
@student_required
def get_escort_requests():
   # Only return active requests from last 30 minutes
   from datetime import datetime, timedelta


   thirty_min_ago = datetime.utcnow() - timedelta(minutes=30)


   requests = EscortRequest.query.filter(
       EscortRequest.created_at >= thirty_min_ago, EscortRequest.status == "active"
   ).all()


   return jsonify(
       [
           {
               "id": r.id,
               "message": r.message,
               "latitude": r.latitude,
               "longitude": r.longitude,
               "created_at": r.created_at,
           }
           for r in requests
       ]
   )




#
@app.route("/api/security-reports/<int:report_id>/messages", methods=["GET"])
@student_required
def get_chat_messages(report_id):
   # Verify the report exists and is active (within 6 hours)
   from datetime import datetime, timedelta


   six_hours_ago = datetime.utcnow() - timedelta(hours=6)
   report = SecurityReport.query.filter(
       SecurityReport.id == report_id, SecurityReport.created_at >= six_hours_ago
   ).first_or_404()


   messages = (
       ChatMessage.query.filter_by(security_report_id=report_id)
       .order_by(ChatMessage.created_at)
       .all()
   )
   return jsonify(
       [
           {
               "id": msg.id,
               "message": msg.message,
               "user_id": msg.user_id,
               "created_at": msg.created_at.isoformat(),
           }
           for msg in messages
       ]
   )




@app.route("/api/security-reports/<int:report_id>/messages", methods=["POST"])
@student_required
def send_chat_message(report_id):
   # Verify the report exists and is active
   from datetime import datetime, timedelta


   six_hours_ago = datetime.utcnow() - timedelta(hours=6)
   report = SecurityReport.query.filter(
       SecurityReport.id == report_id, SecurityReport.created_at >= six_hours_ago
   ).first_or_404()


   data = request.get_json()
   if not data.get("message"):
       return {"error": "Message required"}, 400


   message = ChatMessage(
       message=data["message"],
       security_report_id=report_id,
       user_id=session["user_id"],
   )
   db.session.add(message)
   db.session.commit()
   return {"id": message.id}, 201






@app.route("/api/admin/categories", methods=["POST"])
@admin_required
def create_category():
   data = request.get_json()
   if not data.get("name"):
       return {"error": "Category name is required"}, 400


   # Check if category already exists
   existing = Category.query.filter_by(name=data["name"]).first()
   if existing:
       return {"error": "Category with this name already exists"}, 400


   category = Category(
       name=data["name"],
       description=data.get("description", "")
   )
   db.session.add(category)
   db.session.commit()
   return {
       "id": category.id,
       "name": category.name,
       "description": category.description
   }, 201




@app.route("/api/admin/categories/<int:id>", methods=["PUT"])
@admin_required
def update_category(id):
   category = Category.query.get_or_404(id)
   data = request.get_json()


   if not data.get("name"):
       return {"error": "Category name is required"}, 400


   # Check if another category with this name exists
   existing = Category.query.filter_by(name=data["name"]).first()
   if existing and existing.id != id:
       return {"error": "Category with this name already exists"}, 400


   category.name = data["name"]
   category.description = data.get("description", category.description)
   db.session.commit()


   return {
       "id": category.id,
       "name": category.name,
       "description": category.description
   }




@app.route("/api/admin/categories/<int:id>", methods=["DELETE"])
@admin_required
def delete_category(id):
   category = Category.query.get_or_404(id)


   # Check if category has posts
   if category.posts:
       return {"error": "Cannot delete category with existing posts"}, 400


   db.session.delete(category)
   db.session.commit()
   return {"message": "Category deleted successfully"}






@app.route("/api/admin/university-settings", methods=["GET"])
@admin_required
def get_university_settings():
   settings = UniversitySettings.query.first()
   if not settings:
       settings = UniversitySettings()
       db.session.add(settings)
       db.session.commit()
   return {
       "name": settings.name,
       "latitude": settings.latitude,
       "longitude": settings.longitude,
       "zoom_level": settings.zoom_level,
   }




@app.route("/api/admin/university-settings", methods=["PUT"])
@admin_required
def update_university_settings():
   data = request.get_json()
   settings = UniversitySettings.query.first()
   if not settings:
       settings = UniversitySettings()
       db.session.add(settings)


   settings.name = data.get("name", settings.name)
   settings.latitude = data.get("latitude", settings.latitude)
   settings.longitude = data.get("longitude", settings.longitude)
   settings.zoom_level = data.get("zoom_level", settings.zoom_level)


   db.session.commit()
   return {"message": "University settings updated"}, 200




@app.route("/api/university-settings", methods=["GET"])
def get_public_university_settings():
   settings = UniversitySettings.query.first()
   if not settings:
       settings = UniversitySettings()
       db.session.add(settings)
       db.session.commit()
   return {
       "name": settings.name,
       "latitude": settings.latitude,
       "longitude": settings.longitude,
       "zoom_level": settings.zoom_level,
   }






@app.route("/api/user/profile", methods=["GET"])
def get_user_profile():
   uid = session.get("user_id")
   if not uid:
       return {"error": "Not logged in"}, 401
   user = User.query.get(uid)
   return {
       "id": user.id,
       "email": user.email,
       "role": user.role,
   }




@app.route("/api/user/profile", methods=["PUT"])
def update_user_profile():
   uid = session.get("user_id")
   if not uid:
       return {"error": "Not logged in"}, 401


   data = request.get_json()
   user = User.query.get(uid)


   # Update email if provided and not taken
   if "email" in data:
       new_email = data["email"].strip()
       if not new_email:
           return {"error": "Email cannot be empty"}, 400
       if not is_valid_email(new_email):
           return {"error": "Invalid email format"}, 400
       existing = User.query.filter_by(email=new_email).first()
       if existing and existing.id != uid:
           return {"error": "Email already taken"}, 400
       user.email = new_email


   db.session.commit()
   return {
       "id": user.id,
       "email": user.email,
       "role": user.role,
   }




@app.route("/api/user/activity", methods=["GET"])
def get_user_activity():
   uid = session.get("user_id")
   if not uid:
       return {"error": "Not logged in"}, 401


   # Get user's posts
   posts = Post.query.filter_by(user_id=uid).order_by(Post.created_at.desc()).all()
   posts_data = []
   for p in posts:
       likes = sum(1 for r in p.reactions if r.reaction_type == "like")
       dislikes = sum(1 for r in p.reactions if r.reaction_type == "dislike")
       posts_data.append({
           "id": p.id,
           "content": p.content,
           "images": p.images,
           "category_name": p.category.name,
           "created_at": p.created_at,
           "likes": likes,
           "dislikes": dislikes,
           "comments_count": len(p.comments),
       })


   # Get user's comments
   comments = Comment.query.filter_by(user_id=uid).order_by(Comment.created_at.desc()).all()
   comments_data = [{
       "id": c.id,
       "content": c.content,
       "images": c.images,
       "post_id": c.post_id,
       "post_content": c.post.content[:50] + "..." if len(c.post.content) > 50 else c.post.content,
       "created_at": c.created_at,
   } for c in comments]


   # Get user's reactions
   reactions = Reaction.query.filter_by(user_id=uid).order_by(Reaction.created_at.desc()).all()
   reactions_data = [{
       "id": r.id,
       "reaction_type": r.reaction_type,
       "post_id": r.post_id,
       "post_content": r.post.content[:50] + "..." if len(r.post.content) > 50 else r.post.content,
       "created_at": r.created_at,
   } for r in reactions]


   # Get user's security reports
   security_reports = SecurityReport.query.filter_by(user_id=uid).order_by(SecurityReport.created_at.desc()).all()
   security_data = [{
       "id": r.id,
       "type": r.type,
       "description": r.description,
       "latitude": r.latitude,
       "longitude": r.longitude,
       "created_at": r.created_at,
   } for r in security_reports]


   # Get user's escort requests
   escort_requests = EscortRequest.query.filter_by(user_id=uid).order_by(EscortRequest.created_at.desc()).all()
   escort_data = [{
       "id": r.id,
       "message": r.message,
       "latitude": r.latitude,
       "longitude": r.longitude,
       "status": r.status,
       "created_at": r.created_at,
   } for r in escort_requests]


   return {
       "posts": posts_data,
       "comments": comments_data,
       "reactions": reactions_data,
       "security_reports": security_data,
       "escort_requests": escort_data,
   }






# Initialize database
try:
    with app.app_context():
        db.create_all()
        app.logger.info("Database initialized successfully")
except Exception as e:
    app.logger.error(f"Database initialization failed: {str(e)}")
    # Don't crash the app, just log the error

# Check if running in production (Render provides PORT env var)
if os.environ.get("PORT"):
    # Production deployment (Render)
    port = int(os.environ.get("PORT"))
    app.run(host="0.0.0.0", port=port, debug=False)
elif __name__ == "__main__":
    # Local development
    app.run(host="0.0.0.0", debug=True)
