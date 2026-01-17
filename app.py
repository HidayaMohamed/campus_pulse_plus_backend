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