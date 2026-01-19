# Campus Pulse Plus Backend

A comprehensive Flask-based backend API for campus safety, engagement, and communication platform.

## Group members: 
Hidaya - https://github.com/HidayaMohamed,
Adonis - https://github.com/donnyMP8, 
Victor - https://github.com/wachira567,
Khalid - https://github.com/KHALIDIIN12, 
Mark bryan - https://github.com/MarkB-make
Bradley - https://github.com/brimiq

## Frontend repository
This is the URL for the frontend repo: https://github.com/HidayaMohamed/campus_pulse_plus_frontend

## Features

### Authentication System
- User signup and login with secure password hashing
- Session-based authentication with role management
- Role-based access control (Student/Admin)

### Posts & Comments
- Create, view, and delete posts
- Category-based filtering
- Anonymous commenting support
- Like/dislike reactions system

### Categories & Filtering
- Predefined categories for content organization
- Admin-managed category creation and management
- Category-based post filtering

### Campus Safety Features
- **Security Reports**: Report incidents (theft, harassment, lighting issues, etc.)
- **Escort Requests**: Request campus security escort
- **Real-time Map Display**: Reports shown with decay-based visibility
- **Chat System**: Anonymous chat with security for active reports

### Admin Dashboard
- View all users with activity metrics
- Manage posts and respond to student concerns
- Analytics: category distribution, engagement metrics
- University settings management (map center, zoom level)

### Analytics
- Category-wise post distribution
- Engagement metrics (likes, comments)
- User activity tracking
- Security report statistics

## Tech Stack

- **Backend**: Flask (Python)
- **Database**: SQLAlchemy ORM
- **Database Engine**: SQLite (default) / PostgreSQL configurable
- **Authentication**: Session-based with werkzeug security
- **CORS**: Flask-CORS with credentials support
- **Rate Limiting**: Flask-Limiter
- **Environment**: python-dotenv

## Project Structure

```
campus_pulse_plus_backend2/
├── app.py              # Main Flask application with all routes
├── models.py           # SQLAlchemy models for all entities
├── config.py           # Database configuration
├── seed.py             # Database seeding script
├── Pipfile             # Python dependencies
├── .env                # Environment variables (create from .env.example)
├── .gitignore
└── README.md
```

## Getting Started

### Prerequisites

- Python 3.8+
- pip or pipenv

### Installation

1. **Clone the repository**
   ```bash
   git clone git@github.com:brimiq/campus_pulse_plus_backend2.git
   cd campus_pulse_plus_backend2
   ```

2. **Install dependencies**
   ```bash
   pip install pipenv
   pipenv install
   ```

3. **Set up environment variables**
   ```bash
   cp .env.example .env  # Create .env from example
   # Edit .env with your configuration
   ```

4. **Initialize the database**
   ```bash
   pipenv run python
   >>> from app import app, db
   >>> with app.app_context():
   ...     db.create_all()
   >>> exit()
   ```

5. **Run the server**
   ```bash
   pipenv run python app.py
   ```

The server will start at `http://localhost:5000`

## API Endpoints

### Authentication
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/auth/signup` | POST | Register new user | Public |
| `/auth/login` | POST | Login user | Public |
| `/auth/logout` | POST | Logout user | Public |
| `/auth/current_user` | GET | Get current user | Public |

### Categories
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/categories` | GET | Get all categories | Public |
| `/api/admin/categories` | POST | Create category | Admin |
| `/api/admin/categories/<id>` | PUT | Update category | Admin |
| `/api/admin/categories/<id>` | DELETE | Delete category | Admin |

### Posts
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/posts` | GET | Get posts (with optional category filter) | Public |
| `/api/posts` | POST | Create new post | Student |
| `/api/posts/<id>` | GET | Get single post | Public |
| `/api/posts/<id>` | DELETE | Delete post | Owner |

### Comments
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/comments` | POST | Add comment | Student |
| `/api/comments/<post_id>` | GET | Get comments for post | Public |
| `/api/comments/<id>` | DELETE | Delete comment | Owner |

### Reactions
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/reactions` | POST | Add/remove reaction | Student |

### Security Features
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/security-reports` | POST | Create security report | Student |
| `/api/security-reports` | GET | Get active reports (6h decay) | Student |
| `/api/security-reports/<id>/messages` | GET/POST | Chat messages | Student |
| `/api/escort-requests` | POST | Create escort request | Student |
| `/api/escort-requests` | GET | Get active requests | Student |

### Admin Only
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/responses` | POST | Respond to post |
| `/api/admin/posts/pending` | GET | Get pending posts |
| `/api/admin/posts/detailed` | GET | Get detailed posts list |
| `/api/admin/users` | GET | Get all users |
| `/api/admin/users/<id>` | DELETE | Delete user |
| `/api/admin/stats` | GET | Dashboard statistics |
| `/api/admin/streetwise-reports` | GET | Get security reports |
| `/api/admin/university-settings` | GET/PUT | Manage settings |

### Analytics
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/analytics/categories` | GET | Category distribution |
| `/api/analytics/votes` | GET | Post votes data |
| `/api/analytics` | GET | Combined analytics |

### User
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/user/profile` | GET/PUT | Manage profile | User |
| `/api/user/activity` | GET | Get user activity | User |

### University Settings
| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/api/university-settings` | GET | Public settings | Public |
| `/api/admin/university-settings` | GET/PUT | Admin settings | Admin |

## Request/Response Examples

### Create User (Signup)
```json
POST /auth/signup
{
  "email": "student@university.edu",
  "password": "securepassword123"
}
```

### Login Response
```json
{
  "user": {
    "id": 1,
    "email": "student@university.edu",
    "role": "student"
  }
}
```

### Create Post
```json
POST /api/posts
{
  "content": "The library study rooms need better lighting",
  "category_id": 1,
  "image": "https://example.com/image.jpg"
}
```

### Create Security Report
```json
POST /api/security-reports
{
  "type": "lighting",
  "description": "Dark pathway between buildings A and B",
  "latitude": -1.2921,
  "longitude": 36.8219
}
```

### Categories Response
```json
GET /api/categories
[
  {
    "id": 1,
    "name": "Campus Facilities",
    "description": "Issues or praise about campus facilities"
  },
  {
    "id": 2,
    "name": "Academic",
    "description": "Academic-related discussions"
  }
]
```



## Live Demo

- Frontend: https://your-frontend-url.vercel.app
- Backend API: https://your-backend-url.onrender.com


##  Test Credentials

Use the following accounts to test the application:

### Admin User
- Email: admin@campus.com
- Password: admin123

### Regular User
- Email: student1@campus.com
- Password: password1

## License

This project is part of the Campus Pulse Plus initiative.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Support

For support, please contact the development team or open an issue.

---

Built with love for campus safety and student engagement

