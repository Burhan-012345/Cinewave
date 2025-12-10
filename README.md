# CineWave - Movie Streaming & Download Platform

CineWave is a Flask-based movie streaming and download platform that allows users to browse, stream, and download movies with features like user profiles, watchlists, and analytics.

## 🌟 Features

### User Features

- **User Authentication**: Registration with email verification, login, password reset
- **Profiles**: Multiple user profiles per account with parental controls
- **Watchlist**: Save movies to watch later
- **Continue Watching**: Resume playback from where you left off
- **Movie Streaming**: Stream movies directly in browser
- **Movie Downloads**: Download movies with secure tokens and limits
- **Reviews & Ratings**: Rate and review movies
- **Search & Filters**: Search movies with genre and year filters

### Admin Features

- **Movie Management**: Add, edit, and delete movies
- **File Upload**: Upload movie files, posters, and trailers
- **Bulk Actions**: Bulk delete, feature, enable/disable downloads
- **Analytics Dashboard**: View platform statistics and user activity
- **User Management**: Manage users and their data

### Technical Features

- **Secure Authentication**: Password hashing, OTP verification, CSRF protection
- **File Handling**: Secure file uploads with size and type validation
- **Database**: SQLAlchemy ORM with PostgreSQL/MySQL/SQLite support
- **Email Integration**: Send OTPs, password reset links, notifications
- **OAuth Support**: Google OAuth integration
- **Error Handling**: Custom error pages (404, 500, 403, 413)
- **Responsive Design**: Mobile-friendly templates

## 📋 Prerequisites

- Python 3.8 or higher
- PostgreSQL/MySQL/SQLite
- Git
- Virtual environment (recommended)

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd cinewave
```
