import os
import re
import tempfile
import zipfile
from datetime import datetime, timedelta
from flask import current_app
from models import MovieDownload

def allowed_file(filename, allowed_extensions):
    """Check if the file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions

def generate_download_token(movie_id, user_id, serializer):
    """Generate a secure token for movie downloads"""
    data = {
        'movie_id': movie_id,
        'user_id': user_id,
        'timestamp': datetime.utcnow().isoformat()
    }
    return serializer.dumps(data, salt='movie-download-salt')

def verify_download_token(token, serializer):
    """Verify and decode download token"""
    try:
        data = serializer.loads(token, salt='movie-download-salt', max_age=3600)  # 1 hour expiry
        return data
    except Exception:
        return None

def check_download_limits(user_id):
    """Check if user has reached download limits"""
    from models import MovieDownload
    
    # Get today's downloads
    today = datetime.utcnow().date()
    today_start = datetime.combine(today, datetime.min.time())
    today_end = datetime.combine(today, datetime.max.time())
    
    today_downloads = MovieDownload.query.filter(
        MovieDownload.user_id == user_id,
        MovieDownload.created_at >= today_start,
        MovieDownload.created_at <= today_end,
        MovieDownload.status == 'completed'
    ).count()
    
    # Get weekly downloads
    week_ago = datetime.utcnow() - timedelta(days=7)
    weekly_downloads = MovieDownload.query.filter(
        MovieDownload.user_id == user_id,
        MovieDownload.created_at >= week_ago,
        MovieDownload.status == 'completed'
    ).count()
    
    # Check limits (configurable)
    max_daily = current_app.config.get('MAX_DOWNLOADS_PER_DAY', 10)
    max_weekly = current_app.config.get('MAX_DOWNLOADS_PER_WEEK', 50)
    
    if today_downloads >= max_daily:
        return {
            'allowed': False,
            'message': f'Daily download limit reached ({max_daily} downloads per day).',
            'today_downloads': today_downloads,
            'max_daily': max_daily
        }
    
    if weekly_downloads >= max_weekly:
        return {
            'allowed': False,
            'message': f'Weekly download limit reached ({max_weekly} downloads per week).',
            'weekly_downloads': weekly_downloads,
            'max_weekly': max_weekly
        }
    
    return {
        'allowed': True,
        'message': 'Download allowed.',
        'today_downloads': today_downloads,
        'weekly_downloads': weekly_downloads,
        'max_daily': max_daily,
        'max_weekly': max_weekly
    }

def create_placeholder_movie_file(movie):
    """Create a placeholder movie file for demo purposes"""
    import uuid
    
    # Create temporary directory if it doesn't exist
    temp_dir = os.path.join(current_app.instance_path, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    # Create a text file with movie info
    placeholder_content = f"""CineWave Movie Placeholder
================================
Title: {movie.title}
Release Year: {movie.release_year}
Duration: {movie.duration} minutes
Description: {movie.description}

This is a placeholder file for demonstration purposes.
In a production environment, this would be the actual movie file.

Downloaded from CineWave at {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
================================
Enjoy your movie! 🎬
"""
    
    # Create unique filename
    unique_id = uuid.uuid4().hex[:8]
    filename = f"cinewave_{movie.id}_{unique_id}.txt"
    filepath = os.path.join(temp_dir, filename)
    
    # Write content to file
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(placeholder_content)
    
    return filepath

def format_file_size(bytes):
    """Convert bytes to human-readable file size"""
    if bytes is None:
        return "N/A"
    
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes < 1024.0:
            return f"{bytes:.1f} {unit}"
        bytes /= 1024.0
    return f"{bytes:.1f} TB"

def cleanup_old_temp_files(hours=24):
    """Clean up temporary files older than specified hours"""
    temp_dir = os.path.join(current_app.instance_path, 'temp')
    if not os.path.exists(temp_dir):
        return
    
    cutoff_time = datetime.utcnow() - timedelta(hours=hours)
    
    for filename in os.listdir(temp_dir):
        filepath = os.path.join(temp_dir, filename)
        if os.path.isfile(filepath):
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            if file_time < cutoff_time:
                try:
                    os.remove(filepath)
                except Exception:
                    pass

def get_download_statistics(user_id):
    """Get download statistics for a user"""
    from models import MovieDownload
    
    stats = {
        'total_downloads': 0,
        'completed_downloads': 0,
        'failed_downloads': 0,
        'total_size': 0,
        'average_speed': 0,
        'recent_downloads': []
    }
    
    # Get all downloads for user
    downloads = MovieDownload.query.filter_by(user_id=user_id).all()
    
    if not downloads:
        return stats
    
    stats['total_downloads'] = len(downloads)
    stats['completed_downloads'] = len([d for d in downloads if d.status == 'completed'])
    stats['failed_downloads'] = len([d for d in downloads if d.status == 'failed'])
    
    # Calculate total size
    completed_downloads = [d for d in downloads if d.status == 'completed' and d.file_size]
    if completed_downloads:
        stats['total_size'] = sum(d.file_size for d in completed_downloads)
        
        # Calculate average speed
        speeds = []
        for download in completed_downloads:
            if download.started_at and download.completed_at and download.file_size:
                duration = (download.completed_at - download.started_at).total_seconds()
                if duration > 0:
                    speed = (download.file_size / (1024 * 1024)) / duration  # MB/s
                    speeds.append(speed)
        
        if speeds:
            stats['average_speed'] = sum(speeds) / len(speeds)
    
    # Get recent downloads (last 10)
    stats['recent_downloads'] = MovieDownload.query.filter_by(user_id=user_id)\
        .order_by(MovieDownload.created_at.desc())\
        .limit(10)\
        .all()
    
    return stats

def verify_movie_file_exists(movie):
    """Improved file lookup for movie files - PRIORITIZE ACTUAL VIDEO FILES"""

    if not movie.file_path:
        return False, "No file path in database"

    # Try the exact path first
    if os.path.exists(movie.file_path):
        # Check if it's actually a video file, not a text file
        if is_video_file(movie.file_path):
            return True, movie.file_path
        else:
            # It exists but might be a text placeholder
            return False, f"File exists but is not a valid video: {movie.file_path}"

    # Extract just the filename
    filename = os.path.basename(movie.file_path)
    
    # Define search directories in order of priority
    search_directories = []
    
    # 1. MOVIE_UPLOAD_FOLDER (most likely location for actual videos)
    if 'MOVIE_UPLOAD_FOLDER' in current_app.config:
        search_directories.append(current_app.config['MOVIE_UPLOAD_FOLDER'])
    
    # 2. Look in common upload directories
    search_directories.extend([
        os.path.join(current_app.instance_path, 'movie_files'),
        os.path.join(current_app.instance_path, 'uploads', 'movies'),
        os.path.join(current_app.root_path, 'static', 'uploads', 'movies'),
        os.path.join(current_app.root_path, 'uploads', 'movies'),
        os.path.join(current_app.instance_path, 'temp'),  # Check temp last
    ])

    # Check all directories for the file
    for directory in search_directories:
        if not os.path.exists(directory):
            continue
            
        # Look for exact filename match
        exact_path = os.path.join(directory, filename)
        if os.path.exists(exact_path):
            if is_video_file(exact_path):
                return True, exact_path
            else:
                continue  # Skip non-video files
        
        # Look for any file with movie ID in name (case-insensitive)
        for file in os.listdir(directory):
            if str(movie.id) in file and is_video_file(file):
                file_path = os.path.join(directory, file)
                return True, file_path
        
        # Look for files with similar name pattern
        for file in os.listdir(directory):
            # Try to match by sanitized movie title
            safe_title = re.sub(r'[^\w\s-]', '', movie.title.lower())
            safe_title = safe_title.replace(' ', '_')
            
            if safe_title in file.lower() and is_video_file(file):
                file_path = os.path.join(directory, file)
                return True, file_path

    return False, "No valid video file found in any expected location"


def is_video_file(filepath):
    """Check if a file is actually a video file (not text disguised as video)"""
    if not os.path.exists(filepath):
        return False
    
    # Check by extension first (fast)
    video_extensions = {'.mp4', '.mkv', '.avi', '.mov', '.wmv', '.flv', '.webm', '.m4v'}
    file_ext = os.path.splitext(filepath)[1].lower()
    if file_ext not in video_extensions:
        return False
    
    # Check file size - text files are usually small
    file_size = os.path.getsize(filepath)
    if file_size < 1024:  # Less than 1KB is definitely not a video
        return False
    
    # Check first few bytes for video signatures
    try:
        with open(filepath, 'rb') as f:
            first_bytes = f.read(100)
            
            # MP4 signature check
            mp4_signatures = [
                b'ftyp',  # MP4 signature
                b'moov',  # MP4 movie atom
                b'\x00\x00\x00\x18ftyp',  # MP4 with size prefix
                b'\x00\x00\x00\x1Cftyp',  # MP4 with size prefix
            ]
            
            # AVI signature check
            avi_signatures = [
                b'RIFF',  # AVI signature
            ]
            
            # MKV signature check
            mkv_signatures = [
                b'\x1A\x45\xDF\xA3',  # EBML header for MKV
            ]
            
            # Check for video signatures
            for sig in mp4_signatures + avi_signatures + mkv_signatures:
                if sig in first_bytes:
                    return True
            
            # Check if it's actually a text file (common problem)
            try:
                text_content = first_bytes.decode('utf-8', errors='ignore')
                if any(keyword in text_content.lower() for keyword in ['cinewave', 'placeholder', 'demo', 'text', 'this is']):
                    return False
            except:
                pass
            
            # If we got here and file is large, assume it's a video
            if file_size > 1024 * 1024:  # More than 1MB
                return True
                
    except Exception:
        pass
    
    return False

def create_video_placeholder(movie):
    """Create a proper video placeholder (not text file)"""
    import subprocess
    import uuid
    
    # Create temporary directory
    temp_dir = os.path.join(current_app.instance_path, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    # Create a simple video with ffmpeg
    unique_id = uuid.uuid4().hex[:8]
    output_file = os.path.join(temp_dir, f"placeholder_{movie.id}_{unique_id}.mp4")
    
    # Create a video with movie info
    try:
        # Use ffmpeg to create a simple video
        text = f"{movie.title}\\n{movie.release_year}"
        
        cmd = [
            'ffmpeg',
            '-f', 'lavfi',
            '-i', 'color=c=black:s=640x360:d=10',
            '-vf', f"drawtext=text='{text}':fontcolor=white:fontsize=24:x=(w-text_w)/2:y=(h-text_h)/2",
            '-c:a', 'aac',
            '-b:a', '128k',
            '-y',  # Overwrite output file
            output_file
        ]
        
        subprocess.run(cmd, capture_output=True, check=False)
        
        if os.path.exists(output_file):
            return output_file
        else:
            # Fallback: create a text file but with .mp4 extension
            return create_text_placeholder_with_mp4(movie)
            
    except Exception as e:
        current_app.logger.error(f"Failed to create video placeholder: {str(e)}")
        # Fallback to simple text file
        return create_text_placeholder_with_mp4(movie)

def create_text_placeholder_with_mp4(movie):
    """Create a text file but name it as .mp4"""
    import uuid
    
    temp_dir = os.path.join(current_app.instance_path, 'temp')
    os.makedirs(temp_dir, exist_ok=True)
    
    content = f"""This is a placeholder for: {movie.title}
In production, this would be the actual movie file.
    
To add actual movie files:
1. Go to /admin/movies
2. Find "{movie.title}"
3. Click "Upload/Replace File"
4. Upload an actual .mp4 or .mkv file
"""
    
    unique_id = uuid.uuid4().hex[:8]
    output_file = os.path.join(temp_dir, f"placeholder_{movie.id}_{unique_id}.mp4")
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    return output_file