#!/usr/bin/env python3
"""
Secret Key Generator for Flask Applications
Includes SECRET_KEY and CSRF_SECRET_KEY generation
"""

import secrets
import sys
import argparse
import os
import re
from datetime import datetime

def generate_secret_key(length=32):
    """
    Generate a secure random secret key
    
    Args:
        length (int): Length of the key in bytes (default: 32)
    
    Returns:
        str: Hexadecimal secret key
    """
    if length < 16:
        print("⚠️  Warning: Secret key should be at least 16 bytes for security")
    
    return secrets.token_hex(length)

def generate_csrf_key(length=32):
    """
    Generate a secure random CSRF secret key
    
    Args:
        length (int): Length of the key in bytes (default: 32)
    
    Returns:
        str: Hexadecimal CSRF secret key
    """
    if length < 16:
        print("⚠️  Warning: CSRF key should be at least 16 bytes for security")
    
    return secrets.token_hex(length)

def update_env_file(secret_key, csrf_key, env_file='.env'):
    """
    Update or create .env file with the secret keys
    
    Args:
        secret_key (str): The generated secret key
        csrf_key (str): The generated CSRF secret key
        env_file (str): Path to the .env file
    """
    try:
        # Read existing .env file if it exists
        lines = []
        try:
            with open(env_file, 'r') as f:
                lines = f.readlines()
        except FileNotFoundError:
            print(f"📁 Creating new {env_file} file")
        
        # Track which keys we need to add/update
        keys_to_update = {
            'SECRET_KEY': secret_key,
            'WTF_CSRF_SECRET_KEY': csrf_key
        }
        
        updated_lines = []
        updated_keys = set()
        
        for line in lines:
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                updated_lines.append(line)
                continue
            
            # Check if line contains any of our keys
            key_updated = False
            for key in keys_to_update.keys():
                if line.startswith(f'{key}='):
                    updated_lines.append(f'{key}={keys_to_update[key]}\n')
                    updated_keys.add(key)
                    key_updated = True
                    break
            
            if not key_updated:
                updated_lines.append(line)
        
        # Add any missing keys
        for key, value in keys_to_update.items():
            if key not in updated_keys:
                updated_lines.append(f'{key}={value}\n')
        
        # Add header comment if creating new file or if no comment exists
        if not lines or not any(line.strip().startswith('# Flask Secret Keys') for line in lines):
            header = [
                '\n',
                '# Flask Secret Keys\n',
                '# Generated on ' + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + '\n',
                '# Keep these keys secret and never commit them to version control!\n',
                '\n'
            ]
            # Insert header before the first key if found, or at the end
            inserted = False
            for i, line in enumerate(updated_lines):
                if any(key in line for key in keys_to_update.keys()):
                    for j, header_line in enumerate(reversed(header)):
                        updated_lines.insert(i, header_line)
                    inserted = True
                    break
            
            if not inserted:
                updated_lines.extend(header)
        
        # Write back to file
        with open(env_file, 'w') as f:
            f.writelines(updated_lines)
        
        print(f"✅ Secret keys successfully written to {env_file}")
        return True
        
    except Exception as e:
        print(f"❌ Error updating {env_file}: {e}")
        return False

def validate_env_file(env_file='.env'):
    """
    Validate that .env file contains required keys
    
    Args:
        env_file (str): Path to the .env file
    """
    try:
        if not os.path.exists(env_file):
            print(f"❌ {env_file} not found")
            return False
        
        with open(env_file, 'r') as f:
            content = f.read()
        
        required_keys = ['SECRET_KEY', 'WTF_CSRF_SECRET_KEY']
        missing_keys = []
        
        for key in required_keys:
            if not re.search(rf'^{key}=', content, re.MULTILINE):
                missing_keys.append(key)
        
        if missing_keys:
            print(f"❌ Missing keys in {env_file}: {', '.join(missing_keys)}")
            return False
        
        print(f"✅ {env_file} contains all required keys")
        return True
        
    except Exception as e:
        print(f"❌ Error validating {env_file}: {e}")
        return False

def show_current_keys(env_file='.env'):
    """
    Show current keys from .env file
    
    Args:
        env_file (str): Path to the .env file
    """
    try:
        if not os.path.exists(env_file):
            print(f"❌ {env_file} not found")
            return
        
        with open(env_file, 'r') as f:
            content = f.read()
        
        print(f"\n📄 Current keys in {env_file}:")
        print("-" * 50)
        
        for line in content.split('\n'):
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                if key in ['SECRET_KEY', 'WTF_CSRF_SECRET_KEY']:
                    # Show first 10 and last 10 characters for security
                    if len(value) > 20:
                        masked = f"{value[:10]}...{value[-10:]}"
                    else:
                        masked = "[TOO SHORT - REGENERATE]"
                    print(f"{key}: {masked}")
        
        print("-" * 50)
        
    except Exception as e:
        print(f"❌ Error reading {env_file}: {e}")

def main():
    parser = argparse.ArgumentParser(
        description='Generate secure Flask secret keys (SECRET_KEY and CSRF_SECRET_KEY)'
    )
    parser.add_argument('--length', type=int, default=32,
                       help='Length of the secret keys in bytes (default: 32)')
    parser.add_argument('--csrf-length', type=int, default=32,
                       help='Length of the CSRF key in bytes (default: 32)')
    parser.add_argument('--update-env', action='store_true',
                       help='Automatically update .env file with the generated keys')
    parser.add_argument('--env-file', default='.env',
                       help='Path to .env file (default: .env)')
    parser.add_argument('--validate', action='store_true',
                       help='Validate existing .env file')
    parser.add_argument('--show', action='store_true',
                       help='Show current keys from .env file')
    parser.add_argument('--force', action='store_true',
                       help='Force regeneration even if keys exist')
    
    args = parser.parse_args()
    
    # Show current keys if requested
    if args.show:
        show_current_keys(args.env_file)
        return
    
    # Validate existing file if requested
    if args.validate:
        validate_env_file(args.env_file)
        return
    
    # Generate keys
    print("\n" + "="*60)
    print("🔐 FLASK SECRET KEY GENERATOR")
    print("="*60)
    
    secret_key = generate_secret_key(args.length)
    csrf_key = generate_csrf_key(args.csrf_length)
    
    print(f"Secret Key length: {args.length} bytes ({args.length * 2} hex characters)")
    print(f"CSRF Key length: {args.csrf_length} bytes ({args.csrf_length * 2} hex characters)")
    print("-" * 60)
    print(f"SECRET_KEY: {secret_key}")
    print(f"WTF_CSRF_SECRET_KEY: {csrf_key}")
    print("="*60)
    
    # Show usage examples
    print("\n📋 Usage in your Flask app config.py:")
    print("# Load from environment variables")
    print("SECRET_KEY = os.environ.get('SECRET_KEY')")
    print("WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY')")
    
    print("\n📋 Or in your .env file:")
    print(f"SECRET_KEY={secret_key}")
    print(f"WTF_CSRF_SECRET_KEY={csrf_key}")
    
    # Update .env file if requested
    if args.update_env:
        if os.path.exists(args.env_file) and not args.force:
            print(f"\n⚠️  {args.env_file} already exists.")
            response = input("Overwrite existing keys? (yes/no): ")
            if response.lower() not in ['yes', 'y']:
                print("Operation cancelled.")
                return
        
        update_env_file(secret_key, csrf_key, args.env_file)
    
    print("\n⚠️  IMPORTANT SECURITY NOTES:")
    print("• Keep these keys secret and never commit them to version control")
    print("• Add .env to your .gitignore file")
    print("• Use different keys for development and production environments")
    print("• Store keys in environment variables, not in source code")
    print("• Regenerate keys if you suspect they've been compromised")
    print("• Minimum recommended key length: 32 bytes (64 hex characters)")
    
    print("\n✅ Configuration tips for config.py:")
    print("""
# In your config.py:
import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-change-in-production'
    WTF_CSRF_SECRET_KEY = os.environ.get('WTF_CSRF_SECRET_KEY') or SECRET_KEY
    
    # Production should require environment variables
    @classmethod
    def validate_production(cls):
        if not cls.SECRET_KEY or cls.SECRET_KEY == 'dev-key-change-in-production':
            raise ValueError("SECRET_KEY must be set in production!")
    """)

if __name__ == "__main__":
    main()