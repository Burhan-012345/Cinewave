import sqlite3
import shutil
import os

DB_PATH = "instance/database.db"  # change path if your DB is elsewhere

def backup_database():
    backup_path = DB_PATH + ".backup"
    print(f"[+] Creating backup at: {backup_path}")
    shutil.copy(DB_PATH, backup_path)
    print("[✓] Backup created successfully.\n")

def column_exists(cursor, table, column):
    cursor.execute(f"PRAGMA table_info({table});")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns

def fix_profiles_table():
    print("[+] Connecting to SQLite database...")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("[+] Checking for corrupted 'continue_watching' column...")

    # Check if the column exists
    if not column_exists(cursor, "profiles", "continue_watching"):
        print("[✓] No corrupted column found. Your DB is already correct.")
        conn.close()
        return

    print("[!] Corrupted column found. Fixing database...")

    # 1. Create new correct table structure
    print("[+] Creating new profiles table (profiles_new)...")
    cursor.execute("""
        CREATE TABLE profiles_new (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            name VARCHAR(50) NOT NULL,
            avatar VARCHAR(100) DEFAULT 'default.png',
            is_default BOOLEAN DEFAULT 0,
            is_active BOOLEAN DEFAULT 1,
            is_child BOOLEAN DEFAULT 0,
            created_at DATETIME,
            updated_at DATETIME,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
    """)

    # 2. Copy clean data
    print("[+] Copying valid data into profiles_new...")
    cursor.execute("""
        INSERT INTO profiles_new (id, user_id, name, avatar, is_default, is_active, is_child, created_at, updated_at)
        SELECT id, user_id, name, avatar, is_default, is_active, is_child, created_at, updated_at
        FROM profiles;
    """)

    # 3. Drop the corrupted table
    print("[+] Dropping old corrupted profiles table...")
    cursor.execute("DROP TABLE profiles;")

    # 4. Rename the new table
    print("[+] Renaming profiles_new → profiles...")
    cursor.execute("ALTER TABLE profiles_new RENAME TO profiles;")

    conn.commit()
    conn.close()

    print("\n[✓] DATABASE FIXED SUCCESSFULLY!")
    print("[✓] The corrupted 'continue_watching' column is removed.")
    print("[✓] You can now restart your Flask server.\n")

def main():
    print("=== CineWave Database Fix Tool (SQLite) ===\n")

    if not os.path.exists(DB_PATH):
        print(f"[ERROR] Database file not found at path: {DB_PATH}")
        return
    
    backup_database()
    fix_profiles_table()

    print("=== DONE ===")

if __name__ == "__main__":
    main()
