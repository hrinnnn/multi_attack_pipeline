import sqlite3

DB_PATH = 'intelligence_v2.db'

def migrate_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    print("Migrating chains table to add AI evaluation fields...")
    
    # List of new columns to add
    new_columns = [
        ("reproducibility_level", "TEXT"),
        ("evaluation_reason", "TEXT"),
        ("implementation_guide", "TEXT")
    ]
    
    for col_name, col_type in new_columns:
        try:
            cursor.execute(f"ALTER TABLE chains ADD COLUMN {col_name} {col_type}")
            print(f"  + Added column: {col_name}")
        except sqlite3.OperationalError as e:
            if "duplicate column name" in str(e):
                print(f"  = Column already exists: {col_name}")
            else:
                print(f"  ! Error adding {col_name}: {e}")
                
    conn.commit()
    conn.close()
    print("Migration complete.")

if __name__ == "__main__":
    migrate_db()
