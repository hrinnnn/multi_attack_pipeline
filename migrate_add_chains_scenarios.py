#!/usr/bin/env python3
"""
迁移脚本：添加 chains 和 scenarios 表到 intelligence_v2.db
"""
import sqlite3
from datetime import datetime

DB_PATH = 'intelligence_v2.db'

def migrate():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. 创建 chains 表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS chains (
            id TEXT PRIMARY KEY,
            attack_id TEXT NOT NULL,
            func_id TEXT NOT NULL,
            risk_id TEXT NOT NULL,
            source_type TEXT,
            source_refs TEXT,
            reproducibility_score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(attack_id, func_id, risk_id),
            FOREIGN KEY (attack_id) REFERENCES graph_nodes(id),
            FOREIGN KEY (func_id) REFERENCES graph_nodes(id),
            FOREIGN KEY (risk_id) REFERENCES graph_nodes(id)
        )
    ''')
    print("✓ chains 表已创建")
    
    # 2. 创建 scenarios 表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scenarios (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            description TEXT,
            steps_json TEXT NOT NULL,
            final_state TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    print("✓ scenarios 表已创建")
    
    conn.commit()
    conn.close()
    print(f"\n迁移完成！数据库: {DB_PATH}")

if __name__ == '__main__':
    migrate()
