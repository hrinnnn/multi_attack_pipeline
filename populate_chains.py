#!/usr/bin/env python3
"""
填充 chains 表：从现有 graph_edges 中提取所有 Attack→Func→Risk 路径
"""
import sqlite3
import json

DB_PATH = 'intelligence_v2.db'

def generate_chain_id(attack_id, func_id, risk_id):
    """生成唯一的 chain ID"""
    # 简化：取各ID的前20个字符拼接
    a = attack_id[:20] if len(attack_id) > 20 else attack_id
    f = func_id[:15] if len(func_id) > 15 else func_id
    r = risk_id[:15] if len(risk_id) > 15 else risk_id
    return f"chain_{a}_{f}_{r}"

def populate_chains():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 查找所有 existing chains (同一 source_ref 内的完整链)
    cursor.execute('''
        SELECT DISTINCT 
            e1.source as attack,
            e1.target as func,
            e2.target as risk,
            GROUP_CONCAT(DISTINCT e1.source_ref) as source_refs
        FROM edge_evidence e1
        JOIN edge_evidence e2 ON e1.source_ref = e2.source_ref 
            AND e1.target = e2.source
        WHERE e1.relation = 'utilizes' AND e2.relation = 'exposes'
        GROUP BY e1.source, e1.target, e2.target
    ''')
    existing_chains = cursor.fetchall()
    
    # 查找所有可能的 chains (包括 discovered)
    cursor.execute('''
        SELECT DISTINCT 
            e1.source as attack,
            e1.target as func,
            e2.target as risk
        FROM graph_edges e1
        JOIN graph_edges e2 ON e1.target = e2.source
        WHERE e1.relation = 'utilizes' AND e2.relation = 'exposes'
    ''')
    all_chains = cursor.fetchall()
    
    # 构建 existing_set 用于快速查找
    existing_set = set((a, f, r) for a, f, r, _ in existing_chains)
    existing_map = {(a, f, r): refs for a, f, r, refs in existing_chains}
    
    # 插入所有 chains
    inserted_count = 0
    for attack, func, risk in all_chains:
        chain_id = generate_chain_id(attack, func, risk)
        is_existing = (attack, func, risk) in existing_set
        source_type = 'existing' if is_existing else 'discovered'
        source_refs = existing_map.get((attack, func, risk), None)
        
        try:
            cursor.execute('''
                INSERT OR IGNORE INTO chains 
                (id, attack_id, func_id, risk_id, source_type, source_refs)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (chain_id, attack, func, risk, source_type, source_refs))
            if cursor.rowcount > 0:
                inserted_count += 1
        except Exception as e:
            print(f"跳过 {chain_id}: {e}")
    
    conn.commit()
    
    # 统计结果
    cursor.execute("SELECT source_type, COUNT(*) FROM chains GROUP BY source_type")
    stats = cursor.fetchall()
    
    conn.close()
    
    print(f"✓ 成功插入 {inserted_count} 条 chains")
    print("\n统计：")
    for source_type, count in stats:
        print(f"  - {source_type}: {count} 条")

if __name__ == '__main__':
    populate_chains()
