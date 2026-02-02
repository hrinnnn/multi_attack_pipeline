import sqlite3
import json
import textwrap
import os
from collections import defaultdict

# 路径配置
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, '../intelligence_v2.db')
OUTPUT_FILE = 'related_chains_report.txt'

def get_connection():
    return sqlite3.connect(DB_PATH, timeout=30)

def get_all_data():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. 加载所有节点
    cursor.execute("SELECT id, label, type, description, origin FROM graph_nodes")
    nodes = {row['id']: dict(row) for row in cursor.fetchall()}

    # 2. 加载边及其证据来源
    cursor.execute("SELECT source, target, relation FROM graph_edges")
    edges_raw = cursor.fetchall()

    cursor.execute("SELECT source, target, relation, source_ref FROM edge_evidence")
    evidence_rows = cursor.fetchall()
    
    edge_to_refs = defaultdict(set)
    for ev in evidence_rows:
        edge_to_refs[(ev['source'], ev['target'], ev['relation'])].add(ev['source_ref'])

    # 3. 加载已有链 (Existing Chains)
    cursor.execute("SELECT id, attack_id, func_id, risk_id FROM chains WHERE source_type = 'existing'")
    existing_chains = [dict(row) for row in cursor.fetchall()]

    conn.close()
    return nodes, edges_raw, edge_to_refs, existing_chains

def find_discovered_chains(nodes, edges_raw, edge_to_refs):
    atk_to_funcs = defaultdict(list)
    atk_to_risks = defaultdict(list)

    for edge in edges_raw:
        s, t, r = edge['source'], edge['target'], edge['relation']
        refs = edge_to_refs.get((s, t, r), set())
        if r == 'utilizes':
            atk_to_funcs[s].append((t, refs))
        elif r == 'causes':
            atk_to_risks[s].append((t, refs))

    discovered_chains = []
    for atk_id, funcs in atk_to_funcs.items():
        risks = atk_to_risks.get(atk_id, [])
        for f_id, atk_func_refs in funcs:
            for risk_id, atk_risk_refs in risks:
                atk_node = nodes.get(atk_id)
                func_node = nodes.get(f_id)
                risk_node = nodes.get(risk_id)
                if not (atk_node and func_node and risk_node): continue

                is_cross_source = not (atk_func_refs & atk_risk_refs)
                has_augmented = any(n['origin'] == 'augmented' for n in [atk_node, func_node, risk_node])

                if is_cross_source or has_augmented:
                    reason = []
                    if is_cross_source: reason.append("Cross-Source")
                    if has_augmented: reason.append("Augmented")
                    
                    discovered_chains.append({
                        "attack_id": atk_id,
                        "func_id": f_id,
                        "risk_id": risk_id,
                        "nodes": (atk_id, f_id, risk_id),
                        "reason": " | ".join(reason),
                        "atk_func_refs": list(atk_func_refs),
                        "atk_risk_refs": list(atk_risk_refs)
                    })
    return discovered_chains

def compare_and_report(nodes, existing, discovered):
    results = []
    for d in discovered:
        d_set = set(d['nodes'])
        for e in existing:
            e_nodes = (e['attack_id'], e['func_id'], e['risk_id'])
            e_set = set(e_nodes)
            
            # 找共同节点
            intersection = d_set & e_set
            if len(intersection) == 2:
                results.append((e, d, intersection))

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("=== Related Chains Report (Shared 2 Nodes) ===\n")
        f.write(f"Existing Chains: {len(existing)}\n")
        f.write(f"Discovered Chains: {len(discovered)}\n")
        f.write(f"Found Pairs: {len(results)}\n")
        f.write("="*80 + "\n\n")

        for i, (e, d, shared) in enumerate(results):
            f.write(f"Pair #{i+1}\n")
            f.write(f"Shared Nodes: {', '.join([nodes[nid]['label'] for nid in shared])}\n\n")
            
            f.write(f"--- Existing Chain [{e['id']}] ---\n")
            f.write(f"Attack: {nodes[e['attack_id']]['label']}\n")
            f.write(f"Func:   {nodes[e['func_id']]['label']}\n")
            f.write(f"Risk:   {nodes[e['risk_id']]['label']}\n\n")

            f.write(f"--- Discovered Chain [{d['reason']}] ---\n")
            f.write(f"Attack: {nodes[d['attack_id']]['label']}\n")
            f.write(f"Func:   {nodes[d['func_id']]['label']}\n")
            f.write(f"Risk:   {nodes[d['risk_id']]['label']}\n")
            f.write("-" * 80 + "\n\n")

if __name__ == "__main__":
    print("正在搜寻关联链...")
    nodes, edges_raw, edge_to_refs, existing = get_all_data()
    discovered = find_discovered_chains(nodes, edges_raw, edge_to_refs)
    compare_and_report(nodes, existing, discovered)
    print(f"完成！报告已生成: {os.path.abspath(OUTPUT_FILE)}")
