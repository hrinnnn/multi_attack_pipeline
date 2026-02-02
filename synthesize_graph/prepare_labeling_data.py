
import sqlite3
import json
import os
from collections import defaultdict

# 配置路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 数据库位于上一级目录的根目录
DB_PATH = os.path.join(BASE_DIR, '../intelligence_v2.db')
# 输出文件位置
OUTPUT_FILE = os.path.join(BASE_DIR, '../my_notes/chain_labels.json')

def get_connection():
    return sqlite3.connect(DB_PATH, timeout=30)

def get_node_info(cursor, node_id):
    """
    获取节点的详细信息: label, description, type
    """
    cursor.execute("SELECT id, label, type, description, origin FROM graph_nodes WHERE id = ?", (node_id,))
    row = cursor.fetchone()
    if row:
        return dict(row)
    return None

def fetch_existing_chains(cursor):
    """
    从数据库获取所有 Existing Chains
    """
    cursor.execute("SELECT id, attack_id, func_id, risk_id FROM chains WHERE source_type = 'existing'")
    raw_chains = cursor.fetchall()

    existing_chains = []
    print(f"[Info] Found {len(raw_chains)} existing chains in DB.")

    for idx, row in enumerate(raw_chains, 1):
        chain_data = {
            "index": idx,
            "id": row['id'],
            "nodes": {
                "attack": get_node_info(cursor, row['attack_id']),
                "func": get_node_info(cursor, row['func_id']),
                "risk": get_node_info(cursor, row['risk_id'])
            },
            # Existing Chain 只需打分：复现性
            "human_label": {
                "reproducibility": -1,  # -1 表示未打分
                "notes": ""
            }
        }
        existing_chains.append(chain_data)
    
    return existing_chains

def discover_chains_logic(cursor):
    """
    复现 discover_graph_chains.py 的逻辑来寻找潜在链路
    """
    # 1. 加载所有节点
    cursor.execute("SELECT * FROM graph_nodes")
    nodes_map = {row['id']: dict(row) for row in cursor.fetchall()}

    # 2. 加载边证据
    cursor.execute("SELECT source, target, relation, source_ref FROM edge_evidence")
    evidence_rows = cursor.fetchall()
    edge_to_refs = defaultdict(set)
    for ev in evidence_rows:
        edge_to_refs[(ev['source'], ev['target'], ev['relation'])].add(ev['source_ref'])

    # 3. 加载边
    cursor.execute("SELECT source, target, relation FROM graph_edges")
    edges_raw = cursor.fetchall()

    atk_to_funcs = defaultdict(list)
    atk_to_risks = defaultdict(list)

    for edge in edges_raw:
        s, t, r = edge['source'], edge['target'], edge['relation']
        refs = edge_to_refs.get((s, t, r), set())
        if r == 'utilizes':
            atk_to_funcs[s].append((t, refs))
        elif r == 'causes':
            atk_to_risks[s].append((t, refs))

    discovered = []
    
    for atk_id, funcs in atk_to_funcs.items():
        risks = atk_to_risks.get(atk_id, [])
        for f_id, atk_func_refs in funcs:
            for risk_id, atk_risk_refs in risks:
                atk_node = nodes_map.get(atk_id)
                func_node = nodes_map.get(f_id)
                risk_node = nodes_map.get(risk_id)
                
                if not (atk_node and func_node and risk_node):
                    continue

                # 核心发现逻辑：如果是 Cross-Source 或 包含 Augmented 节点
                is_cross_source = not (atk_func_refs & atk_risk_refs)
                has_augmented = any(n['origin'] == 'augmented' for n in [atk_node, func_node, risk_node])

                if is_cross_source or has_augmented:
                    reason = []
                    if is_cross_source: reason.append("Cross-Source")
                    if has_augmented: reason.append("Augmented")
                    
                    # 生成一个临时ID
                    chain_id = f"disc_{atk_id}_{f_id}_{risk_id}"
                    
                    discovered.append({
                        "id": chain_id,
                        "attack_id": atk_id,
                        "func_id": f_id,
                        "risk_id": risk_id,
                        "nodes": (atk_id, f_id, risk_id), # 用于集合运算
                        "discovery_reason": " | ".join(reason)
                    })
    
    print(f"[Info] Discovered {len(discovered)} potential chains.")
    return discovered, nodes_map

def process_discovered_chains(cursor, discovered_raw, nodes_map):
    """
    处理发现的链，并寻找其 Reference (相似的 Existing Chain)
    """
    # 获取用于对比的 Existing Chains 的简化集合
    cursor.execute("SELECT id, attack_id, func_id, risk_id FROM chains WHERE source_type = 'existing'")
    existing_rows = cursor.fetchall()
    
    processed_chains = []

    for idx, d in enumerate(discovered_raw, 1):
        d_nodes_set = set(d['nodes'])
        
        # 寻找相似链 (2个节点重合)
        reference_context = None
        
        for e in existing_rows:
            e_nodes = (e['attack_id'], e['func_id'], e['risk_id'])
            e_nodes_set = set(e_nodes)
            
            intersection = d_nodes_set & e_nodes_set
            
            # 如果有2个节点相同，视为高度相关，以此作为 Reference
            if len(intersection) == 2:
                # 找出那个不同的节点
                diff_node_id = list(e_nodes_set - d_nodes_set)[0]
                diff_node_info = nodes_map.get(diff_node_id)
                
                reference_context = {
                    "related_existing_chain_id": e['id'],
                    "shared_nodes_count": 2,
                    "difference_node": {
                        "id": diff_node_id,
                        "label": diff_node_info['label'] if diff_node_info else "Unknown",
                        "description": diff_node_info['description'] if diff_node_info else "",
                        "type": diff_node_info['type'] if diff_node_info else "Unknown"
                    },
                    "note": "This existing chain shares 2/3 nodes with the discovered chain. Use it to judge Novelty."
                }
                break # 找到一个最相似的即可
        
        # 构建最终对象
        chain_obj = {
            "index": idx,
            "id": d['id'],
            "discovery_reason": d['discovery_reason'],
            "nodes": {
                "attack": nodes_map.get(d['attack_id']),
                "func": nodes_map.get(d['func_id']),
                "risk": nodes_map.get(d['risk_id'])
            },
            "reference_context": reference_context, # 如果为 None，说明是一个结构上全新的链 (High Novelty 潜力)
            
            # Discovered Chain 需要打双分
            "human_label": {
                "reproducibility": -1, # 0-1
                "novelty": -1,         # 0-1
                "notes": ""
            }
        }
        processed_chains.append(chain_obj)
        
    return processed_chains

def main():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    try:
        # 1. 处理 Existing Chains (只打复现分)
        existing_data = fetch_existing_chains(cursor)

        # 2. 发现并处理 Discovered Chains (打复现分 + 新颖性分)
        discovered_raw, nodes_map = discover_chains_logic(cursor)
        discovered_data = process_discovered_chains(cursor, discovered_raw, nodes_map)

        # 3. 合并输出
        final_output = {
            "meta": {
                "total_existing": len(existing_data),
                "total_discovered": len(discovered_data),
                "instruction": "Please fill in 'human_label' fields. reproducibility: 0-1, novelty: 0-1. -1 means pending."
            },
            "existing_chains": existing_data,
            "discovered_chains": discovered_data
        }

        # 4. 写入文件
        # 如果目录不存在先创建
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            json.dump(final_output, f, indent=2, ensure_ascii=False)
            
        print(f"\n[Success] Data prepared at: {OUTPUT_FILE}")
        print(f"Stats: {len(existing_data)} Existing, {len(discovered_data)} Discovered.")

    except Exception as e:
        print(f"[Error] {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
