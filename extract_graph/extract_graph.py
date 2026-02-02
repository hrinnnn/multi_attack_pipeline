import sqlite3
import json
import os
import time
from typing import List, Dict, Any, Tuple
# Note: When running this as a package or within the folder, imports work differently.
# If running as 'python extract_graph.py' inside the folder:
from llm_handlers import (
    extract_graph_from_text,
    merge_node_descriptions,
    check_semantic_similarity,
    augment_attack_node,
    perf_stats
)

# Configuration
# Since this script is now in a subdirectory, the DB is in the parent directory.
DB_PATH = '../intelligence_v2.db' 
BATCH_LIMIT = 0  # 0 means no limit

def init_db(conn):
    """初始化数据库表"""
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS graph_nodes (
            id TEXT PRIMARY KEY,
            label TEXT,
            type TEXT NOT NULL,
            description TEXT,
            source_ref INTEGER,
            origin TEXT DEFAULT 'extracted'
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS graph_edges (
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            relation TEXT NOT NULL,
            PRIMARY KEY (source, target, relation),
            FOREIGN KEY (source) REFERENCES graph_nodes(id),
            FOREIGN KEY (target) REFERENCES graph_nodes(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS edge_evidence (
            source TEXT NOT NULL,
            target TEXT NOT NULL,
            relation TEXT NOT NULL,
            source_ref INTEGER NOT NULL,
            description TEXT,
            PRIMARY KEY (source, target, relation, source_ref),
            FOREIGN KEY (source, target, relation) REFERENCES graph_edges(source, target, relation)
        )
    ''')
    conn.commit()

def process_node(cursor, node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id, origin='extracted'):
    """
    处理单个节点的插入/更新/对齐逻辑
    """
    try:
        original_id = node['id']
        final_id = original_id
        new_desc = node.get('description', '')
        node_type = node['type']
        
        is_new_entry = False

        if original_id in existing_nodes_dict:
            final_id = original_id
            old_desc = existing_nodes_dict[final_id]['description']
            if new_desc and new_desc != old_desc:
                merged_desc = merge_node_descriptions(old_desc, new_desc)
                cursor.execute("UPDATE graph_nodes SET description = ? WHERE id = ?", (merged_desc, final_id))
                existing_nodes_dict[final_id]['description'] = merged_desc
        
        else:
            candidates = existing_nodes_by_type.get(node_type, [])
            match_id = check_semantic_similarity(node, candidates)
            
            if match_id and match_id in existing_nodes_dict:
                print(f"    [Semantic Match] '{original_id}' -> '{match_id}'")
                final_id = match_id
                old_desc = existing_nodes_dict[final_id]['description']
                if new_desc:
                    merged_desc = merge_node_descriptions(old_desc, new_desc)
                    cursor.execute("UPDATE graph_nodes SET description = ? WHERE id = ?", (merged_desc, final_id))
                    existing_nodes_dict[final_id]['description'] = merged_desc
            else:
                is_new_entry = True
                print(f"    [New Node] 插入: {final_id}")
                cursor.execute('''
                    INSERT INTO graph_nodes (id, label, type, description, source_ref, origin)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (final_id, node['label'], node['type'], new_desc, intelligence_id, origin))
                
                node_info = {"id": final_id, "label": node['label'], "type": node_type, "description": new_desc, "origin": origin}
                if node_type not in existing_nodes_by_type:
                    existing_nodes_by_type[node_type] = []
                existing_nodes_by_type[node_type].append(node_info)
                existing_nodes_dict[final_id] = node_info
				
        id_mapping[original_id] = final_id
        return final_id, is_new_entry
            
    except Exception as e:
        print(f"    处理节点错误 {node.get('id')}: {e}")
        return original_id, False

def insert_edge(cursor, source, target, relation, description, intelligence_id):
    try:
        cursor.execute('''
            INSERT OR IGNORE INTO graph_edges (source, target, relation)
            VALUES (?, ?, ?)
        ''', (source, target, relation))
        
        cursor.execute('''
            INSERT OR IGNORE INTO edge_evidence (source, target, relation, source_ref, description)
            VALUES (?, ?, ?, ?, ?)
        ''', (source, target, relation, intelligence_id, description))
    except Exception as e:
        print(f"    插入边/证据失败 {source}->{target}: {e}")

def validate_and_insert_edge(cursor, source, target, relation, description, intelligence_id, nodes_dict):
    valid_schema = {
        'utilizes': ('Attack', 'Functionality'),
        'causes': ('Attack', 'Risk'),
        'exposes': ('Functionality', 'Risk')
    }
    if relation not in valid_schema: return False

    src_type = nodes_dict.get(source, {}).get('type')
    dst_type = nodes_dict.get(target, {}).get('type')
    expected_src, expected_dst = valid_schema[relation]

    if src_type == expected_src and dst_type == expected_dst:
        insert_edge(cursor, source, target, relation, description, intelligence_id)
        return True
    return False

def save_graph_data(conn, data, source_url, intelligence_id):
    cursor = conn.cursor()
    
    if not isinstance(data, dict):
        print(f"    [Error] LLM 返回数据格式错误 (预期为 dict, 实际为 {type(data)})。跳过记录。")
        cursor.execute("UPDATE intel_core SET extraction_status = 'error' WHERE id = ?", (intelligence_id,))
        conn.commit()
        return

    if not data.get("graphable", False):
        cursor.execute("UPDATE intel_core SET extraction_status = 'skipped' WHERE id = ?", (intelligence_id,))
        conn.commit()
        return

    atomic_chains = data.get("atomic_chains", [])
    raw_scenarios = data.get("complex_scenarios", [])
    if not atomic_chains and data.get("scenarios"): atomic_chains = data.get("scenarios")

    complex_scenarios = []
    if isinstance(raw_scenarios, list):
        for s in raw_scenarios:
            if not isinstance(s, dict): continue
            steps = s.get('steps', [])
            if len(steps) == 1 and isinstance(steps[0].get('chain'), dict):
                # 显式降级：单步场景直接转为原子链
                atomic_chains.append(steps[0]['chain'])
            elif len(steps) >= 2:
                complex_scenarios.append(s)

    print(f"  -> 提取: {len(atomic_chains)} 原子链, {len(complex_scenarios)} 复合场景")
    
    cursor.execute("SELECT id, label, type, description, origin FROM graph_nodes")
    all_existing_nodes = cursor.fetchall()
    existing_nodes_by_type = {}
    existing_nodes_dict = {} 
    
    for row in all_existing_nodes:
        nid, nlabel, ntype, ndesc, norigin = row
        if ntype not in existing_nodes_by_type: existing_nodes_by_type[ntype] = []
        node_info = {"id": nid, "label": nlabel, "type": ntype, "description": ndesc, "origin": norigin}
        existing_nodes_by_type[ntype].append(node_info)
        existing_nodes_dict[nid] = node_info

    id_mapping = {}

    def process_chain(chain_data):
        if not isinstance(chain_data, dict):
            print(f"    [Warning] 跳过格式错误的原子链 (预期为 dict, 实际为 {type(chain_data)}): {chain_data}")
            return None
            
        attack_node = chain_data.get('attack')
        func_node = chain_data.get('functionality')
        risk_node = chain_data.get('risk')
        if not (isinstance(attack_node, dict) and isinstance(func_node, dict) and isinstance(risk_node, dict)): 
            atk_label = attack_node.get('label', 'Unknown') if isinstance(attack_node, dict) else str(attack_node)
            print(f"    [Warning] 跳过数据不完整的原子链 (节点格式错误): {atk_label}")
            return None

        atk_id, atk_is_new = process_node(cursor, attack_node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id)
        func_id, _ = process_node(cursor, func_node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id)
        risk_id, _ = process_node(cursor, risk_node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id)

        details = chain_data.get('details', '')
        validate_and_insert_edge(cursor, atk_id, func_id, 'utilizes', details, intelligence_id, existing_nodes_dict)
        validate_and_insert_edge(cursor, atk_id, risk_id, 'causes', details, intelligence_id, existing_nodes_dict)
        validate_and_insert_edge(cursor, func_id, risk_id, 'exposes', details, intelligence_id, existing_nodes_dict)

        if atk_is_new and attack_node['type'] == 'Attack':
            variants = augment_attack_node(atk_id, attack_node['label'], attack_node.get('description',''), func_node.get('label', ''), risk_node.get('label', ''))
            for v in variants:
                if not v.get('label'): continue
                temp_id = "attack_" + v.get('label', '').encode('utf-8').hex()[:10]
                v_node = {"id": temp_id, "label": v['label'], "type": "Attack", "description": v.get('description', '')}
                v_id, _ = process_node(cursor, v_node, existing_nodes_dict, existing_nodes_by_type, id_mapping, intelligence_id, origin='augmented')
                if v_id:
                    aug_details = f"[Augmented from {attack_node['label']}] {v.get('description','')[:50]}..."
                    validate_and_insert_edge(cursor, v_id, func_id, 'utilizes', aug_details, intelligence_id, existing_nodes_dict)
                    validate_and_insert_edge(cursor, v_id, risk_id, 'causes', aug_details, intelligence_id, existing_nodes_dict)
        return (atk_id, func_id, risk_id)

    for chain in atomic_chains:
        if not isinstance(chain, dict): continue
        ids = process_chain(chain)
        if ids:
            atk_id, func_id, risk_id = ids
            chain_id = f"chain_{atk_id}_{func_id}_{risk_id}"
            cursor.execute('INSERT OR IGNORE INTO chains (id, attack_id, func_id, risk_id, source_type, source_refs) VALUES (?, ?, ?, ?, "existing", ?)', (chain_id, atk_id, func_id, risk_id, json.dumps([intelligence_id])))

    for scenario in complex_scenarios:
        if not isinstance(scenario, dict): continue
        s_name = scenario.get('name', '未命名场景')
        s_id = "scenario_" + s_name.lower().replace(" ", "_")
        steps_processed = []
        for step in scenario.get('steps', []):
            if not isinstance(step, dict): continue
            chain_data = step.get('chain')
            if chain_data:
                # Handle both inline chain definitions (dict) and chain references (string)
                if isinstance(chain_data, str):
                    # It's a chain ID reference - skip processing, just record it
                    steps_processed.append({
                        "order": step.get('order'),
                        "chain_id": chain_data,
                        "action": step.get('action', ''),
                        "resulting_state": step.get('resulting_state', '')
                    })
                elif isinstance(chain_data, dict):
                    # It's an inline chain definition - process it
                    ids = process_chain(chain_data)
                    if ids:
                        atk_id, func_id, risk_id = ids
                        c_id = f"chain_{atk_id}_{func_id}_{risk_id}"
                        cursor.execute('INSERT OR IGNORE INTO chains (id, attack_id, func_id, risk_id, source_type, source_refs) VALUES (?, ?, ?, ?, "existing", ?)', (c_id, atk_id, func_id, risk_id, json.dumps([intelligence_id])))
                        steps_processed.append({
                            "order": step.get('order'),
                            "chain_id": c_id,
                            "action": chain_data.get('attack', {}).get('label', ''),
                            "resulting_state": step.get('resulting_state', '')
                        })
        if steps_processed:
            cursor.execute('INSERT OR REPLACE INTO scenarios (id, name, description, steps_json, final_state) VALUES (?, ?, ?, ?, ?)', (s_id, s_name, scenario.get('description', ''), json.dumps(steps_processed, ensure_ascii=False), scenario.get('final_state')))

    cursor.execute("UPDATE intel_core SET extraction_status = 'extracted' WHERE id = ?", (intelligence_id,))
    conn.commit()

def main():
    conn = sqlite3.connect(DB_PATH)
    init_db(conn)
    cursor = conn.cursor()
    cursor.execute("SELECT id, url, full_text FROM intel_core WHERE is_relevant=1 AND process_status='processed' AND extraction_status='pending'")
    rows = cursor.fetchall()
    print(f"找到 {len(rows)} 条待处理情报...")
    
    if BATCH_LIMIT > 0: rows = rows[:BATCH_LIMIT]
    for i, row in enumerate(rows):
        db_id, url, content = row
        print(f"\n[{i+1}/{len(rows)}] 正在处理 [{db_id}] {url} ...")
        content_to_process = (content[:35000] + "\n\n[... truncated ...]\n\n" + content[-25000:]) if len(content) > 60000 else content
        result = extract_graph_from_text(content_to_process, url)
        if result: save_graph_data(conn, result, url, db_id)

    print(f"\n{'='*50}\n性能统计摘要:")
    for cat, durations in perf_stats.items():
        if durations: print(f"  - {cat:15}: 总计 {len(durations):3} 次, 平均 {sum(durations)/len(durations):5.2f}s")
    print(f"{'='*50}\n")
    conn.close()

if __name__ == "__main__":
    main()
