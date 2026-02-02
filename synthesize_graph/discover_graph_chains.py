import sqlite3
import json
import textwrap
import os
from collections import defaultdict

# 路径配置
# 获取当前脚本所在目录的绝对路径，确保在任何地方运行都能找到 DB
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, '../intelligence_v2.db')
OUTPUT_FILE = 'graph_discovered_report.txt'

def get_connection():
    return sqlite3.connect(DB_PATH, timeout=30)

def discover_chains():
    conn = get_connection()
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    # 1. 加载所有节点及其属性
    cursor.execute("SELECT id, label, type, description, origin FROM graph_nodes")
    nodes = {row['id']: dict(row) for row in cursor.fetchall()}

    # 2. 加载边及其证据来源
    cursor.execute("SELECT source, target, relation FROM graph_edges")
    edges = cursor.fetchall()

    cursor.execute("SELECT source, target, relation, source_ref FROM edge_evidence")
    evidence_rows = cursor.fetchall()
    
    # 建立边到 source_refs 的映射
    edge_to_refs = defaultdict(set)
    for ev in evidence_rows:
        edge_to_refs[(ev['source'], ev['target'], ev['relation'])].add(ev['source_ref'])

    # 3. 组织路径搜索结构
    # utilizes: Attack -> Func
    # causes: Attack -> Risk
    # 注意：在 extract_graph.py 中，系统会自动补全 utilizes, causes, exposes 三条边。
    # 真正的链路逻辑验证应基于 utilizes (手段->组件) 和 causes (手段->后果)。
    
    atk_to_funcs = defaultdict(list)  # atk_id -> [(func_id, refs)]
    atk_to_risks = defaultdict(list)  # atk_id -> [(risk_id, refs)]

    for edge in edges:
        s, t, r = edge['source'], edge['target'], edge['relation']
        refs = edge_to_refs.get((s, t, r), set())
        
        if r == 'utilizes':
            atk_to_funcs[s].append((t, refs))
        elif r == 'causes':
            atk_to_risks[s].append((t, refs))

    discovered_chains = []

    # 4. 遍历所有可能的 (Attack, Func, Risk) 组合
    # 对于每个 Attack，查看它利用了哪些 Func，以及导致了哪些 Risk
    for atk_id, funcs in atk_to_funcs.items():
        risks = atk_to_risks.get(atk_id, [])
        for f_id, atk_func_refs in funcs:
            for risk_id, atk_risk_refs in risks:
                
                # 获取节点对象
                atk_node = nodes.get(atk_id)
                func_node = nodes.get(f_id)
                risk_node = nodes.get(risk_id)
                
                if not (atk_node and func_node and risk_node):
                    continue

                # 判定逻辑 (两个条件满足其一即为 discovered)
                
                # 逻辑 1: 跨源合成 (Cross-Source Synthesis)
                # 如果 "Attack利用某组件" 的证据来源，与 "Attack导致某风险" 的证据来源不重叠，
                # 说明没有任何一个原始情报直接描述了该 (Attack-Func-Risk) 的完整关联，而是我们通过图谱合成发现的。
                is_cross_source = False
                if not (atk_func_refs & atk_risk_refs):
                    is_cross_source = True
                
                # 逻辑 2: 涉及增强节点 (Augmented Nodes)
                # 链路中至少有一个节点是 AI 扩充生成的。
                has_augmented_node = False
                if any(n['origin'] == 'augmented' for n in [atk_node, func_node, risk_node]):
                    has_augmented_node = True

                if is_cross_source or has_augmented_node:
                    reason = []
                    if is_cross_source:
                        reason.append(f"跨源合成 (Util-Refs: {list(atk_func_refs)}, Cause-Refs: {list(atk_risk_refs)})")
                    if has_augmented_node:
                        aug_nodes = [n['label'] for n in [atk_node, func_node, risk_node] if n['origin'] == 'augmented']
                        reason.append(f"涉及增强节点: {', '.join(aug_nodes)}")

                    discovered_chains.append({
                        "id": f"disc_{atk_id[:10]}_{f_id[:10]}_{risk_id[:10]}",
                        "attack": atk_node,
                        "func": func_node,
                        "risk": risk_node,
                        "atk_func_refs": list(atk_func_refs),
                        "atk_risk_refs": list(atk_risk_refs),
                        "discovery_reason": " | ".join(reason)
                    })

    conn.close()
    return discovered_chains

def export_report(chains):
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("=== PART 1: DISCOVERED ATOMIC CHAINS ===\n")
        f.write(f"Total Discovered Paths: {len(chains)}\n")
        f.write("="*80 + "\n\n")

        for i, c in enumerate(chains):
            # 这里的格式模仿 all_existing_graph_data.txt
            f.write(f"Discovery #{i+1} [{c['discovery_reason']}]\n")
            f.write(f"ID: {c['id']}\n")
            
            # Helper to format node label
            def fmt_node(node):
                label = node['label']
                if node.get('origin') == 'augmented':
                    label += " [Augmented]"
                return f"{label} ({node['id']})"

            # Attack
            f.write(f"   [Attack] {fmt_node(c['attack'])}\n")
            desc = textwrap.fill(c['attack']['description'] or "", width=80)
            f.write(textwrap.indent(desc, "      ") + "\n")
            
            # Edge 1: Attack -> utilizes -> Func
            f.write(f"      |\n")
            f.write(f"      +--[utilizes (Source: {c['atk_func_refs'] or '?'})]-->\n")
            
            # Func
            f.write(f"   [Func]   {fmt_node(c['func'])}\n")
            desc = textwrap.fill(c['func']['description'] or "", width=80)
            f.write(textwrap.indent(desc, "      ") + "\n")

            # Edge 2: Attack -> causes -> Risk
            f.write(f"      |\n")
            f.write(f"      +--[causes (Source: {c['atk_risk_refs'] or '?'})]-->\n")

            # Risk
            f.write(f"   [Risk]   {fmt_node(c['risk'])}\n")
            desc = textwrap.fill(c['risk']['description'] or "", width=80)
            f.write(textwrap.indent(desc, "      ") + "\n")
            
            f.write("-" * 80 + "\n\n")

if __name__ == "__main__":
    # 修改输出文件名后缀为 .txt 以匹配样式
    OUTPUT_FILE = 'graph_discovered_report.txt'
    print(f"正在基于图结构特征搜索潜在攻击链 (utilizes + causes)...")
    chains = discover_chains()
    export_report(chains)
    print(f"完成！共发现 {len(chains)} 条链路。")
    print(f"报告已生成至: {os.path.abspath(OUTPUT_FILE)}")
