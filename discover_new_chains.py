
import sqlite3
import json
import textwrap
from collections import defaultdict

def discover_new_chains():
    conn = sqlite3.connect('intelligence_v2.db')
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # 1. Load Data
    print("Loading graph data...")
    cursor.execute("SELECT id, label, type, description FROM graph_nodes")
    nodes = {row['id']: dict(row) for row in cursor.fetchall()}
    
    # 获取所有逻辑边
    cursor.execute("SELECT source, target, relation FROM graph_edges")
    edges = cursor.fetchall()
    
    # 获取所有证据 (支持多源)
    cursor.execute("SELECT source, target, relation, source_ref, description FROM edge_evidence")
    evidence_rows = cursor.fetchall()
    
    # evidence_map[(src, dst, rel)] = {"refs": {ref1, ref2}, "descriptions": [desc1, desc2]}
    evidence_map = defaultdict(lambda: {"refs": set(), "descs": []})
    for ev in evidence_rows:
        key = (ev['source'], ev['target'], ev['relation'])
        evidence_map[key]["refs"].add(ev['source_ref'])
        if ev['description']:
            evidence_map[key]["descs"].append((ev['source_ref'], ev['description']))
    
    # Build Indices
    func_uses = defaultdict(list)
    func_exposes = defaultdict(list)
    existing_direct_links = set()
    
    for edge in edges:
        src, dst, rel = edge['source'], edge['target'], edge['relation']
        ev_info = evidence_map.get((src, dst, rel))
        if not ev_info or not ev_info.get("refs"):
            continue # Skip edges without evidence
        
        if rel == 'utilizes':
            if nodes.get(dst, {}).get('type') == 'Functionality':
                func_uses[dst].append((src, ev_info))
                
        elif rel == 'exposes':
            if nodes.get(src, {}).get('type') == 'Functionality':
                func_exposes[src].append((dst, ev_info))
                
        elif rel == 'causes':
            existing_direct_links.add((src, dst))

    print(f"Indices built: {len(func_uses)} funcs used by attacks, {len(func_exposes)} funcs exposing risks.")
    
    discovered_chains = []
    
    # 2. Pivot on Functionality
    # Identify: Attack A -> Functionality F -> Risk R
    for func_id, attacks in func_uses.items():
        risks_exposed = func_exposes.get(func_id, [])
        if not risks_exposed:
            continue
            
        for atk_id, atk_ev in attacks:
            for risk_id, risk_ev in risks_exposed:
                
                # 检查 1: 这是一个已知的直接关联吗？
                is_known = (atk_id, risk_id) in existing_direct_links
                
                # 检查 2: 交集逻辑确定是否为“单源证实”
                # 如果存在一个 Ref 同时提到这两条边，则为 Single-Source
                common_refs = atk_ev['refs'] & risk_ev['refs']
                is_single_source = len(common_refs) > 0
                
                if is_single_source:
                    chain_type = "Existing" # 单源证实
                elif is_known:
                    chain_type = "Corrobated (Multi-Source)" # 已知但由多源拼凑证据
                else:
                    chain_type = "New (Discovered)" # 全新推断发现
                
                # 为了报告显示，选一个代表性的描述和 Ref
                atk_refs_sorted = sorted(list(atk_ev['refs']))
                if not atk_refs_sorted: continue # Double check
                ref_atk = atk_refs_sorted[0]
                desc_atk = next((d for r, d in atk_ev['descs'] if r == ref_atk), "")
                
                risk_refs_sorted = sorted(list(risk_ev['refs']))
                if not risk_refs_sorted: continue
                ref_risk = risk_refs_sorted[0]
                desc_risk = next((d for r, d in risk_ev['descs'] if r == ref_risk), "")

                # 如果是单源，优先显示那个共同的 Ref
                if is_single_source:
                    ref_atk = ref_risk = sorted(list(common_refs))[0]
                    desc_atk = next((d for r, d in atk_ev['descs'] if r == ref_atk), desc_atk)
                    desc_risk = next((d for r, d in risk_ev['descs'] if r == ref_risk), desc_risk)
                
                chain = {
                    "type": chain_type,
                    "attack": nodes[atk_id],
                    "functionality": nodes[func_id],
                    "risk": nodes[risk_id],
                    "inference_logic": {
                        "path": "Attack -> utilizes -> Func -> exposes -> Risk",
                        "attack_use_ref": ref_atk,
                        "risk_expose_ref": ref_risk,
                        "attack_use_desc": desc_atk,
                        "risk_expose_desc": desc_risk,
                        "common_refs": list(common_refs)
                    }
                }
                discovered_chains.append(chain)

    discovered_chains.sort(key=lambda x: 0 if "New" in x['type'] else 1)
    
    # 3. Output
    print(f"\nFound {len(discovered_chains)} total logical chains.")
    
    def write_chain_report(filename, chains, title):
        with open(filename, "w", encoding="utf-8") as f:
            f.write(f"=== {title} ===\n")
            f.write(f"Total Count: {len(chains)}\n")
            f.write("="*80 + "\n\n")
            
            for i, chain in enumerate(chains):
                f.write(f"Chain #{i+1} [{chain['type']}]\n")
                
                # ATTACK
                f.write(f"   [Attack] {chain['attack']['label']} ({chain['attack']['id']})\n")
                atk_desc = textwrap.indent(textwrap.fill(chain['attack']['description'], width=80), "      ")
                f.write(f"{atk_desc}\n")
                
                # EDGE 1
                edge1_desc = chain['inference_logic']['attack_use_desc']
                edge1_ref = chain['inference_logic']['attack_use_ref']
                f.write(f"      |\n")
                f.write(f"      +--[utilizes (Ref:{edge1_ref})]-->\n")
                if edge1_desc:
                    f.write(f"      |  Desc: {edge1_desc}\n")
                
                # FUNC
                f.write(f"   [Func]   {chain['functionality']['label']} ({chain['functionality']['id']})\n")
                func_desc = textwrap.indent(textwrap.fill(chain['functionality']['description'], width=80), "      ")
                f.write(f"{func_desc}\n")
                
                # EDGE 2
                edge2_desc = chain['inference_logic']['risk_expose_desc']
                edge2_ref = chain['inference_logic']['risk_expose_ref']
                f.write(f"      |\n")
                f.write(f"      +--[exposes (Ref:{edge2_ref})]-->\n")
                if edge2_desc:
                    f.write(f"      |  Desc: {edge2_desc}\n")
                
                # RISK
                f.write(f"   [Risk]   {chain['risk']['label']} ({chain['risk']['id']})\n")
                risk_desc = textwrap.indent(textwrap.fill(chain['risk']['description'], width=80), "      ")
                f.write(f"{risk_desc}\n\n")
                
                if "New" in chain['type']:
                    f.write(f"   💡 Insight: Cross-reference discovery.\n")
                    f.write(f"      - Edge 1 from Source {edge1_ref}\n")
                    f.write(f"      - Edge 2 from Source {edge2_ref}\n")
                
                f.write("-" * 80 + "\n\n")
        print(f"Saved {len(chains)} chains to {filename}")

    # Split chains
    # Existing: Single source, known link
    # Corrobated: Multi source, known link (Inferred explanation)
    # New Discovery: Unknown link (Inferred discovery)
    
    single_source_chains = [c for c in discovered_chains if c['type'] == "Existing"]
    inferred_chains = [c for c in discovered_chains if c['type'] != "Existing"]
    
    write_chain_report("chains_existing.txt", single_source_chains, "Single-Source Verified Attack Chains")
    write_chain_report("chains_discovered.txt", inferred_chains, "Inferred & Discovered Attack Chains (Multi-Source)")

    conn.close()

if __name__ == "__main__":
    discover_new_chains()
