import sqlite3
import json
import textwrap

DB_PATH = '../intelligence_v2.db'
OUTPUT_FILE = 'all_graph_data.txt'

def get_connection():
    return sqlite3.connect(DB_PATH)

def fetch_edge_evidence(cursor, src_id, dst_id, relation):
    """Fetch description from edge_evidence for a given node pair."""
    cursor.execute('''
        SELECT description, source_ref FROM edge_evidence
        WHERE source = ? AND target = ? AND relation = ?
        LIMIT 1
    ''', (src_id, dst_id, relation))
    row = cursor.fetchone()
    if row:
        return row[0], row[1]
    return None, None

def export_chains(f, cursor):
    f.write("=== PART 1: ATOMIC CHAINS ===\n")
    
    # Fetch all chains
    cursor.execute("""
        SELECT 
            c.id, c.source_type, c.reproducibility_level,
            c.attack_id, a.label as attack_label, a.description as attack_desc,
            c.func_id, f.label as func_label, f.description as func_desc,
            c.risk_id, r.label as risk_label, r.description as risk_desc
        FROM chains c
        JOIN graph_nodes a ON c.attack_id = a.id
        JOIN graph_nodes f ON c.func_id = f.id
        JOIN graph_nodes r ON c.risk_id = r.id
        ORDER BY c.source_type, c.id
    """)
    chains = cursor.fetchall()
    f.write(f"Total Atomic Chains: {len(chains)}\n")
    f.write("="*80 + "\n\n")

    for i, row in enumerate(chains):
        cid, stype, repro_level, aid, alab, adesc, fid, flab, fdesc, rid, rlab, rdesc = row
        
        type_str = f"{stype}"
        if repro_level:
            type_str += f" | AI-Eval: {repro_level}"

        f.write(f"Chain #{i+1} [{type_str}]\n")
        f.write(f"ID: {cid}\n")
        
        # Attack
        f.write(f"   [Attack] {alab} ({aid})\n")
        f.write(textwrap.indent(textwrap.fill(adesc or "", width=80), "      ") + "\n")
        
        # Edge 1: Attack -> utilizes -> Func
        desc1, ref1 = fetch_edge_evidence(cursor, aid, fid, 'utilizes')
        f.write(f"      |\n")
        f.write(f"      +--[utilizes (Ref:{ref1 or '?'})]-->\n")
        if desc1:
             f.write(f"      |  Desc: {desc1[:100]}...\n")

        # Func
        f.write(f"   [Func]   {flab} ({fid})\n")
        f.write(textwrap.indent(textwrap.fill(fdesc or "", width=80), "      ") + "\n")

        # Edge 2: Func -> exposes -> Risk
        desc2, ref2 = fetch_edge_evidence(cursor, fid, rid, 'exposes')
        f.write(f"      |\n")
        f.write(f"      +--[exposes (Ref:{ref2 or '?'})]-->\n")
        if desc2:
             f.write(f"      |  Desc: {desc2[:100]}...\n")

        # Risk
        f.write(f"   [Risk]   {rlab} ({rid})\n")
        f.write(textwrap.indent(textwrap.fill(rdesc or "", width=80), "      ") + "\n")
        
        f.write("-" * 80 + "\n\n")

def export_scenarios(f, cursor):
    f.write("\n=== PART 2: COMPLEX SCENARIOS ===\n")
    
    cursor.execute('''
        SELECT id, name, description, steps_json, final_state, created_at
        FROM scenarios
        ORDER BY created_at
    ''')
    scenarios = cursor.fetchall()
    f.write(f"Total Complex Scenarios: {len(scenarios)}\n")
    f.write("="*80 + "\n\n")
    
    for i, row in enumerate(scenarios):
        sid, name, desc, steps_json, final_state, created = row
        f.write(f"Scenario #{i+1}: {name}\n")
        f.write(f"ID: {sid}\n")
        f.write(f"Created: {created}\n")
        f.write(f"Description: {desc}\n")
        f.write(f"Final State: {final_state}\n")
        f.write("\n   Steps:\n")
        
        try:
            steps = json.loads(steps_json)
            for step in steps:
                order = step.get('order')
                cid = step.get('chain_id')
                action = step.get('action')
                res_state = step.get('resulting_state')
                
                # Fetch basic chain info for context
                cursor.execute("""
                    SELECT a.label, f.label, r.label
                    FROM chains c
                    JOIN graph_nodes a ON c.attack_id = a.id
                    JOIN graph_nodes f ON c.func_id = f.id
                    JOIN graph_nodes r ON c.risk_id = r.id
                    WHERE c.id = ?
                """, (cid,))
                chain_info = cursor.fetchone()
                chain_str = f"{chain_info[0]} -> {chain_info[1]} -> {chain_info[2]}" if chain_info else "Unknown Chain"

                f.write(f"   [Step {order}] Action: {action}\n")
                f.write(f"      Chain: {chain_str} ({cid})\n")
                f.write(f"      Result: {res_state}\n")
        except Exception as e:
            f.write(f"      [Error parsing steps: {e}]\n")
            
        f.write("\n" + "-" * 80 + "\n\n")

def main():
    conn = get_connection()
    cursor = conn.cursor()
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        export_chains(f, cursor)
        export_scenarios(f, cursor)
        
    conn.close()
    print(f"Export complete! Data saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
