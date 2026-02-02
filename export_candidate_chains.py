import sqlite3
import textwrap

DB_PATH = 'intelligence_v2.db'
OUTPUT_FILE = 'chain_candidates_full.md'

def fetch_chains():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            c.id, 
            c.reproducibility_level,
            c.evaluation_reason,
            c.implementation_guide,
            a.label as attack, a.description as atk_desc,
            f.label as func, f.description as func_desc,
            r.label as risk, r.description as risk_desc
        FROM chains c
        JOIN graph_nodes a ON c.attack_id = a.id
        JOIN graph_nodes f ON c.func_id = f.id
        JOIN graph_nodes r ON c.risk_id = r.id
        WHERE c.reproducibility_level IN ('High', 'Medium')
        ORDER BY CASE c.reproducibility_level 
            WHEN 'High' THEN 1 
            WHEN 'Medium' THEN 2 
            ELSE 3 
        END
    """)
    return cursor.fetchall()

def format_report(chains):
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("# Attack Chain Candidates (High & Medium Reproducibility)\n\n")
        f.write(f"Total Found: {len(chains)}\n\n")
        
        current_level = None
        
        for chain in chains:
            level = chain['reproducibility_level']
            if level != current_level:
                f.write(f"\n## --- {level} Reproducibility ---\n\n")
                current_level = level
                
            f.write(f"### {chain['attack']} -> {chain['func']} -> {chain['risk']}\n")
            f.write(f"**Chain ID**: `{chain['id']}`\n\n")
            f.write(f"**AI Evaluation**: {chain['evaluation_reason']}\n\n")
            
            if chain['implementation_guide']:
                f.write(f"**Implementation Guide**:\n```python\n{chain['implementation_guide']}\n```\n\n")
                
            f.write("<details>\n<summary>Click to view Node Descriptions</summary>\n\n")
            f.write(f"**[Attack] {chain['attack']}**\n> {chain['atk_desc']}\n\n")
            f.write(f"**[Func] {chain['func']}**\n> {chain['func_desc']}\n\n")
            f.write(f"**[Risk] {chain['risk']}**\n> {chain['risk_desc']}\n\n")
            f.write("</details>\n\n")
            f.write("---\n")

if __name__ == "__main__":
    chains = fetch_chains()
    format_report(chains)
    print(f"Report generated: {OUTPUT_FILE}")
