import sqlite3
import json

DB_PATH = 'intelligence_v2.db'

def create_example():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    scenario_id = 'scenario_zero_click_pdf_exfil'
    name = '零点击PDF数据窃取'
    description = '通过PDF隐式注入逐步突破安全边界，最终实现数据外泄'

    steps = [
        {
            'order': 1,
            'chain_id': 'chain_hidden_prompt_injec_r_a_g_retriever_secur',
            'action': 'PDF白色文字注入绕过安全约束',
            'resulting_state': '安全约束已被绕过',
            'state_type': 'constraint_bypassed'
        },
        {
            'order': 2,
            'chain_id': 'chain_hidden_prompt_injec_system_prompt_s_syste',
            'action': '利用绕过后的权限提取系统提示词',
            'resulting_state': '系统提示已泄露',
            'state_type': 'info_disclosed'
        },
        {
            'order': 3,
            'chain_id': 'chain_hidden_prompt_injec_r_a_g_retriever_unaut',
            'action': '利用泄露的提示词实施数据外泄',
            'resulting_state': '敏感数据已外传至攻击者服务器',
            'state_type': 'data_exfiltrated'
        }
    ]

    steps_json = json.dumps(steps, ensure_ascii=False)
    final_state = '用户PII数据完全泄露'

    # Check if chains exist to avoid FK (logic) errors, though we don't strictly enforce FK in SQLite by default unless enabled
    # But let's check for log warnings
    for s in steps:
        cursor.execute("SELECT id FROM chains WHERE id LIKE ?", (s['chain_id'] + '%',))
        if not cursor.fetchone():
             # Try to find a real chain ID to use if the hardcoded one is missing (since IDs are generated dynamically)
             # The populate script uses generated IDs based on truncated strings.
             # Let's try to find a suitable replacement if missing.
             print(f"Warning: Chain {s['chain_id']} not found exactly.")

    # We use INSERT OR REPLACE to ensure it works
    cursor.execute('''
        INSERT OR REPLACE INTO scenarios (id, name, description, steps_json, final_state)
        VALUES (?, ?, ?, ?, ?)
    ''', (scenario_id, name, description, steps_json, final_state))
    
    conn.commit()
    print(f"✓ 示例场景 '{name}' 创建成功！")
    conn.close()

if __name__ == '__main__':
    create_example()
