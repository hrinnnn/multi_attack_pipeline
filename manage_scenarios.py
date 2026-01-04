#!/usr/bin/env python3
"""
Scenario 管理工具：创建、查看、列出复合攻击场景

此工具用于管理攻击场景（Scenarios），支持基于现有攻击链（Chains）构建复杂的多步骤攻击路径。

常用命令:

1. 列出所有场景:
    python manage_scenarios.py list

2. 查看特定场景详情:
    python manage_scenarios.py show <scenario_id>
    示例: python manage_scenarios.py show scenario_zero_click_pdf_exfil

3. 搜索可用攻击链 (用于构建场景):
    python manage_scenarios.py chains [--limit N] [--type existing|discovered] [--search KEYWORD]

4. 导出场景详情到文件:
    python manage_scenarios.py export <scenario_id> [--output filename.txt]
    示例: python manage_scenarios.py export scenario_drip_example

5. 创建新场景 (交互式):
    python manage_scenarios.py create "场景名称" [--desc "场景描述"]
"""
import sqlite3
import json
import argparse
from datetime import datetime

DB_PATH = 'intelligence_v2.db'

def get_connection():
    return sqlite3.connect(DB_PATH)

def list_scenarios():
    """列出所有场景"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, name, description, 
               json_array_length(steps_json) as step_count,
               created_at
        FROM scenarios
        ORDER BY created_at DESC
    ''')
    scenarios = cursor.fetchall()
    conn.close()
    
    if not scenarios:
        print("暂无场景。使用 'create' 命令创建第一个场景。")
        return
    
    print(f"共 {len(scenarios)} 个场景:\n")
    print(f"{'ID':<30} {'名称':<25} {'步骤数':<8} {'创建时间'}")
    print("-" * 80)
    for sid, name, desc, steps, created in scenarios:
        print(f"{sid:<30} {name:<25} {steps:<8} {created[:16]}")

def show_scenario(scenario_id):
    """显示场景详情"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, name, description, steps_json, final_state, created_at
        FROM scenarios WHERE id = ?
    ''', (scenario_id,))
    row = cursor.fetchone()
    
    if not row:
        print(f"场景 '{scenario_id}' 不存在")
        return
    
    sid, name, desc, steps_json, final_state, created = row
    steps = json.loads(steps_json)
    
    print(f"\n{'='*60}")
    print(f"场景: {name}")
    print(f"ID: {sid}")
    print(f"描述: {desc or '无'}")
    print(f"创建时间: {created}")
    print(f"{'='*60}\n")
    
    print("攻击步骤:")
    print("-" * 60)
    for step in steps:
        order = step.get('order', '?')
        chain_id = step.get('chain_id', '?')
        action = step.get('action', '')
        state = step.get('resulting_state', '')
        state_type = step.get('state_type', '')
        
        # 获取 chain 详情
        cursor.execute('''
            SELECT 
                n1.label as attack,
                n2.label as func,
                n3.label as risk
            FROM chains c
            JOIN graph_nodes n1 ON c.attack_id = n1.id
            JOIN graph_nodes n2 ON c.func_id = n2.id
            JOIN graph_nodes n3 ON c.risk_id = n3.id
            WHERE c.id = ?
        ''', (chain_id,))
        chain_row = cursor.fetchone()
        
        print(f"\n步骤 {order}: {action}")
        if chain_row:
            attack, func, risk = chain_row
            print(f"  Chain: {attack} → {func} → {risk}")
        else:
            print(f"  Chain ID: {chain_id}")
        print(f"  状态变化: {state} [{state_type}]")
    
    if final_state:
        print(f"\n最终状态: {final_state}")
    
    conn.close()

def export_scenario(scenario_id, output_file=None):
    """导出格式化的场景报告"""
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, name, description, steps_json, final_state, created_at
        FROM scenarios WHERE id = ?
    ''', (scenario_id,))
    row = cursor.fetchone()
    
    if not row:
        print(f"场景 '{scenario_id}' 不存在")
        return
    
    sid, name, desc, steps_json, final_state, created = row
    steps = json.loads(steps_json)
    
    if not output_file:
        output_file = f"{name.replace(' ', '_')}_report.txt"
        
    with open(output_file, 'w', encoding='utf-8') as f:
        # Header
        f.write("=" * 80 + "\n")
        f.write(f"ATTACK SCENARIO REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        # Meta Info
        f.write(f"NAME        : {name}\n")
        f.write(f"ID          : {sid}\n")
        f.write(f"CREATED     : {created}\n")
        f.write(f"DESCRIPTION : {desc or 'N/A'}\n")
        f.write("-" * 80 + "\n\n")
        
        # Steps
        f.write("ATTACK EXECUTION FLOW\n")
        f.write("=" * 21 + "\n\n")
        
        for step in steps:
            order = step.get('order', '?')
            chain_id = step.get('chain_id', '?')
            action = step.get('action', 'Unknown Action')
            state = step.get('resulting_state', 'Unknown State')
            state_type = step.get('state_type', '')
            
            # Fetch Chain Details
            cursor.execute('''
                SELECT 
                    n1.label as attack, n1.description as atk_desc,
                    n2.label as func, n2.description as func_desc,
                    n3.label as risk, n3.description as risk_desc,
                    c.source_type
                FROM chains c
                JOIN graph_nodes n1 ON c.attack_id = n1.id
                JOIN graph_nodes n2 ON c.func_id = n2.id
                JOIN graph_nodes n3 ON c.risk_id = n3.id
                WHERE c.id = ?
            ''', (chain_id,))
            chain_row = cursor.fetchone()
            
            f.write(f"[STEP {order}] {action}\n")
            f.write("+" + "-"*78 + "+\n")
            
            if chain_row:
                atk, atk_d, func, func_d, risk, risk_d, ctype = chain_row
                
                f.write(f"| Chain ID : {chain_id}\n")
                f.write(f"| Type     : {ctype.upper()}\n")
                f.write("|\n")
                f.write(f"| [ATTACK] : {atk}\n")
                # f.write(f"|            {atk_d[:100]}...\n")
                f.write("|    |\n")
                f.write("|    v (utilizes)\n")
                f.write(f"| [FUNC]   : {func}\n")
                # f.write(f"|            {func_d[:100]}...\n")
                f.write("|    |\n")
                f.write("|    v (exposes)\n")
                f.write(f"| [RISK]   : {risk}\n")
                # f.write(f"|            {risk_d[:100]}...\n")
            else:
                f.write(f"| Chain ID : {chain_id} (Details not found in DB)\n")
                
            f.write("|\n")
            f.write(f"| >>> Resulting State: {state}\n")
            if state_type:
                f.write(f"| >>> State Type     : {state_type}\n")
            f.write("+" + "-"*78 + "+\n")
            f.write("      |\n")
            f.write("      v\n\n")
            
        # Final State
        f.write("[FINAL OUTCOME]\n")
        f.write(f"{final_state or 'No final state defined.'}\n")
        f.write("\n" + "=" * 80 + "\n")
        
    conn.close()
    print(f"✓ Scenario report saved to: {output_file}")

def create_scenario(name, description, steps, final_state=None):
    """创建新场景"""
    conn = get_connection()
    cursor = conn.cursor()
    
    # 生成 ID
    scenario_id = "scenario_" + name.lower().replace(" ", "_").replace("-", "_")[:30]
    
    # 验证所有 chain_id 存在
    for step in steps:
        cursor.execute("SELECT id FROM chains WHERE id = ?", (step['chain_id'],))
        if not cursor.fetchone():
            print(f"警告: chain '{step['chain_id']}' 不存在，继续创建...")
    
    steps_json = json.dumps(steps, ensure_ascii=False)
    
    try:
        cursor.execute('''
            INSERT INTO scenarios (id, name, description, steps_json, final_state)
            VALUES (?, ?, ?, ?, ?)
        ''', (scenario_id, name, description, steps_json, final_state))
        conn.commit()
        print(f"✓ 场景 '{name}' 创建成功！ID: {scenario_id}")
    except sqlite3.IntegrityError:
        print(f"错误: 场景 ID '{scenario_id}' 已存在")
    
    conn.close()
    return scenario_id

def list_chains(limit=20, source_type=None, search=None):
    """列出可用的 chains"""
    conn = get_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT c.id, n1.label, n2.label, n3.label, c.source_type
        FROM chains c
        JOIN graph_nodes n1 ON c.attack_id = n1.id
        JOIN graph_nodes n2 ON c.func_id = n2.id
        JOIN graph_nodes n3 ON c.risk_id = n3.id
    '''
    if source_type:
        query += f" WHERE c.source_type = '{source_type}'"
        
    if search:
        # 添加关键字搜索
        keyword = f"%{search}%"
        if "WHERE" in query:
            query += " AND "
        else:
            query += " WHERE "
        query += "(n1.label LIKE ? OR n2.label LIKE ? OR n3.label LIKE ? OR c.id LIKE ?)"
        cursor.execute(query + f" LIMIT {limit}", (keyword, keyword, keyword, keyword))
    else:
        cursor.execute(query + f" LIMIT {limit}")
        
    chains = cursor.fetchall()
    conn.close()
    
    print(f"\n可用 Chains (前 {limit} 条):\n")
    print(f"{'Chain ID':<50} {'类型':<12} 路径")
    print("-" * 100)
    for cid, attack, func, risk, stype in chains:
        short_id = cid[:48] + ".." if len(cid) > 50 else cid
        print(f"{short_id:<50} {stype:<12} {attack[:15]}→{func[:15]}→{risk[:15]}")

def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest='command')
    
    # list 命令
    list_parser = subparsers.add_parser('list', help='列出所有场景')
    
    # show 命令
    show_parser = subparsers.add_parser('show', help='显示场景详情')
    show_parser.add_argument('scenario_id', help='场景ID')
    
    # chains 命令
    chains_parser = subparsers.add_parser('chains', help='列出可用的 chains')
    chains_parser.add_argument('--limit', type=int, default=20, help='显示数量')
    chains_parser.add_argument('--type', choices=['existing', 'discovered'], help='筛选类型')
    chains_parser.add_argument('--search', help='搜索关键词 (Attack/Func/Risk)')
    
    # export 命令
    export_parser = subparsers.add_parser('export', help='导出场景详情到文件')
    export_parser.add_argument('scenario_id', help='场景ID')
    export_parser.add_argument('--output', help='输出文件名')

    # create 命令 (简化版，通过交互式创建)
    create_parser = subparsers.add_parser('create', help='创建新场景')
    create_parser.add_argument('name', help='场景名称')
    create_parser.add_argument('--desc', help='简短描述')
    
    args = parser.parse_args()
    
    if args.command == 'list':
        list_scenarios()
    elif args.command == 'show':
        show_scenario(args.scenario_id)
    elif args.command == 'chains':
        list_chains(args.limit, args.type, args.search)
    elif args.command == 'export':
        export_scenario(args.scenario_id, args.output)
    elif args.command == 'create':
        print(f"\n创建场景: {args.name}")
        print("请输入步骤 (格式: chain_id | action | state | state_type)")
        print("输入空行结束\n")
        
        steps = []
        order = 1
        while True:
            line = input(f"步骤 {order}: ").strip()
            if not line:
                break
            parts = [p.strip() for p in line.split('|')]
            if len(parts) >= 2:
                step = {
                    'order': order,
                    'chain_id': parts[0],
                    'action': parts[1] if len(parts) > 1 else '',
                    'resulting_state': parts[2] if len(parts) > 2 else '',
                    'state_type': parts[3] if len(parts) > 3 else ''
                }
                steps.append(step)
                order += 1
            else:
                print("  格式错误，请重试")
        
        if steps:
            final = input("最终状态 (可选): ").strip() or None
            create_scenario(args.name, args.desc, steps, final)
        else:
            print("未添加任何步骤，取消创建")
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
