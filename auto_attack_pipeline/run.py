"""
run.py - 命令行入口
支持按 Func 类型、指定 chain_id、对照实验等多种运行模式。

使用示例：
  # 对"上下文窗口"类链路批量运行（默认模式）
  python run.py

  # 指定 Func 关键词
  python run.py --func "RAG"

  # 指定具体 chain_id
  python run.py --chain-ids chain_001 chain_002 chain_003

  # 最多运行 5 条
  python run.py --max 5

  # 静默模式（只输出摘要）
  python run.py --quiet
"""

import argparse
import sys
import os

# 确保 auto_attack_pipeline 目录在 Python 路径里
sys.path.insert(0, os.path.dirname(__file__))

from pipeline import run_pipeline


def main():
    parser = argparse.ArgumentParser(
        description="图谱增强版 PAIR 自动攻击复现 Pipeline",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--func", type=str, default="上下文窗口",
        help="Func 节点标签关键词过滤（如 '上下文窗口', 'RAG', '输入验证'）"
    )
    parser.add_argument(
        "--max-iters", type=int, default=None,
        help="每条链路最大迭代次数（覆盖 pipeline.py 默认值 20）"
    )
    parser.add_argument(
        "--phase1", action="store_true",
        help="只跑 Phase 1 链路（Risk 不依赖外部工具，纯 LLM 可验证）"
    )
    parser.add_argument(
        "--max", type=int, default=5,
        help="最多执行的链路数量"
    )
    parser.add_argument(
        "--chain-ids", nargs="+", default=None,
        metavar="CHAIN_ID",
        help="指定 chain_id 列表（优先于 --func 过滤）"
    )
    parser.add_argument(
        "--db", type=str, default="../intelligence_v2.db",
        help="图谱数据库路径"
    )
    parser.add_argument(
        "--output", type=str, default="pipeline_results.json",
        help="结果输出文件路径"
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="静默模式，只输出最终摘要"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="试运行：只显示将要攻击的链路，不实际执行攻击"
    )
    parser.add_argument(
        "--skip-tested", action="store_true",
        help="跳过已经测试过的链路，只选取尚未测试的 existing chain"
    )

    args = parser.parse_args()

    if args.dry_run:
        # 只列出将要测试的链路
        from graph_kb import GraphKnowledgeBase
        kb = GraphKnowledgeBase(db_path=args.db)
        if args.chain_ids:
            chains = [kb.get_chain_by_id(cid) for cid in args.chain_ids]
            chains = [c for c in chains if c is not None]
        else:
            chains = kb.get_feasible_chains_by_func(args.func)[:args.max]

        print(f"\n[DryRun] 将要攻击的链路（共 {len(chains)} 条）：")
        for i, c in enumerate(chains):
            print(f"  [{i+1}] {c.id}")
            print(f"       Attack: {c.attack.label}")
            print(f"       Func:   {c.func.label}")
            print(f"       Risk:   {c.risk.label}")
            print(f"       Origin: {c.attack.origin}")
        return

    # 实际执行
    run_pipeline(
        func_keyword=args.func,
        max_chains=args.max,
        db_path=args.db,
        chain_ids=args.chain_ids,
        verbose=not args.quiet,
        output_file=args.output,
        phase1_only=args.phase1,
        max_iters_override=args.max_iters,
        skip_tested=args.skip_tested,
    )


if __name__ == "__main__":
    main()
