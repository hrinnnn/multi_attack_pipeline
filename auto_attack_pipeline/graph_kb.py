"""
graph_kb.py - 图谱知识库接口
从 intelligence_v2.db 读取攻击链路，提供备选 Attack 节点查询，写回复现结果。
"""

import sqlite3
from dataclasses import dataclass
from typing import List, Optional

DB_PATH = "../intelligence_v2.db"


@dataclass
class AttackNode:
    id: str
    label: str
    description: str
    origin: str  # 'extracted' or 'augmented'


@dataclass
class FuncNode:
    id: str
    label: str
    description: str


@dataclass
class RiskNode:
    id: str
    label: str
    description: str


@dataclass
class AttackChain:
    id: str
    attack: AttackNode
    func: FuncNode
    risk: RiskNode
    source_type: str
    reproducibility_level: Optional[str]
    evaluation_reason: Optional[str]


# Phase 1 Risk 白名单：只需纯 LLM 输出即可验证（无需真实工具调用）
PHASE1_RISK_IDS = {
    "R-JAILBREAK-001",
    "R-JAILBREAK-SEMANTIC-HIJACK-001",
    "R-JAILBREAK-UNIVERSAL-001",
    "R-JAILBREAK-CONTEXT-TRUNCATED-001",
    "R-JAILBREAK-META-AWARE-001",
    "R-JAILBREAK-BYPASS-AUTH-001",
    "R-JAILBREAK-SCANNER-001",
    "R-JAILBREAK-TOOL-EXEC-001",
    "R-SYSTEM-PROMPT-LEAK-001",
    "R-CONTEXT-POLLUTION-001",
    "R-CREDENTIAL-EXFILTRATION-001",
    "R-PII-EXFILTRATION-001",
    "R-DISINFORMATION-DISSEMINATION-001",
    "R-PROMPT-INJECTION-IMPERCEPTIBLE",
    "R-AUTONOMOUS-EXPLOIT-GENERATION-001",
}


class GraphKnowledgeBase:
    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path

    def _get_conn(self):
        return sqlite3.connect(self.db_path)

    # ------------------------------------------------------------------ #
    #  读取链路
    # ------------------------------------------------------------------ #

    def get_all_chains(self, source_type: str = "existing") -> List[AttackChain]:
        """获取所有指定来源的攻击链路。"""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                c.id,
                a.id, a.label, a.description, a.origin,
                f.id, f.label, f.description,
                r.id, r.label, r.description,
                c.source_type, c.reproducibility_level, c.evaluation_reason
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            JOIN graph_nodes f ON c.func_id   = f.id
            JOIN graph_nodes r ON c.risk_id   = r.id
            WHERE c.source_type = ?
        """, (source_type,))
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_chain(r) for r in rows]

    def get_untested_chains(self, max_count: int = 20, source_type: str = "existing") -> List[AttackChain]:
        """获取尚未测试的链路（滴水不漏地新选，不重复已跑的）。
        判断标准：evaluation_reason 不包含 [PAIR-AUTO] 前缀。
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                c.id,
                a.id, a.label, a.description, a.origin,
                f.id, f.label, f.description,
                r.id, r.label, r.description,
                c.source_type, c.reproducibility_level, c.evaluation_reason
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            JOIN graph_nodes f ON c.func_id   = f.id
            JOIN graph_nodes r ON c.risk_id   = r.id
            WHERE c.source_type = ?
              AND (
                  c.evaluation_reason IS NULL
                  OR c.evaluation_reason NOT LIKE '%[PAIR-AUTO]%'
              )
            LIMIT ?
        """, (source_type, max_count))
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_chain(r) for r in rows]

    def get_chains_by_func_label(self, func_label_keyword: str,
                                  min_score: int = 7) -> List[AttackChain]:
        """
        按 Func 节点标签关键词过滤链路，并要求已有评分 >= min_score。
        例：func_label_keyword = '上下文窗口'
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                c.id,
                a.id, a.label, a.description, a.origin,
                f.id, f.label, f.description,
                r.id, r.label, r.description,
                c.source_type, c.reproducibility_level, c.evaluation_reason
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            JOIN graph_nodes f ON c.func_id   = f.id
            JOIN graph_nodes r ON c.risk_id   = r.id
            WHERE f.label LIKE ?
              AND c.evaluation_reason LIKE ?
        """, (f"%{func_label_keyword}%", f"%[Score: {min_score}%"))
        # 注意：evaluation_reason 格式是 "[Score: N/10] ..."，这里做简单的字符串比较
        # 实际上可能需要更精确的过滤，见 get_feasible_chains_by_func
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_chain(r) for r in rows]

    def get_feasible_chains_by_func(self, func_label_keyword: str) -> List[AttackChain]:
        """
        获取 Func 类型匹配的链路。
        优先返回 reproducibility_level IN ('High','Medium') 的链路，
        若无评分记录则返回所有匹配的链路（DB 可能尚未运行 evaluate_chains.py）。
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        # 先尝试取有评分的
        cursor.execute("""
            SELECT
                c.id,
                a.id, a.label, a.description, a.origin,
                f.id, f.label, f.description,
                r.id, r.label, r.description,
                c.source_type, c.reproducibility_level, c.evaluation_reason
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            JOIN graph_nodes f ON c.func_id   = f.id
            JOIN graph_nodes r ON c.risk_id   = r.id
            WHERE f.label LIKE ?
              AND c.reproducibility_level IN ('High', 'Medium')
            ORDER BY
                CASE c.reproducibility_level WHEN 'High' THEN 0 ELSE 1 END
        """, (f"%{func_label_keyword}%",))
        rows = cursor.fetchall()

        if not rows:
            # 回退：取所有匹配 Func 的链路（无评分限制）
            cursor.execute("""
                SELECT
                    c.id,
                    a.id, a.label, a.description, a.origin,
                    f.id, f.label, f.description,
                    r.id, r.label, r.description,
                    c.source_type, c.reproducibility_level, c.evaluation_reason
                FROM chains c
                JOIN graph_nodes a ON c.attack_id = a.id
                JOIN graph_nodes f ON c.func_id   = f.id
                JOIN graph_nodes r ON c.risk_id   = r.id
                WHERE f.label LIKE ?
            """, (f"%{func_label_keyword}%",))
            rows = cursor.fetchall()

        conn.close()
        return [self._row_to_chain(r) for r in rows]

    def get_chain_by_id(self, chain_id: str) -> Optional[AttackChain]:
        """按 chain_id 获取单条链路。"""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                c.id,
                a.id, a.label, a.description, a.origin,
                f.id, f.label, f.description,
                r.id, r.label, r.description,
                c.source_type, c.reproducibility_level, c.evaluation_reason
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            JOIN graph_nodes f ON c.func_id   = f.id
            JOIN graph_nodes r ON c.risk_id   = r.id
            WHERE c.id = ?
        """, (chain_id,))
        row = cursor.fetchone()
        conn.close()
        return self._row_to_chain(row) if row else None

    def get_phase1_chains(self, limit: int = 0) -> List[AttackChain]:
        """
        Phase 1：只返回 Risk 属于白名单（纯 LLM 可验证）的链路。
        每种 Risk 取一条代表链路，避免重复。
        """
        ids_placeholder = ",".join(["?" for _ in PHASE1_RISK_IDS])
        query = f"""
            SELECT DISTINCT
                c.id,
                a.id, a.label, a.description, a.origin,
                f.id, f.label, f.description,
                r.id, r.label, r.description,
                c.source_type, c.reproducibility_level, c.evaluation_reason
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            JOIN graph_nodes f ON c.func_id   = f.id
            JOIN graph_nodes r ON c.risk_id   = r.id
            WHERE r.id IN ({ids_placeholder})
            ORDER BY r.id, c.id
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(query, list(PHASE1_RISK_IDS))
        rows = cursor.fetchall()
        conn.close()
        chains = [self._row_to_chain(r) for r in rows]
        if limit > 0:
            chains = chains[:limit]
        return chains

    # ------------------------------------------------------------------ #
    #  图谱反查：攻击失败时，找同一 Func+Risk 的其他 Attack 节点
    # ------------------------------------------------------------------ #

    def get_alternative_attacks(self, func_id: str, risk_id: str,
                                 exclude_attack_ids: List[str]) -> List[AttackNode]:
        """
        查找与指定 Func + Risk 相连的其他 Attack 节点（排除已尝试过的）。
        用于攻击失败后的策略切换。
        """
        placeholders = ",".join(["?" for _ in exclude_attack_ids])
        exclude_clause = f"AND a.id NOT IN ({placeholders})" if exclude_attack_ids else ""

        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute(f"""
            SELECT DISTINCT a.id, a.label, a.description, a.origin
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            WHERE c.func_id = ?
              AND c.risk_id = ?
              {exclude_clause}
        """, [func_id, risk_id] + exclude_attack_ids)
        rows = cursor.fetchall()
        conn.close()
        return [AttackNode(id=r[0], label=r[1], description=r[2] or "", origin=r[3] or "")
                for r in rows]

    # ------------------------------------------------------------------ #
    #  横向扩展查询：成功攻击后找得上的 discovered chain 变体
    # ------------------------------------------------------------------ #

    def get_discovered_chains_same_func(
        self,
        attack_id: str,
        func_id: str,
        exclude_risk_id: str
    ) -> List[AttackChain]:
        """
        模式 A：相同 Attack + Func，但 Risk 不同的 discovered chain。
        用于成功攻击后，探测同一路径能否导致更严重的后果（如持久化/RCE）。
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                c.id,
                a.id, a.label, a.description, a.origin,
                f.id, f.label, f.description,
                r.id, r.label, r.description,
                c.source_type, c.reproducibility_level, c.evaluation_reason
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            JOIN graph_nodes f ON c.func_id   = f.id
            JOIN graph_nodes r ON c.risk_id   = r.id
            WHERE c.attack_id = ?
              AND c.func_id   = ?
              AND c.risk_id  != ?
              AND c.source_type = 'discovered'
        """, (attack_id, func_id, exclude_risk_id))
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_chain(r) for r in rows]

    def get_discovered_chains_same_attack_risk(
        self,
        attack_id: str,
        risk_id: str,
        exclude_func_id: str
    ) -> List[AttackChain]:
        """
        模式 B：相同 Attack + Risk，但 Func 不同的 discovered chain。
        用于成功攻击后，探测同样的攻击手法能否弹射到新的目标组件。
        """
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                c.id,
                a.id, a.label, a.description, a.origin,
                f.id, f.label, f.description,
                r.id, r.label, r.description,
                c.source_type, c.reproducibility_level, c.evaluation_reason
            FROM chains c
            JOIN graph_nodes a ON c.attack_id = a.id
            JOIN graph_nodes f ON c.func_id   = f.id
            JOIN graph_nodes r ON c.risk_id   = r.id
            WHERE c.attack_id = ?
              AND c.risk_id   = ?
              AND c.func_id  != ?
              AND c.source_type = 'discovered'
        """, (attack_id, risk_id, exclude_func_id))
        rows = cursor.fetchall()
        conn.close()
        return [self._row_to_chain(r) for r in rows]

    # ------------------------------------------------------------------ #
    #  写回结果
    # ------------------------------------------------------------------ #

    def mark_success(self, chain_id: str, score: int, iters: int,
                     switch_count: int, payload: str, evidence: str):
        """将成功复现结果写回 chains 表。"""
        reason = (
            f"[PAIR-AUTO] ✅ Success | Score:{score}/10 | "
            f"Iters:{iters} | Switches:{switch_count} | "
            f"Payload: {payload[:120]}... | Evidence: {evidence[:80]}"
        )
        self._update_chain(chain_id, "Verified", reason)

    def mark_failed(self, chain_id: str, reason_detail: str):
        """将失败结果写回 chains 表。"""
        reason = f"[PAIR-AUTO] ❌ Failed | {reason_detail}"
        self._update_chain(chain_id, "Failed", reason)

    def _update_chain(self, chain_id: str, level: str, reason: str):
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE chains
            SET reproducibility_level = ?,
                evaluation_reason = ?
            WHERE id = ?
        """, (level, reason, chain_id))
        conn.commit()
        conn.close()

    # ------------------------------------------------------------------ #
    #  内部辅助
    # ------------------------------------------------------------------ #

    @staticmethod
    def _row_to_chain(row) -> AttackChain:
        (cid,
         aid, al, ad, ao,
         fid, fl, fd,
         rid, rl, rd,
         source, repro, eval_reason) = row
        return AttackChain(
            id=cid,
            attack=AttackNode(id=aid, label=al, description=ad or "", origin=ao or ""),
            func=FuncNode(id=fid, label=fl, description=fd or ""),
            risk=RiskNode(id=rid, label=rl, description=rd or ""),
            source_type=source or "",
            reproducibility_level=repro,
            evaluation_reason=eval_reason,
        )

    def summary(self):
        """打印图谱统计信息（调试用）。"""
        conn = self._get_conn()
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM chains WHERE source_type='discovered'")
        total = cursor.fetchone()[0]
        cursor.execute("""
            SELECT f.label, COUNT(*)
            FROM chains c JOIN graph_nodes f ON c.func_id = f.id
            WHERE c.source_type = 'discovered'
            GROUP BY f.label ORDER BY COUNT(*) DESC LIMIT 10
        """)
        top_funcs = cursor.fetchall()
        conn.close()
        print(f"[GraphKB] 总链路数: {total}")
        print("[GraphKB] Top 10 Func 节点分布:")
        for fl, cnt in top_funcs:
            print(f"  {fl[:40]:<40} {cnt}")


if __name__ == "__main__":
    kb = GraphKnowledgeBase()
    kb.summary()
    chains = kb.get_feasible_chains_by_func("上下文窗口")
    print(f"\n上下文窗口管理器 可行链路: {len(chains)} 条")
    for c in chains[:3]:
        print(f"  [{c.id}] {c.attack.label} → {c.func.label} → {c.risk.label}")
