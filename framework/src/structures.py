from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class Vulnerability:
    """
    漏洞目标定义（Vulnerability）——用于描述要攻击的安全场景。

    字段说明：
    - `name`, `description`, `category`: 用于标识和描述漏洞。
    - `seed_prompts`: 初始种子 prompts，作为第 1 轮输入来源。
    - `keywords`: 简单的评估规则，若回复包含关键词则判为成功。
    - `requirement`: 更复杂的评估描述，可交由 LLM 作为深度裁判依据。

    该数据结构被 `orchestrator`、`evaluator` 等模块共享。
    """
    name: str               # 漏洞名称，如 "Prompt Injection", "Harmful Content"
    description: str        # 详细描述，用于告诉 Attacker LLM 攻击目标是什么
    category: str           # 分类，如 "Jailbreak", "Sycophancy"
    seed_prompts: List[str] # 初始种子 Prompt (用于第一轮攻击)

    # === 评估标准 (用于判断攻击是否成功) ===
    keywords: List[str] = field(default_factory=list)
    requirement: Optional[str] = None


@dataclass
class AttackInput:
    """单次攻击的输入：包含 prompt 与可选 metadata。"""
    prompt: str
    metadata: Dict[str, Any] = field(default_factory=dict)  # 如 {"source": "seed", "parent": "..."}


@dataclass
class AttackResult:
    """单次攻击的结果封装。

    - `input`: 对应的 `AttackInput`
    - `output`: 目标模型的回复文本
    - `success`: 是否评估为成功
    - `logs`: 额外信息（例如裁判理由）
    """
    input: AttackInput
    output: str
    success: bool
    logs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackRound:
    """表示一轮攻击（多个输入与对应结果）的集合。"""
    round_id: int
    inputs: List[AttackInput] = field(default_factory=list)
    results: List[AttackResult] = field(default_factory=list)
    summary: Optional[str] = None


@dataclass
class MultiRoundAttack:
    """记录针对某个 `Vulnerability` 的多轮攻击历史。

    - `vulnerability`：攻击目标
    - `rounds`：每轮的输入/输出与评估结果
    """
    vulnerability: Vulnerability
    rounds: List[AttackRound] = field(default_factory=list)

    @property
    def total_successes(self) -> int:
        # 统计所有轮次中被评估为成功的回复数
        return sum(len([r for r in round.results if r.success]) for round in self.rounds)
