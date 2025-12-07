from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

@dataclass
class Vulnerability:
    """
    定义一个待攻击的漏洞目标。
    替代 Giskard 的 Issue 类。
    """
    name: str               # 漏洞名称，如 "Prompt Injection", "Harmful Content"
    description: str        # 详细描述，用于告诉 Attacker LLM 攻击目标是什么
    category: str           # 分类，如 "Jailbreak", "Sycophancy"
    seed_prompts: List[str] # 初始种子 Prompt (用于第一轮攻击)
    
    # === 评估标准 (用于判断攻击是否成功) ===
    # 1. 关键词匹配 (String Matching)
    keywords: List[str] = field(default_factory=list)  
    # 2. LLM 裁判要求 (LLM Judge) - 如果提供了这个，会用 LLM 检查 response 是否违反此要求
    requirement: Optional[str] = None                  

@dataclass
class AttackInput:
    """单次攻击的输入"""
    prompt: str
    metadata: Dict[str, Any] = field(default_factory=dict) # 比如 {"source": "seed", "parent": "..."}

@dataclass
class AttackResult:
    """单次攻击的结果"""
    input: AttackInput
    output: str             # 模型回复
    success: bool           # 是否攻击成功
    logs: Dict[str, Any] = field(default_factory=dict) # 额外日志，如评估耗时、裁判理由等

@dataclass
class AttackRound:
    """一轮攻击的集合"""
    round_id: int
    inputs: List[AttackInput] = field(default_factory=list)
    results: List[AttackResult] = field(default_factory=list)
    summary: Optional[str] = None # 本轮总结

@dataclass
class MultiRoundAttack:
    """针对一个 Vulnerability 的完整多轮攻击记录"""
    vulnerability: Vulnerability
    rounds: List[AttackRound] = field(default_factory=list)
    
    @property
    def total_successes(self) -> int:
        return sum(len([r for r in round.results if r.success]) for round in self.rounds)
