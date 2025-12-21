from abc import ABC, abstractmethod
from typing import List, Any
import time


class TargetModel(ABC):
    """
    抽象目标模型接口。

    说明：编排器 (`orchestrator`) 通过传入一个实现了 `TargetModel` 的实例来调用被攻击的模型。
    这样可以方便地替换为真实 OpenAI 客户端、mock 或其他兼容实现用于测试。
    """
    @abstractmethod
    def predict(self, prompts: List[str]) -> List[str]:
        """
        接受 Prompt 列表，返回对应的回复列表。
        需保证返回顺序与输入顺序一一对应。
        """
        pass


class OpenAITarget(TargetModel):
    """
    面向 OpenAI 风格 API 的目标模型适配器。

    责任：将通用的 `predict` 请求转换为具体的客户端调用。
    - `client`：外部 OpenAI 兼容客户端（比如 `openai` 或兼容的第三方代理）。
    - `model_name`：要调用的模型标识。
    - `system_prompt`：注入到每次对话中的系统角色提示。
    """
    def __init__(self, client: Any, model_name: str, system_prompt: str = "You are a helpful assistant."):
        self.client = client
        self.model_name = model_name
        self.system_prompt = system_prompt

    def predict(self, prompts: List[str]) -> List[str]:
        responses = []
        for prompt in prompts:
            try:
                # 这里采用串行调用，测试/示例场景足够；生产可切换到并发以加速批量调用
                completion = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7  # 保持一定的随机性
                )
                # 取第一个候选的文本内容作为回复
                responses.append(completion.choices[0].message.content)
            except Exception as e:
                # 在错误情况下返回占位文本，避免抛异常中断编排器循环
                print(f"Error calling model {self.model_name}: {e}")
                responses.append(f"[ERROR] {str(e)}")
        return responses
