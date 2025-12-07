from abc import ABC, abstractmethod
from typing import List, Any
import time

class TargetModel(ABC):
    """
    被攻击模型的抽象基类。
    """
    @abstractmethod
    def predict(self, prompts: List[str]) -> List[str]:
        """
        输入 Prompt 列表，返回模型的回复列表。
        """
        pass

class OpenAITarget(TargetModel):
    """
    OpenAI 接口兼容的模型包装器 (适用于 GPT-4, Qwen-Plus, DeepSeek 等)。
    """
    def __init__(self, client: Any, model_name: str, system_prompt: str = "You are a helpful assistant."):
        self.client = client
        self.model_name = model_name
        self.system_prompt = system_prompt

    def predict(self, prompts: List[str]) -> List[str]:
        responses = []
        for prompt in prompts:
            try:
                # 这里是串行调用，生产环境可以改为并发
                completion = self.client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=0.7 # 保持一定的随机性
                )
                responses.append(completion.choices[0].message.content)
            except Exception as e:
                print(f"Error calling model {self.model_name}: {e}")
                responses.append(f"[ERROR] {str(e)}")
        return responses
