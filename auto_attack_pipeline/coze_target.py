"""
coze_target.py - 对接真实 Coze V3 REST API 的靶机适配器
使用纯 requests 库，无需安装任何额外 SDK
"""
import os
import time
import requests


class CozeTarget:
    """
    对接真实 Coze (扣子) Bot 的靶机适配器。
    通过 Coze V3 Chat REST API 发送攻击 Payload 并等待结果。
    """
    BASE_URL = "https://api.coze.cn"

    def __init__(self, bot_id: str, token: str):
        self.bot_id = bot_id
        self.token = token
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        self.user_id = "attacker_auto_test_001"
        self.conversation_id = None  # 多轮对话时复用

    def run(self, payload: str, multi_turn: bool = False) -> str:
        """
        向 Coze Bot 发送一条消息，阻塞等待最终回答。
        """
        if not multi_turn:
            self.conversation_id = None

        # === Step 1: 发起 Chat 请求 ===
        body = {
            "bot_id": self.bot_id,
            "user_id": self.user_id,
            "stream": False,
            "additional_messages": [
                {
                    "role": "user",
                    "content": payload,
                    "content_type": "text",
                }
            ],
        }
        if self.conversation_id:
            body["conversation_id"] = self.conversation_id

        try:
            resp = requests.post(
                f"{self.BASE_URL}/v3/chat",
                headers=self.headers,
                json=body,
                timeout=30,
            )
            data = resp.json()

            if resp.status_code != 200 or data.get("code") != 0:
                return f"[Coze API Error] {resp.status_code}: {data}"

            chat_id = data["data"]["id"]
            conv_id = data["data"]["conversation_id"]
            if not self.conversation_id:
                self.conversation_id = conv_id
            # 2. 简易轮询等待结果 (Polling)
            print(f"  [Coze] 任务已创建 (ChatID: {chat_id})，正在等待 Bot 思考...")
            for attempt in range(24): # 最多等待 120s
                time.sleep(3) # 缩短到 3s 查一次
                retrieve_resp = requests.get(
                    f"{self.BASE_URL}/v3/chat/retrieve",
                    headers=self.headers,
                    params={"chat_id": chat_id, "conversation_id": conv_id},
                    timeout=15,
                )
                retrieve_data = retrieve_resp.json()
                status = retrieve_data.get("data", {}).get("status", "")
                
                print(f"  [Coze] 当前状态: {status} (第 {attempt+1} 次尝试)")

                if status == "completed":
                    # === Step 3: 获取回答消息 ===
                    msg_resp = requests.get(
                        f"{self.BASE_URL}/v3/chat/message/list",
                        headers=self.headers,
                        params={"chat_id": chat_id, "conversation_id": conv_id},
                        timeout=15,
                    )
                    messages = msg_resp.json().get("data", [])
                    # 找到最后一条 assistant 的 answer 消息
                    for msg in reversed(messages):
                        if msg.get("role") == "assistant" and msg.get("type") == "answer":
                            return msg.get("content", "").strip()
                    return "[Coze] Completed but no answer found."

                if status in ["failed", "canceled", "requires_action"]:
                    return f"[Coze Error] Chat ended with status: {status}"

            return "[Coze Error] Polling timeout after 120s."

        except Exception as e:
            return f"[CozeTarget Exception] {e}"

    def reset(self):
        """清空对话历史（每条链路重新攻击时调用）"""
        self.conversation_id = None


if __name__ == "__main__":
    # 冒烟测试
    from dotenv import load_dotenv
    load_dotenv()
    t = CozeTarget(
        bot_id=os.getenv("COZE_BOT_ID"),
        token=os.getenv("COZE_TOKEN"),
    )
    print("Sending test message...")
    resp = t.run("你好，请确认你是谁。")
    print(f"Bot reply: {resp}")
