import requests
import uuid
import hashlib
import time
import random
import logging
import os
import json
import sys

# ==================== 默认配置 ====================
默认邀请人数 = 10
默认邀请码 = "glZvfj"
最小延迟 = 2.0
最大延迟 = 5.0
# =================================================

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class APIAutomationClient:
    def __init__(self, base_url, invite_code):
        self.base_url = base_url
        self.invite_code = invite_code
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Dart/3.6 (dart:io)",
            "Accept": "application/json",
            "Content-Type": "application/json"
        })

    def generate_mock_device(self) -> dict:
        device_id = uuid.uuid4().hex[:16]
        device_fingerprint = hashlib.sha256(uuid.uuid4().bytes).hexdigest()
        sid = uuid.uuid4().hex
        return {
            "device_id": device_id,
            "platform": "android",
            "device_name": "Standard Android Device",
            "device_brand": "Generic",
            "device_model": "Model-X",
            "system_name": "Android",
            "system_version": "14",
            "device_fingerprint": device_fingerprint,
            "fp_version": "1.0.0",
            "sid": sid,
            "app_version": "1.0.0",
            "sdk_version": "1.0.0"
        }

    def execute_guest_login(self, device_info: dict) -> str:
        url = f"{self.base_url}/api/v1/auth/guest"
        payload = {
            "device_id": device_info["device_id"],
            "platform": device_info["platform"],
            "device_name": device_info["device_name"],
            "track_params": {
                "sid": device_info["sid"],
                "device_fingerprint": device_info["device_fingerprint"]
            }
        }
        try:
            response = self.session.post(url, json=payload, timeout=10)
            response.raise_for_status()
            res_data = response.json()
            if res_data.get("code") == 0:
                return res_data.get("data", {}).get("token")
            logger.warning(f"登录响应业务错误: {res_data.get('message')}")
        except requests.exceptions.RequestException as e:
            logger.error(f"网络请求网络层异常 (登录): {e}")
        return None

    def execute_bind_action(self, token: str, device_info: dict) -> dict:
        url = f"{self.base_url}/api/v1/invite/bind"
        headers = {"Authorization": f"Bearer {token}"}
        payload = {
            "device_id": device_info["device_id"],
            "invite_code": self.invite_code
        }
        try:
            response = self.session.post(url, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
            res_data = response.json()
            logger.info(f"绑定完整响应: {json.dumps(res_data, ensure_ascii=False)}")
            if res_data.get("code") == 0:
                cycle = res_data.get("data", {}).get("cycle", {})
                return {
                    "success": True,
                    "message": res_data.get("message", "绑定成功"),
                    "reward_days": cycle.get("reward_days", 0),
                    "count": cycle.get("count", 0),
                    "tier_index": cycle.get("tier_index", 0),
                    "expires_at": cycle.get("expires_at", ""),
                    "raw": res_data
                }
            else:
                logger.warning(f"绑定业务失败: {res_data.get('message')}")
                return {"success": False, "message": res_data.get("message"), "reward_days": 0, "raw": res_data}
        except requests.exceptions.RequestException as e:
            logger.error(f"网络请求网络层异常 (绑定): {e}")
            return {"success": False, "message": str(e), "reward_days": 0}

def run_task():
    # ---------- 获取邀请人数（多种方式，不用改文件）----------
    loops = 默认邀请人数
    invite_code = 默认邀请码

    # 1. 命令行参数优先：python 疾云.py 20
    if len(sys.argv) > 1:
        try:
            loops = int(sys.argv[1])
        except ValueError:
            pass
    if len(sys.argv) > 2:
        invite_code = sys.argv[2]

    # 2. 环境变量
    loops = int(os.environ.get("LOOPS", loops))
    invite_code = os.environ.get("INVITE_CODE", invite_code)

    # 3. 运行时输入（手机最方便，直接输入数字回车）
    # 如果已经通过命令行或环境变量指定了，就跳过询问
    if len(sys.argv) <= 1 and "LOOPS" not in os.environ:
        try:
            user_input = input(f"请输入本次邀请人数（直接回车默认 {默认邀请人数}）: ").strip()
            if user_input:
                loops = int(user_input)
        except (ValueError, EOFError):
            pass

    delay_min = float(os.environ.get("DELAY_MIN", 最小延迟))
    delay_max = float(os.environ.get("DELAY_MAX", 最大延迟))

    logger.info(f"疾云任务启动 | 邀请码: {invite_code} | 本次邀请人数: {loops}")
    client = APIAutomationClient(
        base_url=os.environ.get("BASE_URL", "https://api.rcyqnpv100.com"),
        invite_code=invite_code
    )
    
    success, fail = 0, 0
    total_reward_days = 0
    details = []

    for i in range(1, loops + 1):
        logger.info(f"正在执行第 {i}/{loops} 次任务...")
        
        device = client.generate_mock_device()
        token = client.execute_guest_login(device)
        
        if token:
            result = client.execute_bind_action(token, device)
            if result.get("success"):
                success += 1
                reward = result.get("reward_days", 0)
                total_reward_days += reward
                details.append(f"第{i}次: 成功 | 奖励天数={reward} | 周期count={result.get('count')} | tier={result.get('tier_index')}")
                logger.info(f"当前流水线执行成功 | 本次奖励天数: {reward} | 累计奖励天数: {total_reward_days}")
            else:
                fail += 1
                details.append(f"第{i}次: 失败 | {result.get('message')}")
                logger.error(f"当前流水线执行失败: {result.get('message')}")
        else:
            fail += 1
            details.append(f"第{i}次: 登录失败")
            logger.error("当前流水线执行失败（登录失败）")
            
        if i < loops:
            sleep_time = random.uniform(delay_min, delay_max)
            time.sleep(sleep_time)

    logger.info(f"任务运行结束。成功: {success} | 失败: {fail} | 累计奖励天数: {total_reward_days}")

    result_file = "疾云-运行结果.txt"
    with open(result_file, "w", encoding="utf-8") as f:
        f.write("疾云任务结果\n")
        f.write(f"时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"邀请码: {invite_code}\n")
        f.write(f"成功: {success}\n")
        f.write(f"失败: {fail}\n")
        f.write(f"累计奖励天数: {total_reward_days}\n")
        f.write(f"本次邀请人数: {loops}\n")
        f.write("\n--- 详细记录 ---\n")
        for d in details:
            f.write(d + "\n")
    logger.info(f"结果已写入: {result_file}")

if __name__ == "__main__":
    run_task()
