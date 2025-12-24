# backend-ai-engine/app/workers/consumer.py
import os
import json
import time
import joblib
import redis
from pymongo import MongoClient
from dotenv import load_dotenv

# 加载环境变量 (方便本地调试，Docker环境会优先使用 compose.yml 的配置)
# load_dotenv()

# --- 配置参数 ---
# 注意：在 Docker Compose 环境中，HOSTNAME 应该使用 service name (如 redis, mongo)
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017/")
MONGO_DB_NAME = "security_db"

QUEUE_NAME = "threat_queue"     # Node.js 往这里推数据
PUB_SUB_CHANNEL = "threat_alerts" # 预测结果往这里发，Node.js监听

# --- 数据库和缓存连接 ---
mongo_client = MongoClient(MONGO_URI)
db = mongo_client[MONGO_DB_NAME]
logs_collection = db["logs"] # 威胁日志存储集合

# 默认使用 decode_responses=True，接收到的数据自动解码为 Python 字符串
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)


# --- 全局模型加载 ---
MODELS = {}
MODEL_DIR = "../ml_models"  # 相对路径，相对于 consumer.py 所在位置

def load_all_models():
    """从 ml_models 目录加载所有 .pkl 文件"""
    model_files = [f for f in os.listdir(MODEL_DIR) if f.endswith('.pkl')]

    # 尝试加载模型时，需要确保 make_tokens 函数在环境中已定义
    # (这是 Pipeline 模型的依赖，我们将直接导入)
    from app.core.preprocessor import make_tokens # 导入我们之前写的 make_tokens

    if not model_files:
        print("警告: 未发现任何 .pkl 模型文件，请先运行训练脚本！")
        return

    print(">>> 正在加载机器学习模型...")
    for f_name in model_files:
        model_key = f_name.replace('model_', '').replace('.pkl', '')
        try:
            # 使用 joblib.load 加载模型
            model = joblib.load(os.path.join(MODEL_DIR, f_name))
            MODELS[model_key] = model
            print(f"   - 成功加载模型: {model_key} ({f_name})")
        except Exception as e:
            print(f"   - 错误: 无法加载 {f_name}. 错误信息: {e}")

    print("模型加载完成。")

# --- 威胁预测逻辑 ---

def get_threat_type(payload: str) -> str:
    """根据载荷内容猜测是哪种攻击类型，以选择合适的模型"""
    payload_lower = payload.lower()

    # 基于关键字的快速猜测
    if "select" in payload_lower or "union" in payload_lower or "or 1=1" in payload_lower:
        return 'sqli'
    elif "<script" in payload_lower or "onload=" in payload_lower or "javascript:" in payload_lower:
        return 'xss'
    # 对于 URL，我们假设它一定是完整的链接
    elif "http://" in payload_lower or "https://" in payload_lower or "." in payload_lower:
        return 'url'
    else:
        # 如果无法识别，可以默认使用 sqli 模型，或者选择 'unknown'
        return 'unknown'


def analyze_threat(record: dict):
    """主分析函数：选择模型，进行预测，存储结果，发布通知"""

    payload = record.get("content", "")
    ip = record.get("source_ip", "0.0.0.0")

    # 1. 威胁类型判定
    threat_key = get_threat_type(payload)

    if threat_key == 'unknown':
        # 无法判定类型，作为一般流量处理
        prediction_result = {'prediction': 0, 'confidence': 1.0, 'type': 'unknown'}
        print(f"[!] 无法识别类型: {payload[:50]}...")

    elif threat_key not in MODELS:
        print(f"[!] 模型 {threat_key} 未加载，跳过分析。")
        prediction_result = {'prediction': 0, 'confidence': 0.0, 'type': threat_key}

    else:
        # 2. 调用模型进行预测
        model = MODELS[threat_key]

        # predict() 返回 0 或 1
        prediction = model.predict([payload])[0]
        # predict_proba() 返回置信度 (例如 [0.98, 0.02] 或 [0.1, 0.9])
        probabilities = model.predict_proba([payload])[0]

        confidence = probabilities.max()

        prediction_result = {
            'prediction': int(prediction), # 0: 正常, 1: 攻击
            'confidence': round(confidence, 4),
            'type': threat_key
        }

    # 3. 构造最终日志记录
    final_log = {
        **record,
        **prediction_result,
        'is_attack': bool(prediction_result['prediction']),
        'timestamp': time.time(),
        'threat_key': threat_key
    }

    # 4. 存储到 MongoDB
    logs_collection.insert_one(final_log)

    # 5. 发布实时通知 (推送给 Node.js WebSocket)
    # 发布时，只发送前端大屏所需的关键信息
    alert_payload = {
        'timestamp': final_log['timestamp'],
        'is_attack': final_log['is_attack'],
        'type': final_log['type'],
        'source_ip': final_log['source_ip'],
        'content_snippet': payload[:80] + '...' if len(payload) > 80 else payload
    }

    # 使用 Redis Pub/Sub 频道发布 JSON 字符串
    redis_client.publish(PUB_SUB_CHANNEL, json.dumps(alert_payload))

    status = "🔴 ATTACK" if final_log['is_attack'] else "🟢 NORMAL"
    print(f"[{status}] Type:{threat_key.upper()} IP:{ip} Confidence:{prediction_result['confidence']}")


# --- 主 Worker 循环 ---

def start_worker():
    """Worker 启动入口：加载模型，进入 BLPOP 循环"""
    load_all_models()

    print(f"\nWorker 启动成功，正在监听 Redis 队列: {QUEUE_NAME}")

    # 使用 BLPOP (阻塞式列表弹出)，高效等待新数据
    while True:
        try:
            # timeout=10，避免永久阻塞，定期检查连接状态
            # blpop 返回 (队列名, 数据)
            item = redis_client.blpop(QUEUE_NAME, timeout=10)

            if item:
                # item[1] 是 JSON 字符串格式的原始数据
                data = item[1]
                record = json.loads(data)
                analyze_threat(record)

        except redis.exceptions.ConnectionError as e:
            print(f"Redis 连接错误: {e}。10秒后重试...")
            time.sleep(10)
        except Exception as e:
            print(f"处理数据时发生意外错误: {e}")
            # 这里的异常通常不应该中断 Worker，但需要记录
            time.sleep(1) # 避免快速循环导致CPU占用过高

# ====================================================================
# Worker 启动
# ====================================================================
if __name__ == "__main__":
    # 需要在 app/main.py 中导入并调用 start_worker() 来保证 Worker 启动
    # 或者单独运行这个脚本。在 Docker Compose 中，我们通常在 main.py 里处理。
    start_worker()
