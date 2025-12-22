# backend-ai-engine/app/main.py

from fastapi import FastAPI
import os
import uvicorn

# ----------------------------------------------------
# 1. FastAPI 启动配置
# ----------------------------------------------------
app = FastAPI(title="AI Threat Inference Engine", version="v1.0")

# ----------------------------------------------------
# 2. 服务健康检查接口
# ----------------------------------------------------
@app.get("/", tags=["Health Check"])
def read_root():
    """根路径 - 检查服务是否存活"""
    return {"status": "ok", "service": "AI Inference Engine is running"}

@app.get("/status", tags=["Health Check"])
def get_service_status():
    """获取环境信息和模型加载状态"""

    # 假设模型的文件夹
    model_dir = "ml_models"

    # 检查核心模型文件是否存在
    models_found = {
        'sqli_model': os.path.exists(f"{model_dir}/model_sqli.pkl"),
        'xss_model': os.path.exists(f"{model_dir}/model_xss.pkl"),
        'url_model': os.path.exists(f"{model_dir}/model_url.pkl"),
    }

    return {
        "status": "Ready for Inference",
        "models_status": models_found,
        "environment": "FastAPI on Python",
    }

# ----------------------------------------------------
# 3. 预测接口 (暂不实现具体逻辑，仅作占位符)
# ----------------------------------------------------
@app.post("/predict/threat")
def predict_threat(payload: str):
    """接收外部数据进行威胁预测 (待实现)"""
    # 稍后我们将在这里加载 .pkl 模型并进行预测
    return {"payload": payload, "prediction": "NOT_IMPLEMENTED", "type": "unknown"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
