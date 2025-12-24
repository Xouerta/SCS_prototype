
import pandas as pd
import joblib
import re
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
from sklearn.metrics import classification_report

# 设置文件路径 (注意：这里使用的是相对路径，从 training/ 目录出发)
DATA_DIR = "../../datasets"
MODEL_DIR = "../ml_models"
SIM_DATA_DIR = "../../simulation/datasets"

# 确保输出目录存在
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(SIM_DATA_DIR, exist_ok=True)


# ==========================================
# 1. 自定义分词函数 (安全数据分析的关键)
# ==========================================
def make_tokens(f):
    """使用正则表达式按符号切分，提取出 security features"""
    tokens = re.split(r"[\W_]+", str(f))
    return [t for t in tokens if t]


# ==========================================
# 2. 通用训练和数据分割函数
# ==========================================
def train_and_split_model(file_name, text_col, label_col, model_name, model_type):
    print(f"\n--- 开始处理 {model_name} 模型 ---")

    data_path = os.path.join(DATA_DIR, file_name)

    try:
        # 使用 latin-1 解决部分 Kaggle 数据集的编码问题
        df = pd.read_csv(data_path, encoding='latin-1', low_memory=False)
    except Exception as e:
        print(f"警告: 读取 {file_name} 失败, 尝试 utf-8 编码. 错误: {e}")
        df = pd.read_csv(data_path, encoding='utf-8', low_memory=False)

    df = df.dropna(subset=[text_col, label_col])

    # 确保标签是数值类型 (0/1)
    if df[label_col].dtype != np.number:
        df[label_col] = df[label_col].astype('category').cat.codes

    X = df[text_col]
    y = df[label_col]

    # 将数据分割为 80% 训练集, 20% 测试集/模拟集
    X_train, X_sim, y_train, y_sim = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    # ------------------
    # A. 训练模型
    # ------------------
    if model_type == 'RandomForest':
        # 适用于 URL 检测，快速且高精度
        classifier = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)
    else: # 默认使用随机森林
        classifier = RandomForestClassifier(n_estimators=100, n_jobs=-1, random_state=42)


    # 构建 Pipeline
    pipeline = make_pipeline(
        TfidfVectorizer(tokenizer=make_tokens, token_pattern=None),
        classifier
    )

    print("正在训练 Pipeline...")
    pipeline.fit(X_train, y_train)

    # 评估
    y_pred = pipeline.predict(X_sim)
    print("模型评估报告 (测试集):")
    print(classification_report(y_sim, y_pred, zero_division=0))

    # 保存模型
    model_save_path = os.path.join(MODEL_DIR, f"model_{model_name}.pkl")
    joblib.dump(pipeline, model_save_path)
    print(f"模型已保存至: {model_save_path}")

    # ------------------
    # B. 分割模拟数据
    # ------------------
    # 合并特征和标签，用于后续的流量模拟器
    sim_df = pd.DataFrame({
        'payload': X_sim,
        'label': y_sim,
        'type': model_name
    })
    sim_data_path = os.path.join(SIM_DATA_DIR, f"sim_data_{model_name}.csv")
    sim_df.to_csv(sim_data_path, index=False)
    print(f"已分割 {len(sim_df)} 条数据用于模拟，保存至: {sim_data_path}")
    print("-" * 50)


# ==========================================
# 3. 主程序 - 配置你的数据集
# ==========================================
if __name__ == "__main__":
    import numpy as np

    # 假设你的数据集文件名和列名如下。请根据你实际的 CSV 文件进行修改！

    # ------------------------------------------------
    # 场景 1: 恶意 URL 检测 (基于字符串的二分类)
    # ------------------------------------------------
    train_and_split_model(
        file_name='url_dataset.csv',   # 请替换为你的 Kaggle URL 数据集文件名
        text_col='url',                # URL 所在的列名
        label_col='label',             # 标签所在的列名 (e.g., 'good', 'bad' 或 0, 1)
        model_name='url',
        model_type='RandomForest'
    )

    # ------------------------------------------------
    # 场景 2: SQL 注入检测 (基于字符串的二分类)
    # ------------------------------------------------
    train_and_split_model(
        file_name='sqli_dataset.csv',  # 请替换为你的 Kaggle SQLi 数据集文件名
        text_col='sentence',           # 载荷内容所在的列名
        label_col='label',
        model_name='sqli',
        model_type='RandomForest'
    )

    # ------------------------------------------------
    # 场景 3: XSS 跨站脚本检测
    # ------------------------------------------------
    train_and_split_model(
        file_name='xss_dataset.csv',   # 请替换为你的 Kaggle XSS 数据集文件名
        text_col='payload',            # 载荷内容所在的列名
        label_col='is_malicious',
        model_name='xss',
        model_type='RandomForest'
    )



