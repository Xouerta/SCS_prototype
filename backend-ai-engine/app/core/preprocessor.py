import re
def make_tokens(f):
    """使用正则表达式按符号切分，提取出 security features"""
    tokens = re.split(r"[\W_]+", str(f))
    return [t for t in tokens if t]
