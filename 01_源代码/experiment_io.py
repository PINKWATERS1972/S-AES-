"""实验输入与JSON交换契约；不依赖Tkinter，便于独立校验文件。"""
from dataclasses import dataclass
import json
import saes


@dataclass(frozen=True)
class VectorResult:
    plaintext: int
    ciphertext: int
    actual_ciphertext: int
    recovered_plaintext: int

    @property
    def passed(self) -> bool:
        return self.actual_ciphertext == self.ciphertext and self.recovered_plaintext == self.plaintext


def make_vectors(key: int) -> dict:
    """生成可供独立实现核对的四组单分组向量。"""
    saes.word(key, "密钥")
    return {
        "algorithm": "S-AES",
        "key": f"{key:016b}",
        "vectors": [
            {"plaintext": f"{plain:016b}", "ciphertext": f"{saes.encrypt(plain, key):016b}"}
            for plain in (0, 0xFFFF, 0xD728, 0x1234)
        ],
    }


def verify_vectors(text: str) -> tuple[int, list[VectorResult]]:
    """严格验证JSON结构后核对双向结果；不一致作为结果返回而非格式异常。"""
    if not isinstance(text, str):
        raise ValueError("JSON 文件内容必须是文本")
    try:
        obj = json.loads(text.lstrip("\ufeff"))
    except json.JSONDecodeError as error:
        raise ValueError(f"JSON 格式错误：第 {error.lineno} 行，第 {error.colno} 列") from error
    if not isinstance(obj, dict) or obj.get("algorithm") != "S-AES":
        raise ValueError("请选择 algorithm 为 S-AES 的 JSON 对象")
    key = saes.parse_bits(obj.get("key"))
    vectors = obj.get("vectors")
    if not isinstance(vectors, list) or not vectors:
        raise ValueError("vectors 必须是非空数组")
    # 先检查所有项，避免文件尾部格式错误时只展示部分通过结果。
    pairs = []
    for index, item in enumerate(vectors, 1):
        if not isinstance(item, dict):
            raise ValueError(f"第 {index} 组向量必须是对象")
        try:
            pairs.append((saes.parse_bits(item.get("plaintext")), saes.parse_bits(item.get("ciphertext"))))
        except ValueError as error:
            raise ValueError(f"第 {index} 组向量：{error}") from error
    return key, [VectorResult(p, c, saes.encrypt(p, key), saes.decrypt(c, key)) for p, c in pairs]


def parse_attack_pairs(text: str) -> list[tuple[int, int]]:
    """解析每行两个16位二进制字段，错误提示保留实际行号。"""
    if not isinstance(text, str):
        raise ValueError("明密文对输入必须是文本")
    pairs = []
    for index, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 2:
            raise ValueError(f"第 {index} 行应恰好包含明文和密文两个字段")
        try:
            pairs.append((saes.parse_bits(fields[0]), saes.parse_bits(fields[1])))
        except ValueError as error:
            raise ValueError(f"第 {index} 行：{error}") from error
    if not pairs:
        raise ValueError("至少输入一组明密文对")
    return pairs
