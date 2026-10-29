"""教学用 Simplified AES：16 位分组、16 位密钥，GF(2^4) 模多项式 x^4+x+1。"""
from functools import lru_cache
import secrets
from collections.abc import Callable, Iterable

SBOX = (9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7)
INV_SBOX = tuple(SBOX.index(i) for i in range(16))


def word(value: int, name: str = "数据") -> int:
    """验证16位整数；拒绝bool及超出范围的数据，不截断输入。"""
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name}必须是 0～65535 的整数")
    return value


def parse_bits(text: str, length: int = 16) -> int:
    """去除空白后解析固定长度的二进制文本。"""
    if not isinstance(text, str):
        raise ValueError("二进制输入必须是字符串")
    if not isinstance(length, int) or isinstance(length, bool) or length <= 0:
        raise ValueError("二进制位数必须是正整数")
    text = "".join(text.split())
    if len(text) != length or any(c not in "01" for c in text):
        raise ValueError(f"请输入恰好 {length} 位二进制数（只含 0、1，可含空格）")
    return int(text, 2)


def gf_mul(left, right):
    result = 0
    for _ in range(4):
        if right & 1:
            result ^= left
        left <<= 1
        if left & 0x10:
            left ^= 0x13
        right >>= 1
    return result & 15


def substitute(block, box=SBOX):
    return sum(box[(block >> shift) & 15] << shift for shift in (12, 8, 4, 0))


def shift_rows(block):
    # 列优先状态 [[n0,n2],[n1,n3]]；第二行交换，正逆变换相同。
    return (block & 0xF0F0) | ((block & 0x0F00) >> 8) | ((block & 0x000F) << 8)


def mix_columns(block, inverse=False):
    a, b, c, d = ((block >> shift) & 15 for shift in (12, 8, 4, 0))
    x, y = (9, 2) if inverse else (1, 4)
    values = (gf_mul(x, a) ^ gf_mul(y, b), gf_mul(y, a) ^ gf_mul(x, b),
              gf_mul(x, c) ^ gf_mul(y, d), gf_mul(y, c) ^ gf_mul(x, d))
    return sum(n << shift for n, shift in zip(values, (12, 8, 4, 0)))


def expand_key(key: int) -> tuple[int, int, int]:
    """返回(K0,K1,K2)，先校验再访问缓存，保证命中缓存时也校验类型。"""
    word(key, "密钥")
    return _expand_key_cached(key)


@lru_cache(maxsize=65536)
def _expand_key_cached(key: int) -> tuple[int, int, int]:
    def g(byte, rcon):
        rotated = ((byte & 15) << 4) | (byte >> 4)
        return ((SBOX[rotated >> 4] << 4) | SBOX[rotated & 15]) ^ rcon
    w0, w1 = key >> 8, key & 255
    w2 = w0 ^ g(w1, 0x80)
    w3 = w2 ^ w1
    w4 = w2 ^ g(w3, 0x30)
    w5 = w4 ^ w3
    return key, (w2 << 8) | w3, (w4 << 8) | w5


def encrypt(block: int, key: int) -> int:
    """加密单个16位分组，不编码或填充。"""
    word(block)
    k0, k1, k2 = expand_key(key)
    state = block ^ k0
    state = mix_columns(shift_rows(substitute(state))) ^ k1
    return shift_rows(substitute(state)) ^ k2


def decrypt(block: int, key: int) -> int:
    """使用相同密钥按逆序恢复单个16位分组。"""
    word(block)
    k0, k1, k2 = expand_key(key)
    state = substitute(shift_rows(block ^ k2), INV_SBOX)
    state = mix_columns(state ^ k1, inverse=True)
    return substitute(shift_rows(state), INV_SBOX) ^ k0


def encryption_trace(block: int, key: int) -> list[tuple[str, int]]:
    """返回加密逐步状态，供GUI展示和核对。"""
    word(block)
    keys = expand_key(key)
    states = [("输入明文", block), ("K0", keys[0]), ("K1", keys[1]), ("K2", keys[2])]
    state = block ^ keys[0]
    states.append(("初始轮密钥加", state))
    for name, operation in (("第一轮半字节替代", substitute), ("第一轮行移位", shift_rows),
                            ("第一轮列混淆", mix_columns)):
        state = operation(state)
        states.append((name, state))
    state ^= keys[1]
    states.append(("第一轮轮密钥加", state))
    state = substitute(state)
    states.append(("第二轮半字节替代", state))
    state = shift_rows(state)
    states.append(("第二轮行移位", state))
    states.append(("第二轮轮密钥加／密文", state ^ keys[2]))
    return states


def decryption_trace(block: int, key: int) -> list[tuple[str, int]]:
    """返回解密逐步状态，末项为恢复的明文。"""
    word(block)
    keys = expand_key(key)
    states = [("输入密文", block), *[(f"K{i}", k) for i, k in enumerate(keys)]]
    state = block ^ keys[2]
    states.append(("第二轮逆轮密钥加", state))
    for name, operation in (
        ("第二轮逆行移位", shift_rows),
        ("第二轮逆半字节替代", lambda value: substitute(value, INV_SBOX)),
        ("第一轮逆轮密钥加", lambda value: value ^ keys[1]),
        ("第一轮逆列混淆", lambda value: mix_columns(value, inverse=True)),
        ("第一轮逆行移位", shift_rows),
        ("第一轮逆半字节替代", lambda value: substitute(value, INV_SBOX)),
        ("初始逆轮密钥加／明文", lambda value: value ^ keys[0]),
    ):
        state = operation(state)
        states.append((name, state))
    return states


def validate_keys(keys, count=None):
    try:
        keys = tuple(keys)
    except TypeError as error:
        raise ValueError("子密钥必须是含 2 或 3 个16位整数的序列") from error
    if len(keys) not in (2, 3) or (count is not None and len(keys) != count):
        raise ValueError(f"请提供 {count if count else '2 或 3'} 个 16 位子密钥")
    for key in keys:
        word(key, "子密钥")
    return keys


def double_encrypt(block, keys):
    k1, k2 = validate_keys(keys, 2)
    return encrypt(encrypt(block, k1), k2)


def double_decrypt(block, keys):
    k1, k2 = validate_keys(keys, 2)
    return decrypt(decrypt(block, k2), k1)


def triple_encrypt(block, keys):
    keys = validate_keys(keys)
    k1, k2, k3 = keys if len(keys) == 3 else (*keys, keys[0])
    # 三重加密选用 EEE；32 位密钥方案第三次复用 K1。
    return encrypt(encrypt(encrypt(block, k1), k2), k3)


def triple_decrypt(block, keys):
    keys = validate_keys(keys)
    k1, k2, k3 = keys if len(keys) == 3 else (*keys, keys[0])
    return decrypt(decrypt(decrypt(block, k3), k2), k1)


def _validate_bytes(data: bytes) -> bytes:
    if not isinstance(data, (bytes, bytearray)):
        raise ValueError("字节数据必须是 bytes 或 bytearray")
    return bytes(data)


def bytes_to_blocks(data: bytes) -> list[int]:
    """按大端将偶数字节拆成16位分组；允许空序列。"""
    data = _validate_bytes(data)
    if len(data) % 2:
        raise ValueError("数据必须包含偶数个字节")
    return [int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2)]


def blocks_to_bytes(blocks: Iterable[int]) -> bytes:
    """将16位分组连接为大端字节。"""
    return b"".join(word(block).to_bytes(2, "big") for block in blocks)


def pad(data: bytes) -> bytes:
    """添加2字节块大小的PKCS#7填充，偶数长度也添加完整填充分组。"""
    data = _validate_bytes(data)
    count = 2 - len(data) % 2
    return data + bytes([count]) * count


def unpad(data: bytes) -> bytes:
    """严格检查填充再移除，不接受空密文或不完整字节分组。"""
    data = _validate_bytes(data)
    if not data or len(data) % 2 or data[-1] not in (1, 2) or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError("填充无效，请检查密钥、IV 或密文")
    return data[:-data[-1]]


def encrypt_ascii(text: str, key: int) -> bytes:
    """严格ASCII编码，填充后逐块加密；返回原始密文字节。"""
    if not isinstance(text, str):
        raise ValueError("ASCII 明文必须是字符串")
    try:
        data = text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("此功能只接受 ASCII 字符（例如 SAES demo），不接受汉字") from error
    return blocks_to_bytes(encrypt(p, key) for p in bytes_to_blocks(pad(data)))


def decrypt_ascii(data: bytes, key: int) -> str:
    """解密、校验填充并解码ASCII。"""
    data = _validate_bytes(data)
    if not data:
        raise ValueError("密文不能为空")
    try:
        return unpad(blocks_to_bytes(decrypt(c, key) for c in bytes_to_blocks(data))).decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("解密结果不是 ASCII，请检查密钥或密文") from error


def cbc_encrypt(blocks: Iterable[int], key: int, iv: int) -> list[int]:
    """使用给定IV执行CBC，不添加填充，也不修改输入序列。"""
    previous = word(iv, "IV")
    expand_key(key)
    result = []
    for block in blocks:
        previous = encrypt(word(block) ^ previous, key)
        result.append(previous)
    return result


def cbc_decrypt(blocks: Iterable[int], key: int, iv: int) -> list[int]:
    """CBC逐块解密；空分组序列返回空列表。"""
    previous = word(iv, "IV")
    expand_key(key)
    result = []
    for block in blocks:
        result.append(decrypt(block, key) ^ previous)
        previous = block
    return result


def random_iv() -> int:
    """生成供加密和解密双方共享的16位IV。"""
    return secrets.randbits(16)


def meet_in_middle(
    pairs: Iterable[tuple[int, int]],
    progress: Callable[[int, int], None] | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> list[tuple[int, int]]:
    """遍历完整 16 位 K1/K2 空间，保留所有中间值碰撞，再用其余明密文对过滤。"""
    try:
        pairs = list(pairs)
    except TypeError as error:
        raise ValueError("明密文对必须是 (P,C) 序列") from error
    if not pairs:
        raise ValueError("至少输入一组已知明密文对")
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise ValueError("每个明密文对必须恰好包含明文和密文两个整数")
        plain, cipher = pair
        word(plain, "明文")
        word(cipher, "密文")
    table = {}
    plain, cipher = pairs[0]
    for k1 in range(65536):
        table.setdefault(encrypt(plain, k1), []).append(k1)
        if k1 % 1024 == 0:
            if cancelled and cancelled():
                raise InterruptedError("已取消攻击")
            if progress:
                progress(k1, 131072)
    candidates = []
    for k2 in range(65536):
        for k1 in table.get(decrypt(cipher, k2), ()):
            if all(double_encrypt(p, (k1, k2)) == c for p, c in pairs[1:]):
                candidates.append((k1, k2))
        if k2 % 1024 == 0:
            if cancelled and cancelled():
                raise InterruptedError("已取消攻击")
            if progress:
                progress(65536 + k2, 131072)
    if progress:
        progress(131072, 131072)
    return candidates
