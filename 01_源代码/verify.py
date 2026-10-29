"""运行测试，生成可复核的测试报告与跨组测试数据。"""
import datetime
import io
import json
from pathlib import Path
import platform
import time
import unittest
import saes
import experiment_io


def main():
    root = Path(__file__).resolve().parent
    results = root.parent / "02_测试结果"
    results.mkdir(exist_ok=True)
    (root / "examples").mkdir(exist_ok=True)
    stream = io.StringIO()
    start = time.perf_counter()
    suite = unittest.defaultTestLoader.discover(str(root / "tests"))
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    elapsed = time.perf_counter() - start
    log = stream.getvalue()
    (results / "test_log.txt").write_text(log, encoding="utf-8")
    vectors = experiment_io.make_vectors(0x4AF5)
    (root / "examples" / "cross_vectors.json").write_text(json.dumps(vectors, indent=2), encoding="utf-8")
    rows = "\n".join(f"| {int(v['plaintext'], 2):04X} | {int(v['ciphertext'], 2):04X} |" for v in vectors["vectors"])
    plain, key, iv = [0x1234, 0x5678, 0x9ABC], 0x4AF5, 0x1234
    cipher = saes.cbc_encrypt(plain, key, iv)
    altered = cipher.copy()
    altered[0] ^= 1
    recovered = saes.cbc_decrypt(altered, key, iv)
    cbc_rows = "\n".join(f"| {i + 1} | {p:04X} | {c:04X} | {m:04X} | {r:04X} | {p ^ r:04X} |" for i, (p, c, m, r) in enumerate(zip(plain, cipher, altered, recovered)))
    attack_pairs = [(p, saes.double_encrypt(p, (0x4AF5, 0xDD28))) for p in (0xD728, 0x1234, 0xABCD)]
    t0 = time.perf_counter()
    candidates = saes.meet_in_middle(attack_pairs)
    attack_time = time.perf_counter() - t0
    (root / "examples" / "attack_pairs.txt").write_text("\n".join(f"{p:016b} {c:016b}" for p, c in attack_pairs), encoding="utf-8")
    status = "通过" if result.wasSuccessful() else "存在失败，详见日志"
    report = f"""# 自动测试摘要：S-AES 五关验证

生成时间：{datetime.datetime.now(datetime.timezone(datetime.timedelta(hours=8))).isoformat(timespec='seconds')}（北京时间）  
环境：Python {platform.python_version()}，{platform.system()}。  
自动测试：{result.testsRun} 项，失败 {len(result.failures)} 项，异常 {len(result.errors)} 项，耗时 {elapsed:.3f} 秒。结论：**{status}**。

## 第 1 关：基础测试

已知公开向量：P=D728、K=4AF5，预期 C=24EC，实际 C={saes.encrypt(0xD728, 0x4AF5):04X}，解密为 {saes.decrypt(0x24EC, 0x4AF5):04X}。
轮密钥为 K0=4AF5、K1=DD28、K2=87AF。附录密钥扩展示例 2D55 → BCE9 → A34A 也已验证。
固定密钥下遍历全部 65536 个明文，验证密文无碰撞并全部可逆；另外验证 500 组确定性随机明文与密钥。

## 第 2 关：交叉测试

本机公开向量比对和 JSON 向量导入可用。以下向量用于交给其他小组（K=4AF5）：

| 明文 HEX | 密文 HEX |
|---|---|
{rows}

**实际组间交叉测试待完成**：目前没有其他小组程序、成员或运行记录，不能将本机测试作为组间测试。请填写同目录的 [组间交叉测试记录](组间交叉测试记录.md)。

## 第 3 关：ASCII 扩展

对空串、1/2/3 字符、Hello S-AES!、控制字符和空格完成往返验证。两字节分组并使用 PKCS#7 填充。
Hello S-AES! 的密文 HEX：{saes.encrypt_ascii('Hello S-AES!', key).hex().upper()}。
非 ASCII 输入和不合法填充已验证拒绝。

## 第 4 关：多重加密与中间相遇攻击

双重加密（EE），以及三重加密（EEE）的 32/48 位方案均验证了加解密逆序关系（具体定义见开发手册）。
攻击使用三个已知明密文对，完整遍历 65536 个 K1 和 65536 个 K2；本次独立演示耗时 {attack_time:.3f} 秒。
候选数：{len(candidates)}，候选 HEX：{', '.join(f'{a:04X} || {b:04X}' for a, b in candidates)}。
真实密钥 (4AF5, DD28) 是否保留：{(0x4AF5, 0xDD28) in candidates}。
自动测试额外验证单对产生多个候选，保留全部中间值碰撞，使用其余明密文对过滤的结果与完整攻击一致。

## 第 5 关：CBC 和密文篡改

K=4AF5，IV=1234。将 C1 最低位翻转，其他密文不变，再解密：

| 分组 | 原明文 | 原密文 | 篡改后密文 | 解密结果 | 与原明文 XOR |
|---|---|---|---|---|---|
{cbc_rows}

验证结果：P1 被扰乱、P2 最低位翻转、P3 不变。改变 IV 最低位时，仅 P1 最低位翻转。
CBC 本身不检测篡改；这里用于说明错误传播特性。

## 证据与限制

详细断言记录见 test_log.txt；数据可使用 verify.py 重新生成。运行耗时取决于电脑。
GUI 可通过根目录的“启动程序.bat”或 01_源代码/main.py 打开；本报告自动断言针对算法与数据，不把截图或人工操作假写成已完成。
"""
    (results / "自动测试摘要.md").write_text(report, encoding="utf-8")
    print(log)
    print("测试报告：", results / "自动测试摘要.md")
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
