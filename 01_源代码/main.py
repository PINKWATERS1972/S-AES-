"""S-AES 五关实验桌面界面，仅依赖 Python 标准库。"""
import json
from pathlib import Path
import queue
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import saes
import experiment_io

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("S-AES 算法实验室 · 五关实验")
        self.geometry("1060x800")
        self.minsize(860, 650)
        self.events = queue.Queue()
        self.cancel_attack = threading.Event()
        self.attack_running = False
        self.attack_candidates = []
        ttk.Label(self, text="S-AES 算法实验室", font=("Microsoft YaHei UI", 23, "bold")).pack(anchor="w", padx=24, pady=(18, 4))
        ttk.Label(self, text="16 位分组 · 密钥扩展 · 多重加密 · 中间相遇攻击 · CBC 篡改实验").pack(anchor="w", padx=26, pady=(0, 16))
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=20, pady=(0, 12))
        self.basic_tab(notebook)
        self.cross_tab(notebook)
        self.ascii_tab(notebook)
        self.multiple_tab(notebook)
        self.attack_tab(notebook)
        self.cbc_tab(notebook)
        ttk.Label(self, text="教学实验使用；详细步骤见 03_相关文档/用户指南.md。输入错误会提示，不会改变文件。").pack(anchor="w", padx=24, pady=(0, 12))
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.after(100, self.poll)

    def close(self):
        self.cancel_attack.set()
        self.destroy()

    def tab(self, notebook, title, hint):
        frame = ttk.Frame(notebook, padding=18)
        notebook.add(frame, text=title)
        ttk.Label(frame, text=hint, wraplength=920, justify="left").pack(anchor="w", pady=(0, 12))
        return frame

    def entry(self, parent, label, default=""):
        ttk.Label(parent, text=label).pack(anchor="w", pady=(6, 2))
        value = tk.StringVar(value=default)
        entry = ttk.Entry(parent, textvariable=value, font=("Consolas", 12))
        entry.value_variable = value
        value.trace_add("write", lambda *_: self.mark_stale(parent))
        entry.pack(fill="x")
        return entry

    def output(self, parent, height=10):
        holder = ttk.Frame(parent)
        holder.pack(fill="both", expand=True, pady=(10, 0))
        output = tk.Text(holder, height=height, wrap="word", font=("Consolas", 11))
        scroll = ttk.Scrollbar(holder, command=output.yview)
        output.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        output.pack(side="left", fill="both", expand=True)
        output.configure(state="disabled")
        parent.result_output = output
        return output

    def show(self, output, text):
        output.configure(state="normal")
        output.delete("1.0", "end")
        output.insert("1.0", text)
        output.configure(state="disabled")

    def mark_stale(self, frame):
        """输入变化即撤下旧结果，避免截图中参数与结果不对应。"""
        output = getattr(frame, "result_output", None)
        if output is not None and output.get("1.0", "end-1c"):
            self.show(output, "输入或模式已修改，原结果已失效。请重新点击操作按钮计算。")

    def safe(self, function):
        def run():
            try:
                function()
            except (ValueError, OSError, UnicodeError) as error:
                messagebox.showerror("请检查输入", str(error), parent=self)
        return run

    def buttons(self, parent, *items):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=10)
        buttons = []
        for label, command in items:
            button = ttk.Button(row, text=label, command=self.safe(command))
            button.pack(side="left", padx=(0, 10))
            buttons.append(button)
        return buttons

    def basic_tab(self, notebook):
        frame = self.tab(notebook, "1 基础测试", "输入 16 位二进制数据和密钥，可查看三个轮密钥及逐轮加密过程。")
        data = self.entry(frame, "明文／密文（16 位）", "1101011100101000")
        key = self.entry(frame, "密钥（16 位）", "0100101011110101")
        def run(inverse=False):
            p, k = saes.parse_bits(data.get()), saes.parse_bits(key.get())
            result = (saes.decrypt if inverse else saes.encrypt)(p, k)
            text = f"{'解密明文' if inverse else '加密密文'}：{result:016b}  (0x{result:04X})\n\n"
            trace = saes.decryption_trace(p, k) if inverse else saes.encryption_trace(p, k)
            text += "\n".join(f"{name}: {value:016b} / {value:04X}" for name, value in trace)
            self.show(out, text)
        self.buttons(frame, ("加密并显示过程", run), ("解密", lambda: run(True)))
        out = self.output(frame)

    def cross_tab(self, notebook):
        frame = self.tab(notebook, "2 交叉测试", "导出标准测试向量给其他小组；也可导入同格式 JSON 在本程序验证。只有其他小组实际运行后，才能记录为组间通过。")
        key = self.entry(frame, "双方约定的 16 位密钥", "0100101011110101")
        def export():
            k = saes.parse_bits(key.get())
            path = filedialog.asksaveasfilename(parent=self, defaultextension=".json", initialfile="交叉测试向量.json", initialdir=str(PROJECT_ROOT / "02_测试结果" / "第2关_互操作验证"), filetypes=[("JSON", "*.json")])
            if path:
                Path(path).write_text(json.dumps(experiment_io.make_vectors(k), indent=2), encoding="utf-8")
                self.show(out, f"已导出：{path}\n请对方比较加密结果，并用密文解密验证。")
        def verify():
            path = filedialog.askopenfilename(parent=self, filetypes=[("JSON", "*.json")])
            if not path:
                return
            k, results = experiment_io.verify_vectors(Path(path).read_text(encoding="utf-8-sig"))
            key.value_variable.set(f"{k:016b}")
            lines = [f"文件：{path}", f"文件密钥：{k:016b} / {k:04X}"]
            for item in results:
                lines.append(f"{'通过' if item.passed else '失败'}  P={item.plaintext:04X} C={item.ciphertext:04X}")
                if not item.passed:
                    lines.append(f"  实际加密={item.actual_ciphertext:04X}，实际解密={item.recovered_plaintext:04X}")
            lines.append("本机验证不等于组间互测；请保留对方独立实现的记录。")
            self.show(out, "\n".join(lines))
        self.buttons(frame, ("导出给其他小组", export), ("导入并验证", verify))
        out = self.output(frame)

    def ascii_tab(self, notebook):
        frame = self.tab(notebook, "3 ASCII 扩展", "每两字节分组；采用 PKCS#7 填充。密文以十六进制传输，同时显示 Latin-1 字符映射，避免乱码丢失。")
        plain = self.entry(frame, "ASCII 明文", "Hello S-AES!")
        key = self.entry(frame, "16 位密钥", "0100101011110101")
        cipher = self.entry(frame, "十六进制密文（加密后自动填入）")
        def enc():
            data = saes.encrypt_ascii(plain.get(), saes.parse_bits(key.get()))
            cipher.delete(0, "end")
            cipher.insert(0, data.hex().upper())
            self.show(out, f"密文 HEX：{data.hex().upper()}\n密文字符映射（控制字符转义）：{data.decode('latin-1')!r}\n密文字节数：{len(data)}")
        def dec():
            result = saes.decrypt_ascii(bytes.fromhex(cipher.get()), saes.parse_bits(key.get()))
            self.show(out, "解密结果：" + result)
        self.buttons(frame, ("加密字符串", enc), ("解密字符串", dec))
        out = self.output(frame)

    def multiple_tab(self, notebook):
        frame = self.tab(notebook, "4 多重加密", "双重：E(K2,E(K1,P))。三重采用 EEE：48 位用 K1、K2、K3；32 位用 K1、K2、K1。解密逆序执行。")
        mode = ttk.Combobox(frame, state="readonly", values=("双重加密 / 32 位", "三重 EEE / 32 位", "三重 EEE / 48 位"))
        mode.current(0)
        mode.pack(fill="x")
        mode.bind("<<ComboboxSelected>>", lambda event: self.mark_stale(frame))
        data = self.entry(frame, "16 位明文／密文", "1101011100101000")
        key = self.entry(frame, "合并密钥（32 或 48 位，按 K1 || K2 || K3 排列）", "01001010111101011101110100101000")
        def run(inverse=False):
            length = 48 if mode.current() == 2 else 32
            combined = saes.parse_bits(key.get(), length)
            keys = [(combined >> shift) & 65535 for shift in range(length - 16, -1, -16)]
            functions = ((saes.double_encrypt, saes.double_decrypt),
                         (saes.triple_encrypt, saes.triple_decrypt),
                         (saes.triple_encrypt, saes.triple_decrypt))
            function = functions[mode.current()][int(inverse)]
            result = function(saes.parse_bits(data.get()), keys)
            self.show(out, f"{'解密明文' if inverse else '加密密文'}：{result:016b}\nHEX：{result:04X}\n子密钥：" + " / ".join(f"{k:04X}" for k in keys))
        self.buttons(frame, ("加密", run), ("解密", lambda: run(True)))
        out = self.output(frame)

    def attack_tab(self, notebook):
        frame = self.tab(notebook, "4 中间相遇", "攻击双重 S-AES 的完整 32 位密钥空间。每行一对：16 位明文 空格 16 位密文。建议至少 3 对；单对通常不能唯一确定密钥。")
        pairs = tk.Text(frame, height=5, font=("Consolas", 11))
        pairs.pack(fill="x")
        def fill():
            pairs.delete("1.0", "end")
            for p in (0xD728, 0x1234, 0xABCD):
                pairs.insert("end", f"{p:016b} {saes.double_encrypt(p, (0x4AF5, 0xDD28)):016b}\n")
            pairs.edit_modified(False)
            self.attack_candidates = []
            self.show(out, "演示数据真实密钥：K1=4AF5，K2=DD28；开始攻击后只使用输入的明密文对。")
        def start():
            if self.attack_running:
                raise ValueError("攻击正在进行，请等待结束或取消")
            items = experiment_io.parse_attack_pairs(pairs.get("1.0", "end"))
            self.cancel_attack.clear()
            self.set_attack_running(True)
            self.attack_candidates = []
            progress["value"] = 0
            self.show(out, "正在搜索全部 65536 个 K1 和全部 65536 个 K2……")
            def worker():
                begin = time.perf_counter()
                try:
                    results = saes.meet_in_middle(items, lambda a, b: self.events.put(("progress", a / b * 100)), self.cancel_attack.is_set)
                    self.events.put(("done", (results, time.perf_counter() - begin)))
                except Exception as error:
                    self.events.put(("error", str(error)))
            threading.Thread(target=worker, daemon=True).start()
        def export():
            if not self.attack_candidates:
                raise ValueError("当前没有候选密钥可导出，请先完成攻击")
            path = filedialog.asksaveasfilename(parent=self, defaultextension=".json", initialfile="候选密钥.json", initialdir=str(PROJECT_ROOT / "02_测试结果" / "第4关_多重与密钥恢复"), filetypes=[("JSON", "*.json")])
            if path:
                Path(path).write_text(json.dumps([{"K1": f"{a:016b}", "K2": f"{b:016b}"} for a, b in self.attack_candidates], indent=2), encoding="utf-8")
        self.attack_buttons = self.buttons(frame, ("填入演示数据", fill), ("开始完整搜索", start), ("取消", self.cancel_attack.set), ("导出全部候选", export))
        progress = ttk.Progressbar(frame, maximum=100)
        progress.pack(fill="x")
        out = self.output(frame)
        self.attack_output, self.attack_progress = out, progress
        self.attack_input = pairs
        def changed(event):
            if pairs.edit_modified():
                self.attack_candidates = []
                self.mark_stale(frame)
                pairs.edit_modified(False)
        pairs.edit_modified(False)
        pairs.bind("<<Modified>>", changed)
        self.set_attack_running(False)

    def set_attack_running(self, running):
        """搜索使用固定输入快照；运行中锁定会改变数据的控件。"""
        self.attack_running = running
        self.attack_input.configure(state="disabled" if running else "normal")
        for index, button in enumerate(self.attack_buttons):
            enabled = running if index == 2 else not running
            button.configure(state="normal" if enabled else "disabled")

    def poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "progress":
                    self.attack_progress["value"] = payload
                elif kind == "done":
                    self.set_attack_running(False)
                    self.attack_candidates, elapsed = payload
                    lines = [f"搜索完成：{elapsed:.3f} 秒；候选数量：{len(self.attack_candidates)}", "候选按 K1 || K2 展示（界面最多显示前 100 对，可导出全部）："]
                    lines += [f"{a:016b} {b:016b} / {a:04X} {b:04X}" for a, b in self.attack_candidates[:100]]
                    self.show(self.attack_output, "\n".join(lines))
                else:
                    self.set_attack_running(False)
                    self.show(self.attack_output, payload)
        except queue.Empty:
            pass
        self.after(100, self.poll)

    def cbc_tab(self, notebook):
        frame = self.tab(notebook, "5 CBC 与篡改", "每块16位，空格分隔，不填充。加密后可修改密文；翻转第 i 块一位，会扰乱明文第 i 块，并在第 i+1 块相同位置翻转一位。")
        key = self.entry(frame, "16 位密钥", "0100101011110101")
        iv = self.entry(frame, "16 位 IV（解密时必须与加密时相同）", "0001001000110100")
        plain = self.entry(frame, "明文分组（空格分隔）", "0001001000110100 0101011001111000 1001101010111100")
        cipher = self.entry(frame, "密文分组（可手动替换或修改）")
        self.cbc_original = None
        def parse(entry):
            blocks = [saes.parse_bits(s) for s in entry.get().split()]
            if not blocks:
                raise ValueError("至少输入一个 16 位分组")
            return blocks
        def generate():
            iv.delete(0, "end")
            iv.insert(0, f"{saes.random_iv():016b}")
        def enc():
            blocks, k, v = parse(plain), saes.parse_bits(key.get()), saes.parse_bits(iv.get())
            result = saes.cbc_encrypt(blocks, k, v)
            self.cbc_original = (blocks, k, v)
            cipher.delete(0, "end")
            cipher.insert(0, " ".join(f"{c:016b}" for c in result))
            self.show(out, f"CBC 加密完成。IV={v:016b}\n请保留 IV，点击解密验证，或翻转密文后对比。")
        def dec():
            k, v = saes.parse_bits(key.get()), saes.parse_bits(iv.get())
            result = saes.cbc_decrypt(parse(cipher), k, v)
            baseline = self.cbc_original
            lines = ["解密结果："]
            for i, p in enumerate(result):
                line = f"P{i + 1}: {p:016b} / {p:04X}"
                if baseline and baseline[1:] == (k, v) and i < len(baseline[0]):
                    delta = p ^ baseline[0][i]
                    line += f"  原文={baseline[0][i]:04X} XOR差分={delta:04X} 改变位数={delta.bit_count()}"
                lines.append(line)
            self.show(out, "\n".join(lines))
        def tamper():
            blocks = parse(cipher)
            blocks[0] ^= 1
            cipher.delete(0, "end")
            cipher.insert(0, " ".join(f"{c:016b}" for c in blocks))
            dec()
        self.buttons(frame, ("随机生成 IV", generate), ("CBC 加密", enc), ("解密／对比", dec), ("翻转 C1 最低位并对比", tamper))
        out = self.output(frame)


if __name__ == "__main__":
    App().mainloop()
