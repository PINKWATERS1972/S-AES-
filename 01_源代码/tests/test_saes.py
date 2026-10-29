"""已知答案、逆变换、边界条件及五关实验验证。"""
import random
import unittest
import saes


class SaesTests(unittest.TestCase):
    def test_public_input_types_are_checked(self):
        for bad in (None, 1, [], b"01"):
            with self.assertRaises(ValueError):
                saes.parse_bits(bad)
        for length in (0, -1, True, 16.0):
            with self.assertRaises(ValueError):
                saes.parse_bits("0" * 16, length)
        saes.expand_key(1)
        for bad in (True, 1.0, [], None):
            with self.assertRaises(ValueError):
                saes.expand_key(bad)
        for bad in ("AB", None, [1, 2]):
            with self.assertRaises(ValueError):
                saes.bytes_to_blocks(bad)
        with self.assertRaises(ValueError):
            saes.encrypt_ascii(None, 0)
        with self.assertRaises(ValueError):
            saes.double_encrypt(0, None)
        for pairs in (None, [1], [(1,)], [(1, 2, 3)]):
            with self.assertRaises(ValueError):
                saes.meet_in_middle(pairs)

    def test_encryption_and_decryption_traces(self):
        rng = random.Random(20261029)
        for plain, key in [(0xD728, 0x4AF5), *[(rng.randrange(65536), rng.randrange(65536)) for _ in range(50)]]:
            cipher = saes.encrypt(plain, key)
            self.assertEqual(saes.encryption_trace(plain, key)[-1][1], cipher)
            trace = saes.decryption_trace(cipher, key)
            self.assertEqual(trace[-1][1], saes.decrypt(cipher, key))
            self.assertEqual(trace[-1][1], plain)
        self.assertEqual(saes.decryption_trace(0x24EC, 0x4AF5)[4][1], 0xA343)

    def test_published_known_answer(self):
        self.assertEqual(saes.encrypt(0xD728, 0x4AF5), 0x24EC)
        self.assertEqual(saes.decrypt(0x24EC, 0x4AF5), 0xD728)
        self.assertEqual(saes.expand_key(0x4AF5), (0x4AF5, 0xDD28, 0x87AF))

    def test_appendix_key_expansion(self):
        self.assertEqual(saes.expand_key(0x2D55), (0x2D55, 0xBCE9, 0xA34A))

    def test_all_substitution_values(self):
        for value in range(16):
            block = value * 0x1111
            self.assertEqual(saes.substitute(saes.substitute(block), saes.INV_SBOX), block)

    def test_all_mix_and_shift_states(self):
        for block in range(65536):
            self.assertEqual(saes.mix_columns(saes.mix_columns(block), True), block)
            self.assertEqual(saes.shift_rows(saes.shift_rows(block)), block)

    def test_full_plaintext_space(self):
        seen = set()
        for p in range(65536):
            c = saes.encrypt(p, 0x4AF5)
            seen.add(c)
            self.assertEqual(saes.decrypt(c, 0x4AF5), p)
        self.assertEqual(len(seen), 65536)

    def test_varying_keys(self):
        rng = random.Random(20261029)
        for _ in range(500):
            p, k = rng.randrange(65536), rng.randrange(65536)
            self.assertEqual(saes.decrypt(saes.encrypt(p, k), k), p)

    def test_ascii_padding_and_control_characters(self):
        for plain in ("", "A", "AB", "ABC", "Hello S-AES!", "\x00\x01\x02\x7f", " "):
            c = saes.encrypt_ascii(plain, 0x4AF5)
            self.assertEqual(len(c) % 2, 0)
            self.assertEqual(saes.decrypt_ascii(c, 0x4AF5), plain)

    def test_invalid_inputs(self):
        for value in ("", "1" * 15, "1" * 17, "0" * 15 + "2"):
            with self.assertRaises(ValueError):
                saes.parse_bits(value)
        for value in (-1, 65536, True, "1234"):
            with self.assertRaises(ValueError):
                saes.encrypt(value, 0)
        with self.assertRaises(ValueError):
            saes.encrypt_ascii("中文", 0)
        for data in (b"", b"a", b"ab", b"\x01\x02"):
            with self.assertRaises(ValueError):
                saes.unpad(data)
        with self.assertRaises(ValueError):
            saes.decrypt_ascii(b"a", 0)

    def test_double_order(self):
        p, keys = 0xD728, (0x4AF5, 0xDD28)
        self.assertEqual(saes.double_encrypt(p, keys), saes.encrypt(0x24EC, keys[1]))
        self.assertEqual(saes.double_decrypt(saes.double_encrypt(p, keys), keys), p)

    def test_triple_both_key_sizes(self):
        for keys in ((0x4AF5, 0xDD28), (0x4AF5, 0xDD28, 0x1234)):
            for p in (0, 0xD728, 0xFFFF):
                c = saes.triple_encrypt(p, keys)
                self.assertEqual(saes.triple_decrypt(c, keys), p)
                last = keys[2] if len(keys) == 3 else keys[0]
                self.assertEqual(c, saes.encrypt(saes.double_encrypt(p, keys[:2]), last))

    def test_cbc_recurrence(self):
        plain, key, iv = [0x1234, 0x5678, 0x9ABC], 0x4AF5, 0x1234
        c = saes.cbc_encrypt(plain, key, iv)
        previous = iv
        for p, block in zip(plain, c):
            self.assertEqual(block, saes.encrypt(p ^ previous, key))
            previous = block
        self.assertEqual(saes.cbc_decrypt(c, key, iv), plain)

    def test_cbc_tampering_propagation(self):
        plain, key, iv = [0x1234, 0x5678, 0x9ABC], 0x4AF5, 0x1234
        c = saes.cbc_encrypt(plain, key, iv)
        c[0] ^= 1
        changed = saes.cbc_decrypt(c, key, iv)
        self.assertNotEqual(changed[0], plain[0])
        self.assertEqual(changed[1], plain[1] ^ 1)
        self.assertEqual(changed[2], plain[2])
        original_c = saes.cbc_encrypt(plain, key, iv)
        changed_iv = saes.cbc_decrypt(original_c, key, iv ^ 1)
        self.assertEqual(changed_iv, [plain[0] ^ 1, *plain[1:]])

    def test_attack_full_space_and_collision_retention(self):
        # 单对会有大量候选，真实密钥不能因中间值碰撞被覆盖。
        keys = (0x4AF5, 0xDD28)
        p = 0xD728
        candidates = saes.meet_in_middle([(p, saes.double_encrypt(p, keys))])
        self.assertIn(keys, candidates)
        self.assertGreater(len(candidates), 1)
        self.assertTrue(all(saes.double_encrypt(p, pair) == saes.double_encrypt(p, keys) for pair in candidates))
        remaining = [(q, saes.double_encrypt(q, keys)) for q in (0x1234, 0xABCD)]
        expected = {pair for pair in candidates if all(saes.double_encrypt(q, pair) == c for q, c in remaining)}
        self.assertEqual(set(saes.meet_in_middle([(p, saes.double_encrypt(p, keys)), *remaining])), expected)
        self.assertIn(keys, expected)

    def test_attack_cancel_and_empty(self):
        with self.assertRaises(ValueError):
            saes.meet_in_middle([])
        with self.assertRaises(InterruptedError):
            saes.meet_in_middle([(0, 0)], cancelled=lambda: True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
