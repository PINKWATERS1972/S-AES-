"""文件导入契约和错误定位；验证不依赖GUI。"""
import json
import unittest
import experiment_io


class ExperimentIOTests(unittest.TestCase):
    def test_vector_file_roundtrip_and_bom(self):
        for key in (0, 0x4AF5, 0xFFFF):
            text = json.dumps(experiment_io.make_vectors(key))
            actual_key, results = experiment_io.verify_vectors("\ufeff" + text)
            self.assertEqual(actual_key, key)
            self.assertEqual(len(results), 4)
            self.assertTrue(all(result.passed for result in results))

    def test_invalid_json_schema(self):
        valid = experiment_io.make_vectors(0x4AF5)
        invalid = [None, [], 1, {}, {**valid, "algorithm": "AES"},
                   {**valid, "key": 0}, {**valid, "vectors": []},
                   {**valid, "vectors": {}}, {**valid, "vectors": [1]},
                   {**valid, "vectors": [{"plaintext": None, "ciphertext": "0" * 16}]}]
        for item in invalid:
            with self.subTest(item=item), self.assertRaises(ValueError):
                experiment_io.verify_vectors(json.dumps(item))
        with self.assertRaisesRegex(ValueError, "第 1 行"):
            experiment_io.verify_vectors("{")

    def test_wrong_result_is_reported_with_actual_values(self):
        obj = experiment_io.make_vectors(0x4AF5)
        obj["vectors"][0]["ciphertext"] = "0" * 16
        _, results = experiment_io.verify_vectors(json.dumps(obj))
        self.assertFalse(results[0].passed)
        self.assertEqual(results[0].actual_ciphertext, 0x52B1)
        self.assertTrue(all(result.passed for result in results[1:]))

    def test_attack_text_validation_and_line_numbers(self):
        p, c = "1101011100101000", "0110010101111101"
        self.assertEqual(experiment_io.parse_attack_pairs(f"\n{p} {c}\n"), [(0xD728, 0x657D)])
        with self.assertRaisesRegex(ValueError, "第 2 行"):
            experiment_io.parse_attack_pairs(f"{p} {c}\nwrong")
        with self.assertRaisesRegex(ValueError, "第 2 行"):
            experiment_io.parse_attack_pairs(f"{p} {c}\n{'0' * 15} {c}")
        with self.assertRaises(ValueError):
            experiment_io.parse_attack_pairs("\n")
