import copy
import json
import unittest
from pathlib import Path

from guard_receipt import verify_guard_receipt


VECTOR = json.loads(
    (Path(__file__).parent.parent / "vectors" / "guard-receipt-v1.json").read_text(
        encoding="utf-8"
    )
)


class GuardReceiptVectorTests(unittest.TestCase):
    def test_python_verifies_the_rust_receipt_vector(self) -> None:
        verify_guard_receipt(VECTOR["signed_receipt"])

    def test_python_rejects_a_mutated_receipt(self) -> None:
        tampered = copy.deepcopy(VECTOR["signed_receipt"])
        tampered["receipt"]["resource"] = "/workspace/project/other.txt"
        with self.assertRaisesRegex(ValueError, "invalid receipt signature"):
            verify_guard_receipt(tampered)


if __name__ == "__main__":
    unittest.main()
