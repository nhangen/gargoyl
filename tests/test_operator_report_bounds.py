import unittest

from gargoyl.operator_report import _identities


class OperatorReportBoundsTests(unittest.TestCase):
    def test_inventory_and_audit_limits_are_distinct(self):
        values = [f'00000000-0000-4000-8000-{index:012d}' for index in range(32)]
        self.assertEqual(_identities(values[:16], 16), tuple(values[:16]))
        self.assertEqual(_identities(values, 32), tuple(values))
        with self.assertRaises(ValueError):
            _identities(values[:17], 16)
        with self.assertRaises(ValueError):
            _identities(values + ['00000000-0000-4000-8000-000000000032'], 32)

    def test_duplicate_noncanonical_and_lazy_inputs_rejected(self):
        value = '00000000-0000-4000-8000-000000000001'
        for invalid in ([value, value], [value.replace('-', '')], ['private-marker'],
                        value, iter([value]), {value}, [None]):
            with self.subTest(kind=type(invalid).__name__):
                with self.assertRaises(ValueError):
                    _identities(invalid, 32)
