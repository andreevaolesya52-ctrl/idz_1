import unittest
import json
import tempfile
from src.firewall_analyzer import FirewallAnalyzer

class TestFirewall(unittest.TestCase):
    def setUp(self):
        self.f1 = tempfile.NamedTemporaryFile(mode='w', delete=False)
        self.f2 = tempfile.NamedTemporaryFile(mode='w', delete=False)

    # ТЕСТ 1: Проверка различий (симметрической разности)
    def test_diff(self):
        json.dump([['allow', 'tcp', 'any', 'any', '80']], self.f1)
        json.dump([['deny', 'udp', 'any', 'any', '443']], self.f2)
        self.f1.close();
        self.f2.close()

        a = FirewallAnalyzer(self.f1.name, self.f2.name)
        only1, only2 = a.diff
        assert len(only1) == 1 and len(only2) == 1

    # ТЕСТ 2: Проверка конфликтов (одинаковые условия, разные действия)
    def test_conflicts(self):
        json.dump([['allow', 'tcp', 'any', 'any', '80']], self.f1)
        json.dump([['deny', 'tcp', 'any', 'any', '80']], self.f2)
        self.f1.close();
        self.f2.close()

        a = FirewallAnalyzer(self.f1.name, self.f2.name)
        assert len(a.conflicts) == 1


if __name__ == '__main__':
    unittest.main()