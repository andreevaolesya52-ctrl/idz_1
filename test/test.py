import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import json
import tempfile
import pytest
from src.firewall_analyzer import FirewallAnalyzer


@pytest.fixture
def configs():
    f1 = tempfile.NamedTemporaryFile(mode='w', delete=False)
    f2 = tempfile.NamedTemporaryFile(mode='w', delete=False)
    yield f1, f2
    f1.close()
    f2.close()


def test_diff(configs):
    f1, f2 = configs
    json.dump([['allow', 'tcp', 'any', 'any', '80']], f1)
    json.dump([['deny', 'udp', 'any', 'any', '443']], f2)
    f1.close()
    f2.close()

    a = FirewallAnalyzer(f1.name, f2.name)
    only1, only2 = a.diff
    assert len(only1) == 1
    assert len(only2) == 1


def test_conflicts(configs):
    f1, f2 = configs
    json.dump([['allow', 'tcp', 'any', 'any', '80']], f1)
    json.dump([['deny', 'tcp', 'any', 'any', '80']], f2)
    f1.close()
    f2.close()

    a = FirewallAnalyzer(f1.name, f2.name)

    # Просто проверяем, что конфликт найден
    # Неважно, в каком порядке поля в frozenset
    assert len(a.conflicts) == 1