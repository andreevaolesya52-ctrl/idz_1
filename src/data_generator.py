"""
Модуль для генерации тестовых конфигураций правил файрвола.
"""

import json
import random
import os

random.seed(42)


def generate_rules(count: int) -> list:
    """
    Генерирует указанное количество случайных правил.

    Args:
        count: Количество правил для генерации

    Returns:
        list: Список правил, каждое правило - список из 5 элементов
    """
    rules = []
    for _ in range(count):
        action = random.choice(['allow', 'deny'])
        protocol = random.choice(['tcp', 'udp', 'icmp'])
        src = random.choice(['any', '192.168.1.0/24', '10.0.0.0/8'])
        dst = random.choice(['any', '8.8.8.8', '10.0.0.1'])
        port = random.choice(['any', '80', '443', '22', '53'])
        rules.append([action, protocol, src, dst, port])
    return rules


def save_configs() -> None:
    """
    Создаёт два файла конфигураций config1.json и config2.json.

    Генерирует 500 общих правил, 100 уникальных для config1 и 50 уникальных для config2.
    """
    os.makedirs('configs', exist_ok=True)

    common = generate_rules(500)

    # Гарантированно уникальные для config1
    unique1 = []
    for i in range(100):
        unique1.append(['allow', 'tcp', f'10.100.{i // 256}.{i % 256}', f'192.168.{i // 256}.{i % 256}', str(9000 + i)])

    # Гарантированно уникальные для config2
    unique2 = []
    for i in range(50):
        unique2.append(['deny', 'udp', f'10.200.{i // 256}.{i % 256}', f'10.0.{i // 256}.{i % 256}', str(8000 + i)])

    config1 = common + unique1
    config2 = common + unique2

    with open('configs/config1.json', 'w') as f:
        json.dump(config1, f, indent=2)

    with open('configs/config2.json', 'w') as f:
        json.dump(config2, f, indent=2)

    print(f"Создано: config1={len(config1)}, config2={len(config2)}")


if __name__ == '__main__':
    """Запуск генерации конфигураций."""
    save_configs()