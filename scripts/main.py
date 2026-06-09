import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.firewall_analyzer import FirewallAnalyzer

if __name__ == '__main__':
    # Создаем анализатор
    fw = FirewallAnalyzer('configs/config1.json', 'configs/config2.json')

    # Задача 1: различия
    only1, only2 = fw.diff
    print(f"1. Только в config1: {len(only1)}")
    print(f"   Только в config2: {len(only2)}")

    # Задача 2: конфликты
    print(f"2. Конфликтов: {len(fw.conflicts)}")

    # Задача 3: надмножество
    s1, s2 = fw.superset()
    print(f"3. Config1 содержит Config2: {s1}")
    print(f"   Config2 содержит Config1: {s2}")

    # Сохраняем отчет
    fw.report('reports/report.json')
    print("\nГотово! Смотри reports/report.json и logs/app.log")