"""
Главный скрипт для запуска анализатора.
"""

import sys
import os

# Добавляем корневую папку в путь поиска модулей
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.firewall_analyzer import FirewallAnalyzer

if __name__ == '__main__':
    fw = FirewallAnalyzer('configs/config1.json', 'configs/config2.json')

    only1, only2 = fw.diff
    print(f"1. Только в config1: {len(only1)}")
    print(f"   Только в config2: {len(only2)}")

    print(f"2. Конфликтов: {len(fw.conflicts)}")

    s1, s2 = fw.superset()
    print(f"3. Config1 содержит Config2: {s1}")
    print(f"   Config2 содержит Config1: {s2}")

    fw.report('reports/report.json')
    print("\nГотово! Смотри reports/report.json и logs/app.log")