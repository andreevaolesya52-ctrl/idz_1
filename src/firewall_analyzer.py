"""
Модуль для анализа конфигураций межсетевых экранов.
"""

import json
import logging
from collections import defaultdict
from typing import Tuple, Set, List, Dict, Any, Iterator
import os

os.makedirs('logs', exist_ok=True)
logging.basicConfig(
    filename='logs/app.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)


class FirewallAnalyzer:
    """Анализатор конфигураций файрвола."""

    def __init__(self, path1: str, path2: str):
        """Загружает две конфигурации."""
        self._path1 = path1
        self._path2 = path2
        self._rules1: Set[frozenset] = set()
        self._rules2: Set[frozenset] = set()
        self._load_with_generator()

    def _rule_generator(self, file_path: str) -> Iterator[list]:
        """Генератор правил из JSON файла."""
        with open(file_path, 'r') as f:
            data = json.load(f)
            for rule in data:
                yield rule
        logging.debug(f"Finished reading {file_path}")

    def _load_with_generator(self) -> None:
        """Загружает правила из обоих файлов."""
        for rule in self._rule_generator(self._path1):
            self._rules1.add(frozenset(rule))
        for rule in self._rule_generator(self._path2):
            self._rules2.add(frozenset(rule))
        logging.info(f"Loaded: {len(self._rules1)} and {len(self._rules2)} rules")

    @property
    def diff(self) -> Tuple[Set[frozenset], Set[frozenset]]:
        """Правила только в первой и только во второй конфигурации."""
        return self._rules1 - self._rules2, self._rules2 - self._rules1

    @property
    def conflicts(self) -> List[Dict[str, Any]]:
        """Конфликты: одинаковые условия, разные действия."""
        groups = defaultdict(set)
        for rule in self._rules1 | self._rules2:
            parts = list(rule)
            action = 'allow' if 'allow' in parts else 'deny'
            condition = frozenset(p for p in parts if p not in ('allow', 'deny'))
            groups[condition].add(action)
        return [{'condition': list(c), 'actions': list(a)} for c, a in groups.items() if len(a) > 1]

    def superset(self) -> Tuple[bool, bool]:
        """Проверяет, является ли одна конфигурация надмножеством другой."""
        return self._rules1.issuperset(self._rules2), self._rules2.issuperset(self._rules1)

    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует состояние в словарь."""
        return {
            'path1': self._path1,
            'path2': self._path2,
            'rules1': [list(r) for r in self._rules1],
            'rules2': [list(r) for r in self._rules2]
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FirewallAnalyzer':
        """Восстанавливает объект из словаря."""
        instance = cls.__new__(cls)
        instance._path1 = data['path1']
        instance._path2 = data['path2']
        instance._rules1 = {frozenset(r) for r in data['rules1']}
        instance._rules2 = {frozenset(r) for r in data['rules2']}
        return instance

    def save_state(self, file_path: str) -> None:
        """Сохраняет состояние в JSON файл."""
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w') as f:
            json.dump(self.to_dict(), f, indent=2)
        logging.info(f"State saved to {file_path}")

    @classmethod
    def load_state(cls, file_path: str) -> 'FirewallAnalyzer':
        """Загружает состояние из JSON файла."""
        with open(file_path, 'r') as f:
            data = json.load(f)
        logging.info(f"State loaded from {file_path}")
        return cls.from_dict(data)

    def report(self, out_file: str) -> Dict[str, Any]:
        """Формирует отчёт и сохраняет в JSON."""
        only1, only2 = self.diff
        conf = self.conflicts
        sup1, sup2 = self.superset()

        report_data = {
            'summary': {
                'total_rules_config1': len(self._rules1),
                'total_rules_config2': len(self._rules2),
                'common_rules': len(self._rules1 & self._rules2),
                'only_in_config1': len(only1),
                'only_in_config2': len(only2),
                'conflicts_count': len(conf),
                'config1_contains_config2': sup1,
                'config2_contains_config1': sup2,
                'is_fully_consistent': (len(only1) == 0 and len(only2) == 0 and len(conf) == 0)
            },
            'details': {
                'rules_only_in_config1': [list(r) for r in list(only1)[:10]],
                'rules_only_in_config2': [list(r) for r in list(only2)[:10]],
                'conflicts': conf
            }
        }

        os.makedirs(os.path.dirname(out_file), exist_ok=True)
        with open(out_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        logging.info(f"Report saved to {out_file}")
        return report_data