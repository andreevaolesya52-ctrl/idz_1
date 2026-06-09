import json
import logging
from collections import defaultdict

# Настройка логов
logging.basicConfig(
    filename='logs/app.log',
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class FirewallAnalyzer:
    def __init__(self, path1, path2):
        self._path1 = path1
        self._path2 = path2
        self._rules1 = set()
        self._rules2 = set()
        self._load()

    def _load(self):
        # Загружаем первый файл
        with open(self._path1, 'r') as f:
            data = json.load(f)
            for rule in data:
                self._rules1.add(frozenset(rule))

        # Загружаем второй файл
        with open(self._path2, 'r') as f:
            data = json.load(f)
            for rule in data:
                self._rules2.add(frozenset(rule))

        logging.info(f"Loaded: {len(self._rules1)} and {len(self._rules2)} rules")

    @property
    def diff(self):
        """Правила только в первой и только во второй"""
        only1 = self._rules1 - self._rules2
        only2 = self._rules2 - self._rules1
        return only1, only2

    @property
    def conflicts(self):
        """Конфликты: одинаковые условия, разные действия"""
        groups = defaultdict(set)

        for rule in self._rules1 | self._rules2:
            rule_list = list(rule)
            action = rule_list[0]
            condition = frozenset(rule_list[1:])
            groups[condition].add(action)

        result = []
        for condition, actions in groups.items():
            if len(actions) > 1:
                result.append({
                    'condition': list(condition),
                    'actions': list(actions)
                })

        return result

    def superset(self):
        """Проверка надмножества"""
        return self._rules1.issuperset(self._rules2), self._rules2.issuperset(self._rules1)

    def report(self, out_file):
        """Сохранить отчет"""
        only1, only2 = self.diff
        conf = self.conflicts
        sup1, sup2 = self.superset()

        report_data = {
            'total1': len(self._rules1),
            'total2': len(self._rules2),
            'common': len(self._rules1 & self._rules2),
            'only_in_1': len(only1),
            'only_in_2': len(only2),
            'conflicts': len(conf),
            'superset_1_contains_2': sup1,
            'superset_2_contains_1': sup2,
            'is_consistent': (len(only1) == 0 and len(only2) == 0 and len(conf) == 0)
        }

        with open(out_file, 'w') as f:
            json.dump(report_data, f, indent=2)

        logging.info(f"Report saved to {out_file}")
        return report_data