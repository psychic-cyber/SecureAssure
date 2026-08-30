from backend.app.detection_rules import (
    DetectionRule,
    ExposedDatabaseRule,
    OpenSSHRule,
    get_default_rules,
)


def test_database_rule_implements_detection_rule():
    rule = ExposedDatabaseRule()

    assert isinstance(rule, DetectionRule)


def test_database_rule_metadata():
    rule = ExposedDatabaseRule()

    assert rule.rule_id == "SA-DB-001"
    assert rule.name == "Exposed Database Service"


def test_database_rule_detects_mysql():
    rule = ExposedDatabaseRule()

    finding = rule.evaluate(
        {
            "port": 3306,
            "protocol": "tcp",
            "state": "open",
            "service": "mysql",
            "version": "MySQL 8.0",
        }
    )

    assert finding is not None
    assert finding["rule_id"] == "SA-DB-001"
    assert finding["severity"] == "HIGH"
    assert finding["status"] == "OPEN"


def test_database_rule_detects_postgresql():
    rule = ExposedDatabaseRule()

    finding = rule.evaluate(
        {
            "port": 5432,
            "protocol": "tcp",
            "state": "open",
            "service": "postgresql",
        }
    )

    assert finding is not None
    assert finding["rule_id"] == "SA-DB-001"


def test_database_rule_ignores_closed_port():
    rule = ExposedDatabaseRule()

    finding = rule.evaluate(
        {
            "port": 3306,
            "protocol": "tcp",
            "state": "closed",
            "service": "mysql",
        }
    )

    assert finding is None


def test_database_rule_ignores_non_database_port():
    rule = ExposedDatabaseRule()

    finding = rule.evaluate(
        {
            "port": 8080,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
        }
    )

    assert finding is None


def test_ssh_rule_implements_detection_rule():
    rule = OpenSSHRule()

    assert isinstance(rule, DetectionRule)


def test_ssh_rule_metadata():
    rule = OpenSSHRule()

    assert rule.rule_id == "SA-SSH-001"
    assert rule.name == "Exposed SSH Service"


def test_ssh_rule_detects_open_ssh():
    rule = OpenSSHRule()

    finding = rule.evaluate(
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
            "version": "OpenSSH 9.9",
        }
    )

    assert finding is not None
    assert finding["rule_id"] == "SA-SSH-001"
    assert finding["severity"] == "MEDIUM"
    assert finding["status"] == "OPEN"


def test_ssh_rule_ignores_closed_ssh():
    rule = OpenSSHRule()

    finding = rule.evaluate(
        {
            "port": 22,
            "protocol": "tcp",
            "state": "closed",
            "service": "ssh",
        }
    )

    assert finding is None


def test_default_rules():
    rules = get_default_rules()

    assert len(rules) == 2
    assert all(
        isinstance(rule, DetectionRule)
        for rule in rules
    )



from backend.app.detection_rules.engine import DetectionRuleEngine


def test_rule_engine_evaluates_matching_service():
    engine = DetectionRuleEngine(
        get_default_rules()
    )

    findings = engine.evaluate_service(
        {
            "port": 3306,
            "protocol": "tcp",
            "state": "open",
            "service": "mysql",
            "version": "MySQL 8.0",
        }
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SA-DB-001"


def test_rule_engine_returns_empty_for_no_match():
    engine = DetectionRuleEngine(
        get_default_rules()
    )

    findings = engine.evaluate_service(
        {
            "port": 8080,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
        }
    )

    assert findings == []


def test_rule_engine_evaluates_multiple_services():
    engine = DetectionRuleEngine(
        get_default_rules()
    )

    services = [
        {
            "port": 22,
            "protocol": "tcp",
            "state": "open",
            "service": "ssh",
        },
        {
            "port": 3306,
            "protocol": "tcp",
            "state": "open",
            "service": "mysql",
        },
        {
            "port": 8080,
            "protocol": "tcp",
            "state": "open",
            "service": "http",
        },
    ]

    findings = engine.evaluate_services(services)

    assert len(findings) == 2

    rule_ids = {
        finding["rule_id"]
        for finding in findings
    }

    assert rule_ids == {
        "SA-SSH-001",
        "SA-DB-001",
    }


def test_rule_engine_can_use_custom_rules():
    class AlwaysMatchRule(DetectionRule):
        @property
        def rule_id(self) -> str:
            return "TEST-001"

        @property
        def name(self) -> str:
            return "Test Rule"

        def evaluate(
            self,
            service: dict,
        ) -> dict | None:
            return {
                "rule_id": self.rule_id,
                "title": self.name,
            }

    engine = DetectionRuleEngine(
        [AlwaysMatchRule()]
    )

    findings = engine.evaluate_service(
        {
            "port": 1234,
            "protocol": "tcp",
            "state": "open",
        }
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "TEST-001"
