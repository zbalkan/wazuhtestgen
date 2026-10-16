from __future__ import annotations

import os

from .iniParser import IniParser, TestCase
from .naming import identifier

_EXCLUDED_INI_FILES = {"user.ini"}
_EXCLUDED_INI_CASES = {
    "oscap.ini": {"openscap rule notapplicable"},
}


def _python_log_literal(value: str) -> str:
    trailing_backslashes = len(value) - len(value.rstrip("\\"))
    if trailing_backslashes % 2:
        return repr(value)

    for delimiter in ('"""', "'''"):
        quote = delimiter[0]
        if (
            delimiter not in value
            and not value.startswith(quote)
            and not value.endswith(quote)
        ):
            return f"r{delimiter}{value}{delimiter}"

    return repr(value)


def _python_logs_literal(values: tuple[str, ...]) -> str:
    rendered = ", ".join(_python_log_literal(value) for value in values)
    if len(values) == 1:
        rendered += ","
    return f"({rendered})"


class IniConverter:
    header_template = """\
#!/usr/bin/env python3

# These test cases are based on log data and rule descriptions used for regression testing,
# potentially derived from or inspired by Wazuh rulesets and public log samples.

import pytest
from wazuhtester import LogtestStatus, send_log{multiple_import}

pytestmark = pytest.mark.wazuh_logtest


# Converted from {ini_file_name}
"""

    positive_test_template = """\
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
{parameters}
    ],
)
def test_rule_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is LogtestStatus.RuleMatch
    assert response.decoder == decoder
    assert response.rule_id == rule_id
    assert response.rule_level == rule_level


"""

    positive_multiple_test_template = """\
@pytest.mark.parametrize(
    ("logs", "decoder", "rule_id", "rule_level"),
    [
{parameters}
    ],
)
def test_rule_match_multiple_logs(
    logs: tuple[str, ...],
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    responses = send_multiple_logs(list(logs))
    response = responses[-1]

    assert response.status is LogtestStatus.RuleMatch
    assert response.decoder == decoder
    assert response.rule_id == rule_id
    assert response.rule_level == rule_level


"""

    negative_test_template = """\
@pytest.mark.parametrize(
    ("log", "decoder", "rule_id", "rule_level"),
    [
{parameters}
    ],
)
def test_rule_does_not_match(
    log: str,
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    response = send_log(log)

    assert response.status is not LogtestStatus.Error
    assert (
        response.decoder,
        response.rule_id,
        response.rule_level,
    ) != (
        decoder,
        rule_id,
        rule_level,
    )


"""

    negative_multiple_test_template = """\
@pytest.mark.parametrize(
    ("logs", "decoder", "rule_id", "rule_level"),
    [
{parameters}
    ],
)
def test_rule_does_not_match_multiple_logs(
    logs: tuple[str, ...],
    decoder: str,
    rule_id: str,
    rule_level: int,
) -> None:
    responses = send_multiple_logs(list(logs))

    assert all(
        response.status is not LogtestStatus.Error
        for response in responses
    )
    assert all(
        (
            response.decoder,
            response.rule_id,
            response.rule_level,
        )
        != (
            decoder,
            rule_id,
            rule_level,
        )
        for response in responses
    )


"""

    def convert(self, wazuh_ini_test: str, output_directory: str) -> None:
        """Convert a Wazuh INI regression-test file to native pytest tests."""

        ini_file_name = os.path.basename(wazuh_ini_test).lower()
        ini_base_name = os.path.splitext(ini_file_name)[0]
        sanitized = identifier(ini_base_name)
        test_file_name = os.path.join(
            output_directory,
            f"test_{sanitized}_rules.py",
        )

        if ini_file_name in _EXCLUDED_INI_FILES:
            if os.path.exists(test_file_name):
                os.remove(test_file_name)
            print(f"Excluded upstream corpus file {ini_file_name}")
            return

        parser = IniParser()
        excluded_cases = _EXCLUDED_INI_CASES.get(ini_file_name, set())
        test_cases = [
            case
            for case in parser.parse(wazuh_ini_test)
            if case.header not in excluded_cases
        ]

        if not test_cases:
            print(f"No test cases found in {wazuh_ini_test}")
            return

        positive = [case for case in test_cases if case.condition == "pass"]
        negative = [case for case in test_cases if case.condition == "fail"]
        positive_single = [case for case in positive if len(case.logs) == 1]
        positive_multiple = [case for case in positive if len(case.logs) > 1]
        negative_single = [case for case in negative if len(case.logs) == 1]
        negative_multiple = [case for case in negative if len(case.logs) > 1]

        generated = self.header_template.format(
            ini_file_name=os.path.basename(wazuh_ini_test),
            multiple_import=(
                ", send_multiple_logs" if positive_multiple or negative_multiple else ""
            ),
        )

        if positive_single:
            generated += self.positive_test_template.format(
                parameters=self._render_single_parameters(positive_single)
            )

        if positive_multiple:
            generated += self.positive_multiple_test_template.format(
                parameters=self._render_multiple_parameters(positive_multiple)
            )

        if negative_single:
            generated += self.negative_test_template.format(
                parameters=self._render_single_parameters(negative_single)
            )

        if negative_multiple:
            generated += self.negative_multiple_test_template.format(
                parameters=self._render_multiple_parameters(negative_multiple)
            )

        with open(test_file_name, "w", encoding="utf-8") as test_file:
            test_file.write(generated)

        print(f"Test file {test_file_name} created successfully.")

    @staticmethod
    def _render_single_parameters(test_cases: list[TestCase]) -> str:
        return "\n".join(
            (
                "        pytest.param(\n"
                f"            {_python_log_literal(case.logs[0])},\n"
                f"            {case.decoder!r},\n"
                f"            {case.rule!r},\n"
                f"            {case.alert},\n"
                f"            id={identifier(case.header)!r},\n"
                "        ),"
            )
            for case in test_cases
        )

    @staticmethod
    def _render_multiple_parameters(test_cases: list[TestCase]) -> str:
        return "\n".join(
            (
                "        pytest.param(\n"
                f"            {_python_logs_literal(case.logs)},\n"
                f"            {case.decoder!r},\n"
                f"            {case.rule!r},\n"
                f"            {case.alert},\n"
                f"            id={identifier(case.header)!r},\n"
                "        ),"
            )
            for case in test_cases
        )
