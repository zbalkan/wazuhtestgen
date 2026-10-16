from __future__ import annotations

import logging
import os
import pathlib
import xml.etree.ElementTree as ET
from typing import Any, Final

from .naming import claim_unique_name, identifier

ENCODING: Final[str] = "utf-8"
PLACEHOLDER_LOG: Final[str] = "TODO: provide a matching log here"

logger = logging.getLogger(__name__)


class RuleConverter:
    def convert(self, input_directory: str, output_directory: str) -> None:
        output_names: dict[str, str] = {}

        for root, _, files in os.walk(input_directory):
            for filename in [name for name in files if name.endswith(".xml")]:
                file_path = pathlib.Path(root, filename)

                rel_path = str(file_path.relative_to(input_directory))
                logger.info("Processing rule file: %s", rel_path)

                rules = self.__collect_rules_from_file(file_path)
                test_code = self.__generate_pytest_code(rules)

                output_name = claim_unique_name(
                    identifier(rel_path.removesuffix(".xml")),
                    rel_path,
                    output_names,
                    kind="rule output module",
                )
                test_file_path = os.path.join(
                    output_directory,
                    f"test_{output_name}.py",
                )

                os.makedirs(output_directory, exist_ok=True)
                with open(test_file_path, "w", encoding=ENCODING) as test_file:
                    test_file.write(test_code)

                print(f"Test file '{test_file_path}' generated successfully.")

    def __collect_rules_from_file(
        self, rule_file: pathlib.Path
    ) -> list[dict[str, Any]]:
        text = rule_file.read_text(encoding=ENCODING)
        root = ET.fromstring(f"<root>{text}</root>")
        rules: list[dict[str, Any]] = []

        def recurse(element: ET.Element, inherited: list[str]) -> None:
            if element.tag == "group" and element.get("name"):
                names = [group for group in element.get("name", "").split(",") if group]
                inherited = inherited + names

            if element.tag == "rule":
                rule_id = element.get("id")
                level = element.get("level")
                descriptions = [
                    description.text.strip()
                    for description in element.findall("description")
                    if description.text
                ]
                description = " ".join(descriptions) if descriptions else ""

                groups = list(inherited)
                group_element = element.find("groups")
                if group_element is not None and group_element.text:
                    groups += [
                        group.strip()
                        for group in group_element.text.split(",")
                        if group.strip()
                    ]

                rules.append(
                    {
                        "id": rule_id,
                        "level": level,
                        "description": description,
                        "groups": groups,
                    }
                )

            for child in element:
                recurse(child, inherited.copy())

        recurse(root, [])
        return rules

    def __generate_pytest_code(self, rules: list[dict[str, Any]]) -> str:
        lines = [
            "import pytest",
            "from wazuhtester import LogtestStatus, send_log",
            "",
            "pytestmark = pytest.mark.wazuh_logtest",
            "",
            "",
        ]

        test_names: dict[str, str] = {}

        for rule in rules:
            rule_id = rule["id"]
            level = rule["level"]
            description = rule["description"]
            groups = rule["groups"]
            source_name = f"rule {rule_id}"
            test_name = claim_unique_name(
                identifier(f"rule_{rule_id}"),
                source_name,
                test_names,
                kind="rule test function",
            )

            lines.append(
                f"@pytest.mark.skip(reason={f'Provide a log matching rule {rule_id}'!r})"
            )
            lines.append(f"def test_{test_name}() -> None:")
            lines.append(f"    log = {PLACEHOLDER_LOG!r}")
            lines.append("    response = send_log(log)")
            lines.append("")
            lines.append("    assert response.status is LogtestStatus.RuleMatch")
            lines.append(f"    assert response.rule_id == {rule_id!r}")
            lines.append(
                f"    assert response.rule_level == "
                f"{int(level) if level is not None else None}"
            )
            lines.append(f"    assert response.rule_description == {description!r}")
            for group in groups:
                lines.append(f"    assert {group!r} in response.rule_groups")
            lines.extend(["", ""])

        return "\n".join(lines)
