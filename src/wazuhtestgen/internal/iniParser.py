from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal


@dataclass(frozen=True)
class TestCase:
    header: str
    logs: tuple[str, ...]
    condition: Literal["pass", "fail"]
    rule: str
    alert: int
    decoder: str

    def __str__(self) -> str:
        return (
            f"Test Case: {self.header}\n"
            f"Logs: {self.logs}\n"
            f"Condition: {self.condition}\n"
            f"Rule ID: {self.rule}\n"
            f"Alert level: {self.alert}\n"
            f"Decoder: {self.decoder}"
        )


class IniParser:
    def parse(self, path: str) -> list[TestCase]:
        sections = self.__split(path)
        test_cases: list[TestCase] = []
        for section in sections:
            lines = self.__read(section)
            if lines:
                test_cases.extend(lines)

        return test_cases

    def __read(self, lines: list[str]) -> list[TestCase] | None:
        header = lines[0].replace("[", "").replace("]", "").lower()
        log_groups: dict[
            str,
            tuple[Literal["pass", "fail"], list[str]],
        ] = {}
        rule: str | None = None
        alert: int | None = None
        decoder: str | None = None

        pairs: list[tuple[str, str]] = []
        unkeyed_lines: list[str] = []
        assignment_pattern = re.compile(r"^[A-Za-z_][A-Za-z0-9_. -]*\s*=")
        for line in lines[1:]:
            if not line or line.startswith(("#", ";")):
                continue

            if not assignment_pattern.match(line):
                unkeyed_lines.append(line)
                continue

            delim = line.index("=")
            key = line[:delim].strip()
            value = line[delim + 1 :].strip()
            pairs.append((key, value))

        if unkeyed_lines:
            keyed_logs = any(key.startswith("log") for key, _ in pairs)
            if len(unkeyed_lines) != 1 or keyed_logs:
                raise ValueError(f"Invalid unkeyed log data under {header}.")
            pairs.insert(0, ("log 1 pass", unkeyed_lines[0]))

        if not pairs:
            return None

        for key, value in pairs:
            if key.startswith("log"):
                parts = key.split()
                if len(parts) < 3 or parts[2] not in {"pass", "fail"}:
                    raise ValueError(
                        f"Invalid log condition '{key}' under {header}. "
                        "Expected 'log <number> pass' or 'log <number> fail'."
                    )

                condition: Literal["pass", "fail"] = (
                    "pass" if parts[2] == "pass" else "fail"
                )
                if key in log_groups:
                    log_groups[key][1].append(value)
                else:
                    log_groups[key] = (condition, [value])
            elif key.startswith("rule"):
                rule = value
            elif key.startswith("alert"):
                try:
                    alert = int(value)
                except ValueError as exc:
                    raise ValueError(
                        f"Invalid alert level '{value}' under {header}."
                    ) from exc
            elif key.startswith("decoder"):
                decoder = value

        if not log_groups:
            return None

        missing = [
            name
            for name, value in (
                ("rule", rule),
                ("alert", alert),
                ("decoder", decoder),
            )
            if value is None
        ]
        if missing:
            raise ValueError(f"Missing {', '.join(missing)} under {header}.")

        assert rule is not None
        assert alert is not None
        assert decoder is not None

        groups = list(log_groups.values())
        if len(groups) == 1:
            condition, logs = groups[0]
            return [
                TestCase(
                    header,
                    tuple(logs),
                    condition,
                    rule,
                    alert,
                    decoder,
                )
            ]

        return [
            TestCase(
                f"{header} - {index}",
                tuple(logs),
                condition,
                rule,
                alert,
                decoder,
            )
            for index, (condition, logs) in enumerate(groups, start=1)
        ]

    def __split(self, path: str) -> list[list[str]]:
        sections: list[list[str]] = []
        current_section: list[str] = []
        section_header_pattern = re.compile(r"^\[(.*?)\]$")

        with open(path, "r", encoding="utf-8") as infile:
            for line in infile:
                line = line.strip()

                if section_header_pattern.match(line):
                    if current_section:
                        sections.append(current_section)
                        current_section = []

                    current_section.append(line)
                elif current_section:
                    current_section.append(line)

            if current_section:
                sections.append(current_section)

        return sections
