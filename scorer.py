import argparse
import json
from datetime import datetime
from pathlib import Path


def parse_time(value):
    return datetime.fromisoformat(value)


def normalize(value):
    return value.lower() if isinstance(value, str) else value


def list_contains(items, value):
    if value is None:
        return False
    lowered = normalize(value)
    return any(normalize(item) == lowered for item in items)


def contains_any(text, needles):
    if not text:
        return False
    lowered = text.lower()
    return any(needle.lower() in lowered for needle in needles)


def endswith_any(text, suffixes):
    if not text:
        return False
    lowered = text.lower()
    return any(lowered.endswith(suffix.lower()) for suffix in suffixes)


def is_executable_path(path):
    return endswith_any(path, [".exe", ".dll", ".scr", ".bat", ".ps1"])


def event_matches(event, match):
    if "event_type" in match and event.get("event_type") != match["event_type"]:
        return False
    if "parent_process_in" in match and not list_contains(match["parent_process_in"], event.get("parent_process")):
        return False
    if "process_name_in" in match and not list_contains(match["process_name_in"], event.get("process_name")):
        return False
    if "command_line_contains_any" in match and not contains_any(event.get("command_line"), match["command_line_contains_any"]):
        return False
    if "file_path_endswith_any" in match and not endswith_any(event.get("file_path"), match["file_path_endswith_any"]):
        return False
    if "modified_count_gte" in match and event.get("modified_count", 0) < match["modified_count_gte"]:
        return False
    return True


def score_event_rules(events, rules):
    findings = []
    for index, event in enumerate(events):
        for rule in rules:
            if event_matches(event, rule["match"]):
                findings.append(
                    {
                        "rule_id": rule["id"],
                        "name": rule["name"],
                        "score": rule["score"],
                        "event_indexes": [index],
                    }
                )
    return findings


def score_sequence_rules(events, rules):
    findings = []
    created_files = []

    for index, event in enumerate(events):
        event_type = event.get("event_type")
        file_path = event.get("file_path")

        if event_type == "file_create" and is_executable_path(file_path):
            created_files.append((index, event, file_path))

        if event_type == "process_start" and file_path:
            for created_index, created_event, created_path in created_files:
                if normalize(created_path) != normalize(file_path):
                    continue

                elapsed = (parse_time(event["timestamp"]) - parse_time(created_event["timestamp"])).total_seconds()
                for rule in rules:
                    if rule["id"] == "download_execute" and 0 <= elapsed <= rule["within_seconds"]:
                        findings.append(
                            {
                                "rule_id": rule["id"],
                                "name": rule["name"],
                                "score": rule["score"],
                                "event_indexes": [created_index, index],
                            }
                        )
    return findings


def severity_for(score, thresholds):
    if score >= thresholds["high"]:
        return "HIGH"
    if score >= thresholds["medium"]:
        return "MEDIUM"
    if score >= thresholds["low"]:
        return "LOW"
    return "INFO"


def load_json(path):
    with Path(path).open("r", encoding="utf-8") as file:
        return json.load(file)


def score(events, rules):
    event_findings = score_event_rules(events, rules["event_rules"])
    sequence_findings = score_sequence_rules(events, rules["sequence_rules"])
    findings = event_findings + sequence_findings
    total = sum(item["score"] for item in findings)
    return {
        "score": total,
        "severity": severity_for(total, rules["thresholds"]),
        "findings": findings,
    }


def alert_for(result):
    return "suspicious behavior detected" if result["severity"] in {"MEDIUM", "HIGH"} else "no high-risk behavior detected"


def print_report(result):
    alert = alert_for(result)

    print(f"Risk Score: {result['score']}")
    print(f"Severity: {result['severity']}")
    print(f"Alert: {alert}")

    if result["findings"]:
        print()
        print("Reasons:")
        for finding in result["findings"]:
            print(f"- {finding['name']} (+{finding['score']})")
    else:
        print()
        print("Reasons: none")


def print_json_report(result):
    report = {
        "risk_score": result["score"],
        "severity": result["severity"],
        "alert": alert_for(result),
        "findings": result["findings"],
    }
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Score endpoint event scenarios.")
    parser.add_argument("events", help="Path to an event scenario JSON file")
    parser.add_argument("--rules", default="rules.json", help="Path to rules JSON")
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON output")
    args = parser.parse_args()

    events = load_json(args.events)
    rules = load_json(args.rules)
    result = score(events, rules)
    if args.json:
        print_json_report(result)
    else:
        print_report(result)


if __name__ == "__main__":
    main()
