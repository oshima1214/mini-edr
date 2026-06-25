# Mini EDR Scoring Prototype

Windows endpoint behavior scoring prototype for a security portfolio project.

This first version does not monitor the real system. It reads safe, hand-written
event scenarios from JSON files and scores suspicious behavior using explainable
rules.

## Goal

Detect suspicious behavior from a sequence of endpoint events, not from a single
indicator. The scorer evaluates process relationships, network activity, file
creation, and event timing, then explains why the score increased.

## Run

```bash
python scorer.py events/suspicious_office_macro.json
python scorer.py events/normal_dev_workflow.json
```

## Test

```bash
python -m unittest discover -s tests
```

## Example

```text
Risk Score: 90
Severity: HIGH
Alert: suspicious behavior detected

Reasons:
- Office process launched a script interpreter (+30)
- Script interpreter made a network connection (+20)
- Executable file was created (+20)
- Created executable was launched soon (+20)
```

## Current Scope

- Reads sample events from JSON
- Scores individual events
- Scores correlated event sequences
- Prints severity and rule reasons

## Out of Scope

- Real malware execution
- Automatic blocking or deletion
- Kernel drivers
- Memory inspection
- Background monitoring

## Roadmap

1. Add more normal and suspicious scenarios
2. Add unit tests for expected scores
3. Store events and alerts in SQLite
4. Add a FastAPI dashboard API
5. Add a simple web timeline
6. Add safe Windows event collection with `psutil` and `watchdog`
7. Add Sysmon log import support
