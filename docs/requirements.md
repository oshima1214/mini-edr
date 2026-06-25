# Requirements

## Purpose

Mini EDR is a learning-oriented endpoint behavior scoring prototype. It evaluates
safe event scenarios and explains why behavior is considered suspicious.

## Functional Requirements

| ID | Requirement |
| --- | --- |
| FR-1 | Read endpoint event scenarios from JSON files. |
| FR-2 | Apply event-level detection rules. |
| FR-3 | Apply sequence-level detection rules across related events. |
| FR-4 | Calculate a total risk score. |
| FR-5 | Classify the result as INFO, LOW, MEDIUM, or HIGH. |
| FR-6 | Print detection reasons with score contributions. |
| FR-7 | Provide tests for normal and suspicious scenarios. |

## Non-Functional Requirements

| ID | Requirement |
| --- | --- |
| NFR-1 | The prototype must not execute malware or offensive payloads. |
| NFR-2 | The scoring logic should be explainable. |
| NFR-3 | The first version should run with only Python standard libraries. |
| NFR-4 | Rules should be editable without changing the core scoring code. |
| NFR-5 | Test scenarios should be reproducible. |

## Current Out of Scope

- Real-time endpoint monitoring
- Automatic blocking, deletion, or quarantine
- Kernel drivers
- Memory forensics
- Malware sample execution

