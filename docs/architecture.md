# CloudProwler Architecture

## Overview

CloudProwler follows a modular architecture that separates command-line interaction, AWS security checks, report generation, and visualization.

```
                 +--------------------+
                 |      main.py       |
                 +---------+----------+
                           |
             +-------------+--------------+
             |                            |
      AWS Security Scanner          Report Generator
             |                            |
      Security Findings        JSON / HTML Reports
             |                            |
             +-------------+--------------+
                           |
                     Risk Scoring
```

## Components

### main.py

- CLI entry point
- Parses command-line arguments
- Coordinates scanning

### scanner/aws_checks.py

Responsible for:

- IAM checks
- S3 checks
- EC2 checks
- Security Group analysis

### scanner/reporter.py

Responsible for:

- JSON export
- HTML dashboard generation

## Design Principles

- Modular
- Maintainable
- Extensible
- Separation of concerns