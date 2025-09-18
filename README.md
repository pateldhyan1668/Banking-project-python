# Banking CLI — Secure Command-Line Banking System

A secure and robust **command-line banking application** built in **Python**, using:

* **SQLite** for persistent data storage
* **PBKDF2-HMAC-SHA256** for password hashing
* **UUIDv4 account IDs** with human-readable display numbers
* **Cents-accurate integer math** for money handling
* **Transaction ledger with timestamps**

This project demonstrates backend logic, data integrity, and security best practices. It is fully tested with `pytest` and packaged with a `pyproject.toml`.

---

## Features

* Secure user authentication using PBKDF2-HMAC-SHA256 with 200,000 iterations and unique salt per user
* Cents-accurate balance handling (avoids floating-point errors)
* Idempotent database migrations to auto-upgrade legacy schemas
* Full transaction history with timestamps and running balances
* Built-in tax calculation (demonstration at 18% of balance)
* Overflow guard against SQLite 64-bit integer max
* Unit tests with `pytest` for core logic and overflow handling
* Packaged with `pyproject.toml` for installation and execution

---

## Project Structure

```
banking-cli/
│
├── bankingproject_v2.py      # Main CLI application
├── banking_v2.db              # Local SQLite DB (auto-created)
├── tests/
│   └── test_banking.py        # Unit tests
├── pyproject.toml              # Project metadata
├── .gitignore
└── README.md
```

---

## Getting Started

### 1. Clone and set up the environment

```bash
git clone https://github.com/<your-username>/banking-cli.git
cd banking-cli

python -m venv .venv
# Windows
type .venv\\Scripts\\activate
# macOS/Linux
source .venv/bin/activate

pip install -e .[dev]
```

### 2. Run the application

```bash
banking
```

or directly:

```bash
python bankingproject_v2.py
```

A `banking_v2.db` SQLite database will be created automatically in the same folder.

---

## Running Tests

```bash
pytest -q
```

Tests include:

* User signup and login
* Deposit overflow guard near 64-bit max balance

---

## Configuration

* The database path can be configured using the `BANK_DB_PATH` environment variable.

Example:

```bash
set BANK_DB_PATH=mydata.db      # Windows
export BANK_DB_PATH=mydata.db   # macOS/Linux
```

---

## CLI Menu

```
=== Banking System Menu ===
1. Register (Create User)
2. Login
3. Create Account
4. Deposit
5. Withdraw
6. Account Information
7. Account Statement
8. Tax Payable
9. Logout
0. Exit
```

---

## Database Schema

**users**

| column         | type |
| -------------- | ---- |
| username (PK)  | TEXT |
| password\_hash | TEXT |

**accounts**

| column               | type        |
| -------------------- | ----------- |
| account\_id (PK)     | TEXT (UUID) |
| display\_id (unique) | TEXT        |
| account\_holder      | TEXT        |
| balance\_cents       | INTEGER     |
| user\_username (FK)  | TEXT        |

**transactions**

| column                | type                        |
| --------------------- | --------------------------- |
| id (PK)               | INTEGER AUTOINC             |
| account\_id (FK)      | TEXT                        |
| type                  | TEXT (`DEPOSIT`/`WITHDRAW`) |
| amount\_cents         | INTEGER                     |
| balance\_after\_cents | INTEGER                     |
| created\_at           | TEXT                        |
| note                  | TEXT                        |

---

## License

Copyright (c) 2025 Dhyan Patel
All rights reserved.

This project and its source code are the intellectual property of the author.
No part of this project may be copied, modified, distributed, or used in any form without express written permission from the author.

---

## About This Project

This project demonstrates:

* Designing persistent data models and migration logic
* Implementing secure password handling
* Building CLI-based user workflows
* Writing tests and using GitHub Actions CI

This project is intended as a portfolio-ready demonstration of backend design and secure software development practices.
