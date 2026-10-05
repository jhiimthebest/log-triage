# Log Triage Tool

A Python tool that reads SSH login logs and detects brute-force attacks.

## What it does
- Reads Linux auth logs
- Flags IPs with too many failed logins
- Saves alerts to a SQLite database

## How to run
python3 parser.py sample_auth.log

## Coming next
- Machine learning to find unusual activity
- AI summaries of each alert
