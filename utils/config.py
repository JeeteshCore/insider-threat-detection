import os
from dotenv import load_dotenv

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "db/insider_threat.db")

MONITORING_INTERVAL_SECONDS = 5

LOG_DIR = "logs/"

RISK_THRESHOLDS = {
    "low":    (0,  40),
    "medium": (41, 70),
    "high":   (71, 100)
}

RISK_WEIGHTS = {
    "failed_login":          20,
    "off_hours_login":       25,
    "high_file_access":      30,
    "privilege_change":      40,
    "sensitive_file_access": 35,
}

WORK_HOURS_START = 9
WORK_HOURS_END   = 18

DEMO_USERS = [
    "vikas", "amit", "priya", "rahul",
    "sneha", "admin", "dev_user", "intern_01"
]

SENSITIVE_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/var/log/auth.log",
    "/home/admin/confidential",
    "/database/backup",
]