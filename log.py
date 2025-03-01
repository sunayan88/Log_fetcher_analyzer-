# log.py
import re
import subprocess
from datetime import datetime, timedelta
from collections import defaultdict

# Define your log sources and subcategories
LOG_SOURCES = {
    "System Logs": {
        "command": "journalctl --no-pager -p emerg..warning",
        "subcategories": {
            "Kernel": r'(kernel|drm|systemd)',
            "Hardware": r'(usb|hdmi|memory|cpu|disk)',
            "Services": r'(started|stopped|failed|service)'
        }
    },
    "Security Logs": {
        "command": "journalctl SYSLOG_FACILITY=4",  # Security/auth logs
        "subcategories": {
            "SSH": r'sshd',
            "Authentication": r'(sudo|su|pam)',
            "Failed Attempts": r'failed'
        }
    },
    "Application Logs": {
        "command": "journalctl --user-unit=*",
        "subcategories": {
            "Web Servers": r'(nginx|apache)',
            "Databases": r'(mysql|postgres)',
            "Containers": r'(docker|podman)'
        }
    }
}

SEVERITY_LEVELS = {
    "CRITICAL": {"patterns": [r'panic', r'oom', r'hard error']},
    "ERROR":    {"patterns": [r'error', r'failed', r'denied']},
    "WARNING":  {"patterns": [r'warning', r'timeout', r'backoff']},
    "INFO":     {"patterns": []}  # fallback if nothing else matches
}

def get_time_filter(range_label):
    """
    Maps a label like 'Last 15 minutes' to a (since, until) datetime range.
    """
    time_map = {
        "Last 15 minutes": timedelta(minutes=15),
        "Last 1 hour": timedelta(hours=1),
        "Last 24 hours": timedelta(hours=24)
    }
    if range_label in time_map:
        since = datetime.now() - time_map[range_label]
        return since.strftime("%Y-%m-%d %H:%M:%S"), "now"
    else:
        # fallback to 24 hours
        since = datetime.now() - timedelta(hours=24)
        return since.strftime("%Y-%m-%d %H:%M:%S"), "now"

def fetch_logs(source_cmd, since, until):
    """
    Fetch logs from journalctl with the given time range.
    Returns a list of log lines (strings).
    """
    try:
        cmd = source_cmd.split() + ["--since", since, "--until", until, "--utc"]
        result = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        # Return error as a single line so the user sees it
        return [f"Error: {e.stderr}"]

def analyze_logs(logs, log_type):
    """
    Categorizes each log line into subcategories & severities.
    Returns a nested dict: { subcategory: { severity: [lines] } }
    """
    analysis = defaultdict(lambda: defaultdict(list))
    subcats = LOG_SOURCES[log_type]["subcategories"] if log_type in LOG_SOURCES else {}

    for line in logs:
        categorized = False
        # Check subcategories
        for subcat, pattern in subcats.items():
            if re.search(pattern, line, re.IGNORECASE):
                # Then check severity
                severity_found = False
                for sev, data in SEVERITY_LEVELS.items():
                    if any(re.search(p, line, re.IGNORECASE) for p in data["patterns"]):
                        analysis[subcat][sev].append(line)
                        severity_found = True
                        break
                if not severity_found:
                    analysis[subcat]["INFO"].append(line)
                categorized = True
                break

        if not categorized:
            # default subcategory "Other"
            severity_found = False
            for sev, data in SEVERITY_LEVELS.items():
                if any(re.search(p, line, re.IGNORECASE) for p in data["patterns"]):
                    analysis["Other"][sev].append(line)
                    severity_found = True
                    break
            if not severity_found:
                analysis["Other"]["INFO"].append(line)

    return analysis
