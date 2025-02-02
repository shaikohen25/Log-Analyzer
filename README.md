
# Log Analyzer: Detecting Security Threats in Linux Logs

## Overview
This Python-based log analyzer scans system logs for potential security threats such as brute force attacks and DDoS attempts. By parsing log files, it identifies suspicious activity and provides insights for security monitoring.

## Features
- Detects SSH brute force attacks by analyzing repeated failed login attempts in `/var/log/auth.log`.
- Identifies potential DDoS attacks by flagging high-volume HTTP requests in `/var/log/apache2/access.log`.
- Uses regular expressions for efficient log parsing.
- Supports automated analysis and alerting.

## Requirements
- Python 3.x
- Required Python libraries:
  ```
  pip install pandas
  ```

## Usage
1. Clone the repository:
   ```
   git clone https://github.com/shaikohen25/log-analyzer.git
   cd log-analyzer
   ```
2. Run the script with root privileges:
   ```
   sudo python3 log_analyzer.py
   ```
3. The script will output detected anomalies based on log analysis.

## Future Improvements
- Implement automatic IP blocking for detected threats.
- Add email or webhook alerts for real-time monitoring.
- Extend log analysis for additional security events.

