# 🔍 Log Analysis & Threat Detection
A simple yet effective Python-based security log analysis tool that parses log files, maps detected events to MITRE ATT&CK tactics and techniques, and generates a structured incident report.

## 🚀 Features
Detects suspicious events based on log content

Maps detections to MITRE ATT&CK techniques

Counts failed login attempts per IP

Generates a clear text-based security incident report

## 🛠️ Installation
*Clone the repository:*

``git clone https://github.com/PrathamBhanushali30/simple_log_monitoring_and_report_generation.git </n>
 cd log_analysis_project``

## ▶️ Usage
*Run the detection script:*

`python detection.py`
The generated incident report will be saved as **report.txt**.

## 📌 Requirements
*Python 3.x*

*SSH log file (auth.log)* in the project directory

*mitre_mapping.json* file for event-to-ATT&CK mapping

📚 License
This project is for educational and security awareness purposes.
