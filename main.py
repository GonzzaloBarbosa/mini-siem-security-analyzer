
import csv
import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta

# 1. Ler os logs de autenticação
logs = []
alerts = []

with open("logs/auth_logs.csv", "r", encoding="utf-8-sig") as file:
    reader = csv.DictReader(file)

    for log in reader:
        # Converter o timestamp de texto para datetime
        log["timestamp"] = datetime.strptime(
            log["timestamp"], "%Y-%m-%d %H:%M:%S"
        )

        logs.append(log)

# 2. Agrupar tentativas de login falhadas por IP
failed_logins = defaultdict(list)

for log in logs:
    if log["status"] == "FAILED":
        ip = log["source_ip"]
        failed_logins[ip].append(log["timestamp"])


# 3. Detetar 5 falhas num intervalo de 5 minutos
for ip, timestamps in failed_logins.items():
    timestamps.sort()

    for i in range(len(timestamps) - 4):
        first_attempt = timestamps[i]
        fifth_attempt = timestamps[i + 4]

        if fifth_attempt - first_attempt <= timedelta(minutes=5):
            print("[ALERT] Possible brute-force attack detected!")
            print(f"Source IP: {ip}")
            print("Reason: 5 failed login attempts within 5 minutes")

            alerts.append({
                "rule": "BRUTE_FORCE",
                "severity": "MEDIUM",
                "source_ip": ip,
                "timestamp": fifth_attempt.isoformat(),
                "description": "5 failed login attempts within 5 minutes"
            })
        
            break

# 4. Detetar login bem-sucedido após várias falhas
for log in logs:
    if log["status"] != "SUCCESS":
        continue

    ip = log["source_ip"]
    username = log["username"]
    success_time = log["timestamp"]

    # Procurar falhas anteriores do mesmo IP
    recent_failures = [
        timestamp
        for timestamp in failed_logins[ip]
        if timedelta(0) < success_time - timestamp <= timedelta(minutes=5)
    ]

    if len(recent_failures) >= 5:
        print("\n[ALERT] Suspicious successful login detected!")
        print(f"Source IP: {ip}")
        print(f"Username: {username}")
        print(f"Previous failed attempts: {len(recent_failures)}")
        print("Reason: Successful login after multiple failures")

        alerts.append({
            "rule": "SUSPICIOUS_SUCCESSFUL_LOGIN",
            "severity": "HIGH",
            "source_ip": ip,
            "username": username,
            "timestamp": success_time.isoformat(),
            "description": "Successful login after multiple failures"
        })

# 5. Exportar alertas para um relatório JSON

# Criar a pasta reports, caso não exista
Path("reports").mkdir(exist_ok=True)

# Guardar os alertas num ficheiro JSON
with open("reports/security_alerts.json", "w", encoding="utf-8") as file:
    json.dump(alerts, file, indent=4)

print("\nReport generated: reports/security_alerts.json")
print(f"Total alerts: {len(alerts)}")

