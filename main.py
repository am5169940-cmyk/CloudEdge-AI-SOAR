import os
import sys
import time
import json
import urllib.request

LOG_FILE_PATH = "/var/log/auth.log"

# الكلمات المفتاحية التي تستدعي التحليل الأمني الفوري
SUSPICIOUS_KEYWORDS = [
    "Failed password",
    "invalid user",
    "authentication failure",
    "Connection refused",
    "POSSIBLE BREAK-IN ATTEMPT"
]

def analyze_with_ollama(log_event):
    """إرسال الحدث المشبوه فوراً إلى Ollama"""
    prompt_text = f"""
You are an automated SOAR Real-time Incident Response Engine.
A suspicious security event was just detected in /var/log/auth.log.

Log Event:
{log_event}

Provide a fast breakdown:
- Threat Type:
- Severity: (Low / Medium / High / Critical)
- Recommended Action:
"""

    url = "http://127.0.0.1:11434/api/generate"
    payload = {
        "model": "qwen2.5:1.5b",
        "prompt": prompt_text,
        "stream": False,
    }

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )

    try:
        print("\n[!] SUSPICIOUS EVENT DETECTED! Sending to Ollama...")
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode("utf-8"))
            print("=================== LIVE ALERT REPORT ===================")
            print(result.get("response"))
            print("=========================================================\n")
    except Exception as e:
        print("[-] Error connecting to Ollama:", e)

def monitor_auth_log(filepath):
    """مراقبة ملف auth.log في الوقت الفعلي"""
    if not os.path.exists(filepath):
        print(f"[-] Error: File '{filepath}' does not exist.")
        sys.exit(1)

    print(f"[*] Starting SOAR Live Monitor on '{filepath}'...")
    print("[*] Press Ctrl+C to stop.\n")

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            # الانتقال إلى نهاية الملف لمراقبة الأحداث الجديدة فقط
            f.seek(0, os.SEEK_END)

            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)  # الانتظار في حال عدم وجود أسطر جديدة
                    continue

                # التجميع والتحقق من وجود أنشطة مشبوهة
                if any(keyword in line for keyword in SUSPICIOUS_KEYWORDS):
                    analyze_with_ollama(line.strip())

    except PermissionError:
        print("[-] Permission Denied! Run with 'sudo'.")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping SOAR Live Monitor.")

if __name__ == "__main__":
    monitor_auth_log(LOG_FILE_PATH)
