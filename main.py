import os
import sys
import time
import json
import queue
import threading
import urllib.request

LOG_FILE_PATH = "/var/log/auth.log"

# طابور الأحداث المشتركة بين Producer و Monitor
event_queue = queue.Queue()

SUSPICIOUS_KEYWORDS = [
    "Failed password",
    "invalid user",
    "authentication failure",
    "Connection refused",
    "POSSIBLE BREAK-IN ATTEMPT"
]

# ==========================================
# 1. PRODUCER BOT: يقرأ اللوجات ويغذي الطابور
# ==========================================
def producer_bot(filepath):
    print("[+] Producer Bot initialized: Monitoring raw log file...")
    if not os.path.exists(filepath):
        print(f"[-] Producer Error: File '{filepath}' not found.")
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(0, os.SEEK_END)  # البدء من نهاية الملف للأحداث الحية
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.5)
                    continue

                if any(keyword in line for keyword in SUSPICIOUS_KEYWORDS):
                    event = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "raw_log": line.strip()
                    }
                    print(f"\n[Producer Bot] Captured suspicious log -> Pushing to queue.")
                    event_queue.put(event)
    except Exception as e:
        print(f"[-] Producer Bot Error: {e}")

# ==========================================
# 2. MONITOR BOT: يعالج الطابور ويجهز الأحداث
# ==========================================
def monitor_bot():
    print("[+] Monitor Bot initialized: Ready to process event queue...")
    while True:
        event = event_queue.get()
        if event is None:
            break

        print(f"[Monitor Bot] Processing event from queue captured at {event['timestamp']}...")
        
        # تحضير الحدث وتمريره لبوت الذكاء الاصطناعي
        ai_soar_bot(event)
        event_queue.task_done()

# ==========================================
# 3. AI-SOAR BOT: يحلل الأحداث باستخدام Ollama
# ==========================================
def ai_soar_bot(event_data):
    print("[AI-SOAR Bot] Querying Ollama (qwen2.5:1.5b) for threat analysis...")
    
    prompt_text = f"""
You are the AI-SOAR Decision Engine in a 3-tier security pipeline (Producer -> Monitor -> AI-SOAR).
Analyze the following event escalated by the Monitor Bot:

Event Time: {event_data['timestamp']}
Raw Log: {event_data['raw_log']}

Respond in structured format:
1. Threat Level: (Low / Medium / High / Critical)
2. Incident Summary:
3. Automated Response Action:
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
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode("utf-8"))
            print("\n=================== 3-TIER SOAR INCIDENT REPORT ===================")
            print(result.get("response"))
            print("===================================================================\n")
    except Exception as e:
        print(f"[-] AI-SOAR Bot Error: {e}")

# ==========================================
# MAIN WORKFLOW EXECUTION
# ==========================================
if __name__ == "__main__":
    print("=== Starting CloudEdge 3-Tier SOAR Engine (Producer - Monitor - AI) ===")

    # تشغيل Producer Bot في Thread مستقل
    t_producer = threading.Thread(target=producer_bot, args=(LOG_FILE_PATH,), daemon=True)
    t_producer.start()

    # تشغيل Monitor Bot في Thread مستقل
    t_monitor = threading.Thread(target=monitor_bot, daemon=True)
    t_monitor.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down 3-Tier SOAR Pipeline.")
