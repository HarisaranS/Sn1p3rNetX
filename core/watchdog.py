"""
watchdog.py — Continuous network monitoring daemon.
"""
import time
import threading

class WatchdogDaemon:
    def __init__(self, target: str, interval: int = 15):
        self.target = target
        self.interval = interval
        self.running = False
        self._thread = None
        
    def start(self):
        self.running = True
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        
    def stop(self):
        self.running = False
        if self._thread:
            self._thread.join(timeout=2)
            
    def _run(self):
        while self.running:
            # Simulated check
            time.sleep(self.interval * 60)

def start_watchdog(target: str, interval_minutes: int = 15, webhook_url: str = None, slack_webhook: str = None, on_alert=None):
    daemon = WatchdogDaemon(target, interval_minutes)
    daemon.start()
    return daemon
