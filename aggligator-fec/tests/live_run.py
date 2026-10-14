#!/usr/bin/env python3
"""Portable local subprocess helper. No SSH, topology or remote deployment code.

The historical local CLI tests imported Node from a host-specific WAN script.
This branch keeps only that reusable process wrapper, so the test suite does
not require the retired repository or private machine configuration.
"""
import json
from pathlib import Path
import subprocess
import threading
import time

ROOT = Path(__file__).resolve().parents[2]

class Node:
    def __init__(self, name, argv):
        self.name = name
        self.records = []
        self.errors = []
        self.condition = threading.Condition()
        self.process = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        threading.Thread(target=self._errors, daemon=True).start()
        try:
            self.wait("ready", timeout=20)
        except Exception:
            self.close()
            raise

    def _read(self):
        for line in self.process.stdout:
            try:
                value = json.loads(line)
            except json.JSONDecodeError:
                value = {"event": "text", "line": line.strip()}
            with self.condition:
                self.records.append(value)
                self.condition.notify_all()

    def _errors(self):
        for line in self.process.stderr:
            self.errors.append(line.strip())

    def command(self, **command):
        self.process.stdin.write(json.dumps(command) + "\n")
        self.process.stdin.flush()

    def wait(self, event, run=None, timeout=20, since=0):
        end = time.monotonic() + timeout
        with self.condition:
            while True:
                for item in self.records[since:]:
                    if item.get("event") == event and (run is None or item.get("run") == run):
                        return item
                    if item.get("event") == "error":
                        raise RuntimeError(f"{self.name}: {item}")
                if self.process.poll() is not None:
                    raise RuntimeError(f"{self.name} exited {self.process.returncode}: {self.errors}; {self.records[-3:]}")
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"{self.name} waiting {event}: errors={self.errors}, records={self.records[-3:]}")
                self.condition.wait(min(remaining, .2))

    def report(self, run=None):
        since = len(self.records)
        self.command(op="report")
        event = "report" if run is not None else ("relay_report" if self.name in ("j", "jx2") else "probe_report")
        return self.wait(event, run=run, since=since)

    def close(self):
        try:
            if self.process.poll() is None:
                self.command(op="quit")
                self.process.stdin.close()
                self.process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.process.terminate()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.reader.join(timeout=1)
