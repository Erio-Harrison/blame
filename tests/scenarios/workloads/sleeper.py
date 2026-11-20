#!/usr/bin/env python3
"""Threads that sleep and wake in a loop: many short run-queue waits.

--first-sleep delays the first wake-up, so the threads are asleep when an
agent starts.
"""

import argparse
import threading
import time


def loop(first_sleep, period):
    time.sleep(first_sleep)
    while True:
        time.sleep(period)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--threads", type=int, default=1)
    ap.add_argument("--period-ms", type=float, default=1.0)
    ap.add_argument("--first-sleep", type=float, default=0.0, help="seconds")
    args = ap.parse_args()
    for _ in range(args.threads):
        threading.Thread(
            target=loop, args=(args.first_sleep, args.period_ms / 1000), daemon=True
        ).start()
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
