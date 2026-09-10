"""Worker process entrypoint.

The demo API executes jobs inline to remain runnable without infrastructure. This
process intentionally provides a safe placeholder for the production Temporal
worker: it exposes no raw-data API and exits only when the container stops.
"""
from __future__ import annotations

import logging
import signal
import time

running = True


def stop_worker(*_: object) -> None:
    global running
    running = False


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info("AnonFlow demo worker started; inline API processing is enabled")
    signal.signal(signal.SIGTERM, stop_worker)
    signal.signal(signal.SIGINT, stop_worker)
    while running:
        time.sleep(5)
    logging.info("AnonFlow demo worker stopped")


if __name__ == "__main__":
    main()
