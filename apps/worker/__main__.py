import argparse
import json
import logging
import signal

from packages.config import Settings
from packages.storage.database import Database
from packages.storage.queue import Queue
from packages.storage.service import DataService
from packages.storage.worker import Worker

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--max-jobs", type=int, default=None)
    args = parser.parse_args()
    if args.max_jobs is not None and args.max_jobs < 1:
        parser.error("--max-jobs must be positive")
    settings = Settings()
    service = DataService(Database(settings), settings)
    worker = Worker(service, Queue(service.db, settings))
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    signal.signal(signal.SIGINT, lambda *_: worker.stop.set())
    signal.signal(signal.SIGTERM, lambda *_: worker.stop.set())
    if args.once:
        print(json.dumps({"stage": "d3", "processed": worker.run_one()}))
    else:
        worker.run(max_jobs=args.max_jobs)
