from abc import ABC, abstractmethod
from typing import Dict, List, Optional
import threading
import queue
import time
from loguru import logger

class BaseEventCollector(ABC):
    """Base class for all event collectors"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.running = False
        self.collection_thread = None
        self.event_queue = queue.Queue()
        self.error_count = 0
        self.max_errors = config.get('max_errors', 100)
        self.last_event_time = time.time()
        self.health_status = True

    def start(self):
        """Start the collector"""
        if not self.running:
            self.running = True
            self.error_count = 0
            self.collection_thread = threading.Thread(target=self._collection_loop)
            self.collection_thread.daemon = True
            self.collection_thread.start()
            logger.info(f"{self.__class__.__name__} started")

    def stop(self):
        """Stop the collector"""
        self.running = False
        if self.collection_thread:
            self.collection_thread.join(timeout=5.0)
        logger.info(f"{self.__class__.__name__} stopped")

    def is_healthy(self) -> bool:
        """Check if the collector is healthy"""
        return self.health_status and self.error_count < self.max_errors

    def _collection_loop(self):
        """Main collection loop"""
        while self.running:
            try:
                events = self._collect_events()
                if events:
                    for event in events:
                        self.event_queue.put(self._normalize_event(event))
                    self.last_event_time = time.time()
                    self.health_status = True
            except Exception as e:
                logger.error(f"Error in {self.__class__.__name__}: {e}")
                self.error_count += 1
                self.health_status = False
                if self.error_count >= self.max_errors:
                    logger.error(f"Max errors reached in {self.__class__.__name__}, stopping")
                    self.running = False
                    break
            time.sleep(self.config.get('collection_interval', 10))

    @abstractmethod
    def _collect_events(self) -> Optional[List]:
        """Collect events from the source"""
        pass

    @abstractmethod
    def _normalize_event(self, event) -> Dict:
        """Normalize event to common format"""
        pass
