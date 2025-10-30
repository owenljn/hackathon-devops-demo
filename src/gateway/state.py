# State management for webhook events and PR tracking

import os
import json
import logging
from typing import Dict, Optional, List
from threading import Lock

logger = logging.getLogger(__name__)

class EventStore:
    """Simple in-memory event store with optional JSON persistence"""

    def __init__(self, persistence_file: Optional[str] = None):
        self._events: Dict[str, Dict] = {}
        self._lock = Lock()
        self._persistence_file = persistence_file or os.getenv("EVENT_STORE_FILE", "event_store.json")

        # Load existing data if file exists
        self._load_from_file()

    def _load_from_file(self):
        """Load events from JSON file"""
        if not os.path.exists(self._persistence_file):
            return

        try:
            with open(self._persistence_file, 'r') as f:
                self._events = json.load(f)
            logger.info(f"Loaded {len(self._events)} events from {self._persistence_file}")
        except Exception as e:
            logger.error(f"Error loading event store: {str(e)}")

    def _save_to_file(self):
        """Save events to JSON file"""
        try:
            with open(self._persistence_file, 'w') as f:
                json.dump(self._events, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving event store: {str(e)}")

    def store_event(self, event_id: str, event_data: Dict):
        """Store event data with given ID"""
        with self._lock:
            self._events[event_id] = {
                **event_data,
                "stored_at": "now",  # Could use datetime if needed
            }
            self._save_to_file()
            logger.debug(f"Stored event {event_id}")

    def get_event(self, event_id: str) -> Optional[Dict]:
        """Retrieve event data by ID"""
        with self._lock:
            return self._events.get(event_id)

    def update_event(self, event_id: str, updates: Dict):
        """Update event data"""
        with self._lock:
            if event_id in self._events:
                self._events[event_id].update(updates)
                self._save_to_file()
                logger.debug(f"Updated event {event_id}")
            else:
                logger.warning(f"Event {event_id} not found for update")

    def delete_event(self, event_id: str):
        """Delete event data"""
        with self._lock:
            if event_id in self._events:
                del self._events[event_id]
                self._save_to_file()
                logger.debug(f"Deleted event {event_id}")

    def list_events(self) -> Dict[str, Dict]:
        """List all events"""
        with self._lock:
            return self._events.copy()

    def get_pr_url_for_event(self, event_id: str) -> Optional[str]:
        """Get PR URL for a specific event"""
        event = self.get_event(event_id)
        return event.get("pr_url") if event else None

    def set_pr_url_for_event(self, event_id: str, pr_url: str):
        """Set PR URL for a specific event"""
        self.update_event(event_id, {"pr_url": pr_url})

# Global event store instance
event_store = EventStore()

def generate_event_id(repo: str, commit_sha: str) -> str:
    """Generate a unique event ID from repo and commit"""
    return f"{repo}#{commit_sha}"

def is_duplicate_event(repo: str, commit_sha: str) -> bool:
    """Check if we've already processed this repo/commit combination"""
    event_id = generate_event_id(repo, commit_sha)
    existing = event_store.get_event(event_id)

    if existing:
        logger.info(f"Duplicate event detected: {event_id}")
        return True

    return False

def store_push_event(repo: str, branch: str, commit_sha: str, changed_paths: list):
    """Store a push event"""
    event_id = generate_event_id(repo, commit_sha)
    event_data = {
        "type": "push",
        "repo": repo,
        "branch": branch,
        "commit_sha": commit_sha,
        "changed_paths": changed_paths,
        "status": "processing"
    }
    event_store.store_event(event_id, event_data)
    return event_id

def update_event_status(event_id: str, status: str, **kwargs):
    """Update event processing status"""
    updates = {"status": status, **kwargs}
    event_store.update_event(event_id, updates)
