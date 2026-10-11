import logging
from typing import Optional
from pymongo import MongoClient
from pymongo.database import Database
from app.core.config import settings

logger = logging.getLogger(__name__)

class MongoDBManager:
    """
    Singleton connection manager for MongoDB.
    Reuses connection across requests and handles connection health safely.
    """
    _instance: Optional["MongoDBManager"] = None
    _client: Optional[MongoClient] = None
    _db: Optional[Database] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MongoDBManager, cls).__new__(cls)
        return cls._instance

    def get_client(self) -> MongoClient:
        if self._client is None:
            try:
                self._client = MongoClient(
                    settings.MONGODB_URI,
                    serverSelectionTimeoutMS=3000,
                    connectTimeoutMS=3000
                )
                # Verify connection
                self._client.admin.command('ping')
                logger.info(f"Connected to MongoDB at {settings.MONGODB_URI}")
            except Exception as e:
                logger.warning(f"MongoDB connection check failed: {e}")
        return self._client

    def get_database(self) -> Database:
        if self._db is None:
            client = self.get_client()
            self._db = client[settings.MONGODB_DB_NAME]
            # Initialize indices
            self._init_indices()
        return self._db

    def _init_indices(self):
        try:
            reports_col = self._db["reports"]
            # Unique index on report_id
            reports_col.create_index("report_id", unique=True)
            # Index on created_at for fast descending sort
            reports_col.create_index([("created_at", -1)])
            # Index on incident_id
            reports_col.create_index("incident_id")
            # Index on attack_classification
            reports_col.create_index("attack_classification")
        except Exception as e:
            logger.warning(f"Could not initialize MongoDB indexes: {e}")

    def is_connected(self) -> bool:
        try:
            client = self.get_client()
            client.admin.command('ping')
            return True
        except Exception:
            return False

    def close(self):
        if self._client:
            self._client.close()
            self._client = None
            self._db = None
            logger.info("MongoDB connection closed.")

mongo_manager = MongoDBManager()

def get_mongo_db() -> Database:
    """Dependency helper to get the MongoDB database instance."""
    return mongo_manager.get_database()
