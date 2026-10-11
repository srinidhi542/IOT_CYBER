import os
import math
import logging
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class Document(BaseModel):
    id: str
    content: str
    metadata: Dict[str, Any] = Field(default_factory=dict)
    embedding: Optional[List[float]] = None


class SearchResult(BaseModel):
    document: Document
    score: float  # higher = more relevant (0.0 to 1.0)


class VectorStore(ABC):
    @abstractmethod
    def add_documents(self, documents: List[Document]) -> int:
        pass

    @abstractmethod
    def search(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        filter: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        pass

    @abstractmethod
    def get_by_id(self, doc_id: str) -> Optional[Document]:
        pass

    @abstractmethod
    def get_all_documents(self) -> List[Document]:
        pass

    @abstractmethod
    def count(self) -> int:
        pass

    @abstractmethod
    def get_stats(self) -> Dict[str, Any]:
        pass


class ChromaVectorStore(VectorStore):
    """
    Persistent ChromaDB vector store implementation.
    """

    def __init__(self, persist_dir: str, collection_name: str = "iot_threat_intel"):
        self.persist_dir = persist_dir
        self.collection_name = collection_name
        self._init_client()

    def _init_client(self):
        import chromadb
        os.makedirs(self.persist_dir, exist_ok=True)
        self.client = chromadb.PersistentClient(path=self.persist_dir)
        self.collection = self.client.get_or_create_collection(
            name=self.collection_name,
            metadata={"hnsw:space": "cosine"}
        )
        logger.info(f"Initialized ChromaVectorStore at '{self.persist_dir}', collection count: {self.collection.count()}")

    def add_documents(self, documents: List[Document]) -> int:
        if not documents:
            return 0

        ids = [doc.id for doc in documents]
        contents = [doc.content for doc in documents]
        embeddings = [doc.embedding for doc in documents]
        
        # Chroma metadata requires values to be primitive (str, int, float, bool)
        metadatas = []
        for doc in documents:
            clean_meta = {}
            for k, v in doc.metadata.items():
                if isinstance(v, (str, int, float, bool)):
                    clean_meta[k] = v
                elif isinstance(v, list):
                    clean_meta[k] = ", ".join(str(item) for item in v)
                elif v is None:
                    clean_meta[k] = ""
                else:
                    clean_meta[k] = str(v)
            metadatas.append(clean_meta)

        self.collection.upsert(
            ids=ids,
            documents=contents,
            embeddings=embeddings,
            metadatas=metadatas
        )
        return len(documents)

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        filter: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        if self.collection.count() == 0:
            return []

        where_clause = filter if filter else None
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=min(top_k, self.collection.count()),
            where=where_clause
        )

        search_results = []
        ids = results.get("ids", [[]])[0]
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]

        for i in range(len(ids)):
            dist = distances[i] if i < len(distances) else 1.0
            # Cosine distance in chromadb ranges [0, 2], convert to similarity score [0, 1]
            sim = max(0.0, min(1.0, 1.0 - (dist / 2.0)))
            doc_obj = Document(
                id=ids[i],
                content=docs[i] if i < len(docs) else "",
                metadata=metas[i] if i < len(metas) else {}
            )
            search_results.append(SearchResult(document=doc_obj, score=sim))

        return search_results

    def get_by_id(self, doc_id: str) -> Optional[Document]:
        try:
            res = self.collection.get(ids=[doc_id])
            ids = res.get("ids", [])
            if not ids:
                return None
            return Document(
                id=ids[0],
                content=res["documents"][0] if res.get("documents") else "",
                metadata=res["metadatas"][0] if res.get("metadatas") else {}
            )
        except Exception as e:
            logger.debug(f"Chroma lookup for {doc_id} returned: {e}")
            return None

    def get_all_documents(self) -> List[Document]:
        total = self.collection.count()
        if total == 0:
            return []
        res = self.collection.get()
        docs = []
        for i in range(len(res.get("ids", []))):
            docs.append(Document(
                id=res["ids"][i],
                content=res["documents"][i] if res.get("documents") else "",
                metadata=res["metadatas"][i] if res.get("metadatas") else {}
            ))
        return docs

    def count(self) -> int:
        return self.collection.count()

    def get_stats(self) -> Dict[str, Any]:
        docs = self.get_all_documents()
        doc_types: Dict[str, int] = {}
        for d in docs:
            dt = d.metadata.get("doc_type", "unknown")
            doc_types[dt] = doc_types.get(dt, 0) + 1
        return {
            "engine": "chromadb",
            "persist_dir": self.persist_dir,
            "total_documents": len(docs),
            "by_type": doc_types
        }


class InMemoryVectorStore(VectorStore):
    """
    In-memory fallback vector store with exact cosine calculation.
    Guarantees operation even if native vector DB libraries are restricted.
    """

    def __init__(self):
        self.docs: Dict[str, Document] = {}

    def add_documents(self, documents: List[Document]) -> int:
        for d in documents:
            self.docs[d.id] = d
        return len(documents)

    def search(
        self,
        query_embedding: List[float],
        top_k: int = 5,
        filter: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        scored = []
        for d in self.docs.values():
            if filter:
                match = all(d.metadata.get(k) == v for k, v in filter.items())
                if not match:
                    continue
            if not d.embedding:
                continue

            # Cosine similarity
            dot = sum(a * b for a, b in zip(query_embedding, d.embedding))
            norm_q = math.sqrt(sum(a * a for a in query_embedding)) or 1.0
            norm_d = math.sqrt(sum(b * b for b in d.embedding)) or 1.0
            sim = max(0.0, min(1.0, (dot / (norm_q * norm_d) + 1.0) / 2.0))
            scored.append(SearchResult(document=d, score=sim))

        scored.sort(key=lambda s: s.score, reverse=True)
        return scored[:top_k]

    def get_by_id(self, doc_id: str) -> Optional[Document]:
        return self.docs.get(doc_id)

    def get_all_documents(self) -> List[Document]:
        return list(self.docs.values())

    def count(self) -> int:
        return len(self.docs)

    def get_stats(self) -> Dict[str, Any]:
        doc_types: Dict[str, int] = {}
        for d in self.docs.values():
            dt = d.metadata.get("doc_type", "unknown")
            doc_types[dt] = doc_types.get(dt, 0) + 1
        return {
            "engine": "in_memory",
            "total_documents": len(self.docs),
            "by_type": doc_types
        }


_vector_store_instance: Optional[VectorStore] = None

def get_vector_store() -> VectorStore:
    global _vector_store_instance
    if _vector_store_instance is None:
        from app.core.config import settings, load_platform_settings
        raw_persist = rag_cfg.get("persist_directory")
        if raw_persist:
            if os.path.isabs(raw_persist):
                persist_dir = raw_persist
            else:
                clean_path = raw_persist[8:] if (raw_persist.startswith("backend/") or raw_persist.startswith("backend\\")) else raw_persist
                persist_dir = os.path.join(settings.BASE_DIR, clean_path)
        else:
            persist_dir = os.path.join(settings.BASE_DIR, "data", "chroma_db")

        try:
            _vector_store_instance = ChromaVectorStore(persist_dir=persist_dir)
        except Exception as e:
            logger.warning(f"Could not initialize ChromaVectorStore ({e}), using InMemoryVectorStore fallback.")
            _vector_store_instance = InMemoryVectorStore()

    return _vector_store_instance
