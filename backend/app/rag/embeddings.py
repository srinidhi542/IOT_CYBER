import os
import math
import hashlib
import logging
from typing import List, Optional

logger = logging.getLogger(__name__)


class EmbeddingModel:
    """
    Pluggable embedding interface. Uses local sentence-transformers model
    with a deterministic fallback embedding generator if model downloading is unavailable.
    """

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name or os.environ.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
        self._model = None
        self._dimension = 384
        self._init_model()

    def _init_model(self):
        try:
            from sentence_transformers import SentenceTransformer
            # Set HF cache dir in backend/data/models
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
            cache_dir = os.path.join(base_dir, "data", "models")
            os.makedirs(cache_dir, exist_ok=True)
            self._model = SentenceTransformer(self.model_name, cache_folder=cache_dir)
            self._dimension = self._model.get_sentence_embedding_dimension()
            logger.info(f"Loaded sentence-transformers model '{self.model_name}' (dim={self._dimension}).")
        except Exception as e:
            logger.warning(f"Could not load '{self.model_name}' via sentence-transformers ({e}). Using deterministic offline embeddings.")
            self._model = None
            self._dimension = 384

    @property
    def dimension(self) -> int:
        return self._dimension

    def encode(self, texts: List[str]) -> List[List[float]]:
        if not texts:
            return []

        if self._model is not None:
            try:
                embeddings = self._model.encode(texts, convert_to_numpy=True, normalize_embeddings=True)
                return [emb.tolist() for emb in embeddings]
            except Exception as e:
                logger.warning(f"SentenceTransformer encoding failed ({e}), falling back to deterministic embeddings.")

        return [self._deterministic_embedding(t) for t in texts]

    def encode_one(self, text: str) -> List[float]:
        return self.encode([text])[0]

    def _deterministic_embedding(self, text: str) -> List[float]:
        """Generates a normalized 384-dimensional deterministic pseudo-semantic embedding for offline mode."""
        dim = self._dimension
        words = text.lower().split()
        vec = [0.0] * dim

        for word in words:
            # Hash word into bucket
            h = int(hashlib.md5(word.encode("utf-8")).hexdigest(), 16)
            idx = h % dim
            sign = 1.0 if ((h >> 8) & 1) else -1.0
            vec[idx] += sign

        # Add overall string hash for stability
        full_h = int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16)
        for i in range(min(16, dim)):
            vec[(full_h + i) % dim] += 0.5

        # Normalize vector
        norm = math.sqrt(sum(x * x for x in vec)) or 1.0
        return [x / norm for x in vec]


_embedding_instance: Optional[EmbeddingModel] = None

def get_embedding_model() -> EmbeddingModel:
    global _embedding_instance
    if _embedding_instance is None:
        _embedding_instance = EmbeddingModel()
    return _embedding_instance
