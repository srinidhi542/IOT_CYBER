import re
import logging
from typing import List, Dict, Any, Optional
from rank_bm25 import BM25Okapi

from app.rag.vector_store import get_vector_store, VectorStore, Document, SearchResult
from app.rag.embeddings import get_embedding_model

logger = logging.getLogger(__name__)

# Regular expressions for exact cybersecurity identifier lookups
REGEX_MITRE_ID = re.compile(r"\b(T\d{4}(?:\.\d{3})?)\b", re.IGNORECASE)
REGEX_CVE_ID = re.compile(r"\b(CVE-\d{4}-\d{4,7})\b", re.IGNORECASE)
REGEX_CISA_ID = re.compile(r"\b(AA\d{2}-\d{3}[A-Z]|ICSA-\d{2}-\d{3}-\d{2})\b", re.IGNORECASE)


class HybridRetriever:
    """
    Hybrid Retriever uniting:
    1. Exact-ID Matching (CVE-ID, MITRE-ID, or CISA-ID matches always placed at top)
    2. Dense Vector Retrieval (Sentence-Transformers cosine similarity)
    3. Sparse BM25 Keyword Search (BM25Okapi)
    4. Reciprocal Rank Fusion (RRF) with relevance score calibration
    5. Document-type metadata filtering
    """

    def __init__(self, vector_store: Optional[VectorStore] = None):
        self.vector_store = vector_store or get_vector_store()
        self.embedding_model = get_embedding_model()
        self._bm25: Optional[BM25Okapi] = None
        self._bm25_docs: List[Document] = []
        self._build_bm25_index()

    def _tokenize(self, text: str) -> List[str]:
        # Lowercase alphanumeric tokenization
        return re.findall(r"\w+", text.lower())

    def _build_bm25_index(self):
        try:
            docs = self.vector_store.get_all_documents()
            if not docs:
                self._bm25 = None
                self._bm25_docs = []
                return

            corpus = [self._tokenize(d.content) for d in docs]
            self._bm25 = BM25Okapi(corpus)
            self._bm25_docs = docs
            logger.info(f"Built BM25 index with {len(docs)} documents.")
        except Exception as e:
            logger.warning(f"Could not initialize BM25 index: {e}")
            self._bm25 = None
            self._bm25_docs = []

    def refresh_index(self):
        self._build_bm25_index()

    def extract_exact_ids(self, query: str) -> List[str]:
        """Extracts any explicit technique or vulnerability IDs from query."""
        ids = []
        for m in REGEX_MITRE_ID.finditer(query):
            ids.append(m.group(1).upper())
        for m in REGEX_CVE_ID.finditer(query):
            ids.append(m.group(1).upper())
        for m in REGEX_CISA_ID.finditer(query):
            ids.append(m.group(1).upper())
        return list(dict.fromkeys(ids))

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        doc_type: Optional[str] = None,
        min_relevance: float = 0.35
    ) -> List[SearchResult]:
        """
        Executes hybrid search across vector store and BM25 index with RRF.
        """
        if not query.strip():
            return []

        # Refresh BM25 if newly ingested documents exist
        current_count = self.vector_store.count()
        if len(self._bm25_docs) != current_count:
            self._build_bm25_index()

        candidate_map: Dict[str, Document] = {}
        dense_ranks: Dict[str, int] = {}
        bm25_ranks: Dict[str, int] = {}
        exact_match_ids: List[str] = []

        # -------------------------------------------------------------
        # 1. Exact-ID Matching (Always Wins)
        # -------------------------------------------------------------
        extracted_ids = self.extract_exact_ids(query)
        for target_id in extracted_ids:
            doc = self.vector_store.get_by_id(target_id)
            if doc:
                candidate_map[doc.id] = doc
                exact_match_ids.append(doc.id)

        # -------------------------------------------------------------
        # 2. Dense Vector Retrieval
        # -------------------------------------------------------------
        filter_dict = {"doc_type": doc_type} if doc_type else None
        q_emb = self.embedding_model.encode_one(query)
        dense_results = self.vector_store.search(
            query_embedding=q_emb,
            top_k=top_k * 3,
            filter=filter_dict
        )

        for rank, res in enumerate(dense_results, 1):
            doc = res.document
            candidate_map[doc.id] = doc
            dense_ranks[doc.id] = rank

        # -------------------------------------------------------------
        # 3. BM25 Keyword Search
        # -------------------------------------------------------------
        if self._bm25 and self._bm25_docs:
            q_tokens = self._tokenize(query)
            if q_tokens:
                bm25_scores = self._bm25.get_scores(q_tokens)
                # Pair with docs and sort
                scored_bm25 = [
                    (self._bm25_docs[i], score)
                    for i, score in enumerate(bm25_scores)
                    if score > 0.0
                ]
                scored_bm25.sort(key=lambda x: x[1], reverse=True)

                filtered_bm25 = scored_bm25
                if doc_type:
                    filtered_bm25 = [item for item in scored_bm25 if item[0].metadata.get("doc_type") == doc_type]

                for rank, (doc, _) in enumerate(filtered_bm25[:top_k * 3], 1):
                    candidate_map[doc.id] = doc
                    bm25_ranks[doc.id] = rank

        # -------------------------------------------------------------
        # 4. Reciprocal Rank Fusion (RRF) Merging
        # -------------------------------------------------------------
        # Formula: RRF = 1 / (60 + dense_rank) + 1 / (60 + bm25_rank)
        rrf_k = 60
        fused_scores: Dict[str, float] = {}

        for doc_id, doc in candidate_map.items():
            if doc_type and doc.metadata.get("doc_type") != doc_type:
                continue

            # Exact ID matches receive maximum boosted score
            if doc_id in exact_match_ids:
                fused_scores[doc_id] = 1.0
                continue

            r_dense = dense_ranks.get(doc_id, 999)
            r_bm25 = bm25_ranks.get(doc_id, 999)

            score_dense = 1.0 / (rrf_k + r_dense) if r_dense < 999 else 0.0
            score_bm25 = 1.0 / (rrf_k + r_bm25) if r_bm25 < 999 else 0.0

            # Normalize RRF raw score (max possible raw is 2 / 61 ~= 0.0328)
            combined_raw = score_dense + score_bm25
            normalized_score = min(0.99, combined_raw * 30.0)

            # Minimum score floor if dense vector had high direct similarity
            for dr in dense_results:
                if dr.document.id == doc_id:
                    normalized_score = max(normalized_score, dr.score * 0.9)
                    break

            fused_scores[doc_id] = round(normalized_score, 4)

        # Sort candidate results
        sorted_candidates = sorted(
            fused_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )

        final_results = []
        for doc_id, score in sorted_candidates:
            if score >= min_relevance:
                doc_obj = candidate_map[doc_id]
                final_results.append(SearchResult(document=doc_obj, score=score))
            if len(final_results) >= top_k:
                break

        return final_results


_retriever_instance: Optional[HybridRetriever] = None

def get_retriever() -> HybridRetriever:
    global _retriever_instance
    if _retriever_instance is None:
        _retriever_instance = HybridRetriever()
    return _retriever_instance
