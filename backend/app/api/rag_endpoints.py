import os
import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from app.rag.vector_store import get_vector_store
from app.rag.retriever import get_retriever
from app.rag.ingest import ThreatIntelIngester
from app.llm.client import get_llm_client
from app.core.config import load_platform_settings

logger = logging.getLogger(__name__)

router = APIRouter(tags=["RAG & LLM Engine"])


class RAGSearchRequest(BaseModel):
    query: str
    top_k: int = 5
    doc_type: Optional[str] = None
    min_relevance: float = 0.30


@router.get("/rag/status")
def get_rag_status():
    """
    Returns current RAG vector store index status:
    total documents, documents by source/type, and persistence location.
    """
    try:
        vs = get_vector_store()
        stats = vs.get_stats()
        return {
            "status": "online",
            "stats": stats
        }
    except Exception as e:
        logger.error(f"Failed to query RAG status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/rag/refresh")
def refresh_rag_index(refresh_online: bool = Query(False, description="Attempt live download from online STIX and NVD feeds")):
    """
    Triggers an on-demand re-ingestion and index refresh of all threat intelligence sources.
    """
    try:
        ingester = ThreatIntelIngester()
        results = ingester.run_ingestion(refresh=refresh_online)
        # Refresh BM25 index in retriever
        get_retriever().refresh_index()
        return {
            "status": "refreshed",
            "results": results
        }
    except Exception as e:
        logger.error(f"RAG re-ingestion failed: {e}")
        raise HTTPException(status_code=500, detail=f"RAG refresh failed: {str(e)}")


@router.post("/rag/search")
def search_rag_knowledge(
    q: Optional[str] = Query(None, description="Search query string"),
    payload: Optional[RAGSearchRequest] = None
):
    """
    Directly queries the hybrid RAG retrieval engine (Dense + BM25 + Exact-ID + RRF)
    for testing, demonstration, or ad-hoc SOC research.
    """
    query_str = q or (payload.query if payload else "")
    if not query_str:
        raise HTTPException(status_code=400, detail="Search query parameter 'q' or JSON body 'query' is required.")

    top_k = payload.top_k if payload else 5
    doc_type = payload.doc_type if payload else None
    min_rel = payload.min_relevance if payload else 0.30

    try:
        retriever = get_retriever()
        results = retriever.retrieve(
            query=query_str,
            top_k=top_k,
            doc_type=doc_type,
            min_relevance=min_rel
        )
        return {
            "query": query_str,
            "count": len(results),
            "results": [
                {
                    "id": r.document.id,
                    "score": round(r.score, 4),
                    "doc_type": r.document.metadata.get("doc_type"),
                    "source": r.document.metadata.get("source"),
                    "url": r.document.metadata.get("url"),
                    "content_preview": r.document.content[:250],
                    "metadata": r.document.metadata
                }
                for r in results
            ]
        }
    except Exception as e:
        logger.error(f"RAG search execution failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/llm/status")
def get_llm_status():
    """
    Returns live shared LLM layer runtime status, configured provider,
    model name, availability, and recent call metrics.
    """
    try:
        client = get_llm_client()
        cfg = load_platform_settings().get("llm", {})
        recent = [r.model_dump() for r in client.recent_calls[-10:]]

        return {
            "enabled": client.enabled,
            "provider": client.provider,
            "model": client.model,
            "temperature": client.temperature,
            "is_available": client.is_available(),
            "cache_size": len(client.cache),
            "recent_calls_count": len(client.recent_calls),
            "recent_calls": recent,
            "agent_toggles": cfg.get("agent_toggles", {})
        }
    except Exception as e:
        logger.error(f"Failed to query LLM status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
