"""
Knowledge base using ChromaDB for RAG.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any

from utils.logger import get_logger

if TYPE_CHECKING:
    from core.config_manager import Settings

logger = get_logger(__name__)


class KnowledgeBase:
    """
    Vector store for security knowledge using ChromaDB.
    
    Features:
    - Semantic search
    - Persistent storage
    - Metadata filtering
    - Incremental updates
    """
    
    def __init__(self, settings: Settings) -> None:
        """
        Initialize knowledge base.
        
        Args:
            settings: Application settings
        """
        self.settings = settings
        self.store_path = Path(settings.storage.vector_store_path)
        self.collection_name = settings.storage.collection_name
        
        self._client = None
        self._collection = None
        self._initialized = False
    
    def _ensure_initialized(self) -> None:
        """Ensure ChromaDB is initialized."""
        if self._initialized:
            return
        
        try:
            import chromadb
            from chromadb.config import Settings as ChromaSettings
            
            # Create persistent client
            self.store_path.mkdir(parents=True, exist_ok=True)
            
            self._client = chromadb.PersistentClient(
                path=str(self.store_path),
                settings=ChromaSettings(
                    anonymized_telemetry=False,
                ),
            )
            
            # Get or create collection
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            
            self._initialized = True
            logger.info(f"Initialized knowledge base at {self.store_path}")
            
        except ImportError:
            logger.warning("ChromaDB not installed, knowledge base disabled")
            self._initialized = False
        except Exception as e:
            logger.error(f"Failed to initialize knowledge base: {e}")
            self._initialized = False
    
    async def add(
        self,
        text: str,
        metadata: dict[str, Any] | None = None,
        doc_id: str | None = None,
    ) -> str | None:
        """
        Add a document to the knowledge base.
        
        Args:
            text: Document text
            metadata: Optional metadata
            doc_id: Optional document ID
            
        Returns:
            Document ID or None
        """
        self._ensure_initialized()
        
        if not self._collection:
            return None
        
        try:
            import hashlib
            
            # Generate ID if not provided
            if doc_id is None:
                doc_id = hashlib.sha256(text.encode()).hexdigest()[:16]
            
            # Add to collection
            self._collection.add(
                ids=[doc_id],
                documents=[text],
                metadatas=[metadata or {}],
            )
            
            logger.debug(f"Added document {doc_id} to knowledge base")
            return doc_id
            
        except Exception as e:
            logger.error(f"Failed to add document: {e}")
            return None
    
    async def search(
        self,
        query: str,
        n_results: int = 5,
        filter_metadata: dict[str, Any] | None = None,
    ) -> list[str]:
        """
        Search the knowledge base.
        
        Args:
            query: Search query
            n_results: Number of results
            filter_metadata: Optional metadata filter
            
        Returns:
            List of relevant documents
        """
        self._ensure_initialized()
        
        if not self._collection:
            return []
        
        try:
            results = self._collection.query(
                query_texts=[query],
                n_results=n_results,
                where=filter_metadata,
            )
            
            documents = results.get("documents", [[]])[0]
            return documents
            
        except Exception as e:
            logger.error(f"Knowledge base search failed: {e}")
            return []
    
    async def delete(self, doc_id: str) -> bool:
        """
        Delete a document from the knowledge base.
        
        Args:
            doc_id: Document ID
            
        Returns:
            True if deleted
        """
        self._ensure_initialized()
        
        if not self._collection:
            return False
        
        try:
            self._collection.delete(ids=[doc_id])
            return True
        except Exception:
            return False
    
    async def update(
        self,
        doc_id: str,
        text: str,
        metadata: dict[str, Any] | None = None,
    ) -> bool:
        """
        Update a document in the knowledge base.
        
        Args:
            doc_id: Document ID
            text: New text
            metadata: New metadata
            
        Returns:
            True if updated
        """
        self._ensure_initialized()
        
        if not self._collection:
            return False
        
        try:
            self._collection.update(
                ids=[doc_id],
                documents=[text],
                metadatas=[metadata or {}],
            )
            return True
        except Exception:
            return False
    
    async def count(self) -> int:
        """Get document count."""
        self._ensure_initialized()
        
        if not self._collection:
            return 0
        
        try:
            return self._collection.count()
        except Exception:
            return 0
    
    async def load_security_knowledge(self, path: Path | str) -> int:
        """
        Load security knowledge from files.
        
        Args:
            path: Path to knowledge files
            
        Returns:
            Number of documents loaded
        """
        path = Path(path)
        
        if not path.exists():
            logger.warning(f"Knowledge path not found: {path}")
            return 0
        
        loaded = 0
        
        # Load JSON files
        for json_file in path.glob("**/*.json"):
            try:
                import json
                
                with open(json_file) as f:
                    data = json.load(f)
                
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "text" in item:
                            await self.add(
                                item["text"],
                                item.get("metadata", {}),
                            )
                            loaded += 1
                            
            except Exception as e:
                logger.warning(f"Failed to load {json_file}: {e}")
        
        # Load text files
        for txt_file in path.glob("**/*.txt"):
            try:
                text = txt_file.read_text()
                await self.add(
                    text,
                    {"source": str(txt_file)},
                )
                loaded += 1
            except Exception as e:
                logger.warning(f"Failed to load {txt_file}: {e}")
        
        logger.info(f"Loaded {loaded} documents into knowledge base")
        return loaded
