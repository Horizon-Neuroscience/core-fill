from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional, Literal


@dataclass
class KnowledgeObject:
    id: str
    text: str
    entities: List[Dict[str, Any]]  
    predicates: List[Dict[str, Any]]  
    source: str
    session: str
    created_at: str

@dataclass
class Entity:
    id: str
    name: str
    entity_type: str
    role: str
    created_at: str

@dataclass
class Predicate:
    id: str
    name: str
    predicate_type: str
    primary: bool
    created_at: str

@dataclass
class Source:
    id: str
    name: str
    source_type: str
    created_at: str

@dataclass
class Session:
    id: str
    name: str
    session_type: str
    created_at: str
    creator: str


@dataclass
class ReasoningSchema:
    id: str
    name: str
    description: str
    created_at: str

@dataclass
class ReasoningEvent:
    id: str
    reasoning_schema: ReasoningSchema
    created_at: str

@dataclass
class GraphNode:
    id: str
    group: int
    size: int

@dataclass
class GraphLink:
    source: str
    target: str

@dataclass
class GraphData:
    nodes: List[GraphNode]
    links: List[GraphLink]

@dataclass
class ChunkDocumentJob:
    document_id: str
    core_name: str

    blob_name: str            
    filename: str                # helps type-detect (e.g., .pdf/.docx)
    mime: str                    # e.g., application/pdf

    source: str
    session: str
    coref: bool
    textrank: bool
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class ChunkSpan:
    start: int   # UTF-8 byte start
    length: int  # UTF-8 byte length
    chunk_id: str

@dataclass
class ExtractKnowledgeJob:
    document_id: str
    core_name: str
    blob_name: str
    chunk_id: str
    start: int
    length: int
    session: str
    source: str

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class ExtractKnowledgeSimpleJob:
    document_id: str
    core_name: str
    blob_name: str
    filename: str
    mime: str
    session: str
    source: str

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class CustomFileJob:
    document_id: str
    filename: str
    mime: str
    core_name: str
    blob_name: str
    session: str
    source: str

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class PubChemJob:
    compound_id: int
    core_name: str
    session: str
    source: str

    def to_dict(self) -> dict:
        return asdict(self)
    


@dataclass
class StoreKnowledgeObjectsResult:
    success: bool
    total_ko: int
    total_predicates: int
    total_entities: int
    source: str
    session: str

    def to_dict(self) -> dict:
        return asdict(self)

@dataclass
class StoreKnowledgeBatchJob:
    knowledge_objects: List[Dict[str, Any]]  # List of KO dicts
    core_name: str

    def to_dict(self) -> dict:
        return asdict(self)

