from models import KnowledgeObject
from stix2 import FileSystemSource, Filter
from dataclasses import asdict
from datetime import datetime, timezone
import json
import os
import uuid
from typing import List, Dict, Any, Optional, Generator


# STIX object types we want to process from ATT&CK
ATTACK_OBJECT_TYPES = [
    "attack-pattern",      # Techniques
    "malware",             # Malware
    "tool",                # Tools
    "intrusion-set",       # Threat Groups
    "campaign",            # Campaigns
    "course-of-action",    # Mitigations
    "x-mitre-tactic",      # Tactics
    "x-mitre-data-source", # Data Sources
]


def get_attack_id(stix_obj: Dict[str, Any]) -> Optional[str]:
    """Extract the ATT&CK or CAPEC ID (e.g., T1055.011, CAPEC-542) from external references."""
    refs = stix_obj.get("external_references", [])
    for ref in refs:
        source = ref.get("source_name", "").lower()
        if source in ("mitre-attack", "capec"):
            return ref.get("external_id")
    return None


def get_attack_url(stix_obj: Dict[str, Any]) -> Optional[str]:
    """Extract the ATT&CK or CAPEC URL from external references."""
    refs = stix_obj.get("external_references", [])
    for ref in refs:
        source = ref.get("source_name", "").lower()
        if source in ("mitre-attack", "capec"):
            return ref.get("url")
    return None


def get_tactics(stix_obj: Dict[str, Any]) -> List[str]:
    """Extract tactic names from kill chain phases."""
    phases = stix_obj.get("kill_chain_phases", [])
    return [
        phase.get("phase_name", "").replace("-", " ").title()
        for phase in phases
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def get_platforms(stix_obj: Dict[str, Any]) -> List[str]:
    """Extract platform names."""
    return stix_obj.get("x_mitre_platforms", [])


def get_object_type_label(stix_type: str) -> str:
    """Convert STIX type to human-readable label."""
    type_map = {
        "attack-pattern": "Technique",
        "malware": "Malware",
        "tool": "Tool",
        "intrusion-set": "Threat Group",
        "campaign": "Campaign",
        "course-of-action": "Mitigation",
        "x-mitre-tactic": "Tactic",
        "x-mitre-data-source": "Data Source",
    }
    return type_map.get(stix_type, stix_type)


def create_entity(
    name: str,
    entity_type: str,
    role: str,
    start: int,
    end: int
) -> Dict[str, Any]:
    """Create an entity dict for a KnowledgeObject."""
    return {
        "id": str(uuid.uuid4()),
        "name": name,
        "entity_type": entity_type,
        "role": role,
        "start": start,
        "end": end,
    }


def build_text_with_entities(stix_obj: Dict[str, Any]) -> tuple[str, List[Dict[str, Any]]]:
    """
    Build the text content for a KnowledgeObject with inline identifiers,
    and extract entities with their positions.

    Returns: (text, entities)
    """
    entities = []
    text_parts = []
    current_pos = 0

    stix_type = stix_obj.get("type", "")
    name = stix_obj.get("name", "Unknown")
    description = stix_obj.get("description", "")
    attack_id = get_attack_id(stix_obj)
    attack_url = get_attack_url(stix_obj)
    tactics = get_tactics(stix_obj)
    platforms = get_platforms(stix_obj)
    type_label = get_object_type_label(stix_type)

    # Build header with identifiers
    # Format: "[T1055.011] Extra Window Memory Injection (Technique)"
    if attack_id:
        header = f"[{attack_id}] {name} ({type_label})"
        # Entity for ATT&CK ID
        id_start = 1  # After '['
        id_end = id_start + len(attack_id)
        entities.append(create_entity(
            name=attack_id,
            entity_type="attack_id",
            role="identifier",
            start=id_start,
            end=id_end
        ))
        # Entity for name
        name_start = id_end + 2  # After '] '
        name_end = name_start + len(name)
        entities.append(create_entity(
            name=name,
            entity_type=stix_type,
            role="name",
            start=name_start,
            end=name_end
        ))
    else:
        header = f"{name} ({type_label})"
        entities.append(create_entity(
            name=name,
            entity_type=stix_type,
            role="name",
            start=0,
            end=len(name)
        ))

    text_parts.append(header)
    current_pos = len(header)

    # Add tactics if present
    if tactics:
        text_parts.append("\n\nTactics: ")
        current_pos += len("\n\nTactics: ")
        tactic_strs = []
        for tactic in tactics:
            tactic_start = current_pos + len(", ".join(tactic_strs))
            if tactic_strs:
                tactic_start += 2  # ", "
            entities.append(create_entity(
                name=tactic,
                entity_type="tactic",
                role="tactic",
                start=tactic_start,
                end=tactic_start + len(tactic)
            ))
            tactic_strs.append(tactic)
        text_parts.append(", ".join(tactic_strs))
        current_pos += len(", ".join(tactic_strs))

    # Add platforms if present
    if platforms:
        text_parts.append("\nPlatforms: ")
        current_pos += len("\nPlatforms: ")
        platform_strs = []
        for platform in platforms:
            platform_start = current_pos + len(", ".join(platform_strs))
            if platform_strs:
                platform_start += 2
            entities.append(create_entity(
                name=platform,
                entity_type="platform",
                role="platform",
                start=platform_start,
                end=platform_start + len(platform)
            ))
            platform_strs.append(platform)
        text_parts.append(", ".join(platform_strs))
        current_pos += len(", ".join(platform_strs))

    # Add URL if present
    if attack_url:
        text_parts.append(f"\nURL: {attack_url}")
        current_pos += len(f"\nURL: {attack_url}")

    # Add description
    if description:
        text_parts.append(f"\n\n{description}")

    return "".join(text_parts), entities


def stix_to_knowledge_object(
    stix_obj: Dict[str, Any],
    source: str,
    session: str
) -> Optional[KnowledgeObject]:
    """Convert a STIX object to a KnowledgeObject."""
    # Skip deprecated objects
    if stix_obj.get("x_mitre_deprecated", False):
        return None

    # Skip revoked objects
    if stix_obj.get("revoked", False):
        return None

    # Generate a new KO ID (not using STIX ID)
    ko_id = f"ko_{uuid.uuid4().hex[:12]}"

    text, entities = build_text_with_entities(stix_obj)

    # Build predicates from relationships (if any embedded)
    predicates = []

    # Add is_subtechnique predicate if applicable
    if stix_obj.get("x_mitre_is_subtechnique"):
        predicates.append({
            "id": str(uuid.uuid4()),
            "name": "is_subtechnique_of",
            "predicate_type": "hierarchy",
            "primary": True,
        })

    created_at = stix_obj.get("created", datetime.now(timezone.utc).isoformat())

    return KnowledgeObject(
        id=ko_id,
        text=text,
        entities=entities,
        predicates=predicates,
        source=source,
        session=session,
        created_at=created_at
    )


def load_attack_data(cti_path: str, domain: str = "enterprise-attack") -> Generator[Dict[str, Any], None, None]:
    """
    Load ATT&CK data from the CTI repository using stix2 FileSystemSource.

    Args:
        cti_path: Path to the CTI repository root
        domain: ATT&CK domain (enterprise-attack, mobile-attack, ics-attack)

    Yields:
        STIX objects as dictionaries
    """
    domain_path = os.path.join(cti_path, domain)

    if not os.path.exists(domain_path):
        raise ValueError(f"Domain path does not exist: {domain_path}")

    # Use stix2 FileSystemSource for proper parsing
    fs = FileSystemSource(domain_path)

    for obj_type in ATTACK_OBJECT_TYPES:
        try:
            # Query for all objects of this type
            objects = fs.query([Filter("type", "=", obj_type)])
            for obj in objects:
                # Convert stix2 object to dict for consistent handling
                # Some custom MITRE types return dicts directly
                if isinstance(obj, dict):
                    yield obj
                elif hasattr(obj, "serialize"):
                    yield json.loads(obj.serialize())
                else:
                    # Fallback: try to convert to dict
                    yield dict(obj)
        except Exception as e:
            print(f"Warning: Error loading {obj_type}: {e}")
            continue


def process_attack_domain(
    cti_path: str,
    domain: str,
    source: str,
    session: str
) -> List[KnowledgeObject]:
    """
    Process all ATT&CK objects from a domain into KnowledgeObjects.

    Args:
        cti_path: Path to the CTI repository
        domain: ATT&CK domain name
        source: Source identifier for KnowledgeObjects
        session: Session identifier for KnowledgeObjects

    Returns:
        List of KnowledgeObjects
    """
    knowledge_objects = []

    for stix_obj in load_attack_data(cti_path, domain):
        ko = stix_to_knowledge_object(stix_obj, source, session)
        if ko:
            knowledge_objects.append(ko)

    return knowledge_objects


def load_capec_data(cti_path: str, version: str = "2.1") -> Generator[Dict[str, Any], None, None]:
    """
    Load CAPEC data from the CTI repository.

    Args:
        cti_path: Path to the CTI repository root
        version: CAPEC STIX version (2.0 or 2.1)

    Yields:
        STIX objects as dictionaries
    """
    capec_path = os.path.join(cti_path, "capec", version, "stix-capec")

    if not os.path.exists(capec_path):
        # Try alternate path structure
        capec_path = os.path.join(cti_path, "capec", version)
        if not os.path.exists(capec_path):
            raise ValueError(f"CAPEC path does not exist: {capec_path}")

    fs = FileSystemSource(capec_path)

    # CAPEC uses attack-pattern and course-of-action
    capec_types = ["attack-pattern", "course-of-action"]

    for obj_type in capec_types:
        try:
            objects = fs.query([Filter("type", "=", obj_type)])
            for obj in objects:
                if isinstance(obj, dict):
                    yield obj
                elif hasattr(obj, "serialize"):
                    yield json.loads(obj.serialize())
                else:
                    yield dict(obj)
        except Exception as e:
            print(f"Warning: Error loading CAPEC {obj_type}: {e}")
            continue


def process_capec(
    cti_path: str,
    source: str,
    session: str,
    version: str = "2.1"
) -> List[KnowledgeObject]:
    """
    Process CAPEC data into KnowledgeObjects.

    Args:
        cti_path: Path to the CTI repository
        source: Source identifier
        session: Session identifier
        version: CAPEC STIX version

    Returns:
        List of KnowledgeObjects
    """
    knowledge_objects = []

    for stix_obj in load_capec_data(cti_path, version):
        ko = stix_to_knowledge_object(stix_obj, source, session)
        if ko:
            knowledge_objects.append(ko)

    return knowledge_objects


def process_all_domains(
    cti_path: str,
    source: str,
    session: str
) -> Dict[str, List[KnowledgeObject]]:
    """
    Process all ATT&CK domains and CAPEC from the CTI repository.

    Args:
        cti_path: Path to the CTI repository
        source: Source identifier
        session: Session identifier

    Returns:
        Dict mapping domain names to lists of KnowledgeObjects
    """
    # ATT&CK domains including pre-attack
    domains = ["enterprise-attack", "mobile-attack", "ics-attack", "pre-attack"]
    results = {}

    for domain in domains:
        domain_path = os.path.join(cti_path, domain)
        if os.path.exists(domain_path):
            print(f"Processing {domain}...")
            results[domain] = process_attack_domain(cti_path, domain, source, session)
            print(f"  Found {len(results[domain])} objects")

    # Process CAPEC separately (different folder structure)
    capec_path = os.path.join(cti_path, "capec")
    if os.path.exists(capec_path):
        print("Processing capec...")
        results["capec"] = process_capec(cti_path, source, session)
        print(f"  Found {len(results['capec'])} objects")

    return results


def enqueue_all_domains(
    cti_path: str,
    core_name: str,
    source: str,
    session: str,
    batch_size: int = 100
) -> int:
    """
    Process all ATT&CK domains and CAPEC, then enqueue to Redis.

    Args:
        cti_path: Path to the CTI repository
        core_name: Name of the core/index to store in
        source: Source identifier
        session: Session identifier
        batch_size: Number of KOs per batch message

    Returns:
        Total number of KnowledgeObjects enqueued
    """
    from messaging import enqueue
    from models import StoreKnowledgeBatchJob

    all_kos = process_all_domains(cti_path, source, session)

    # Flatten all KOs and convert to dicts
    all_ko_dicts = []
    for kos in all_kos.values():
        for ko in kos:
            all_ko_dicts.append(asdict(ko))

    # Enqueue in batches
    num_batches = 0
    for i in range(0, len(all_ko_dicts), batch_size):
        batch = all_ko_dicts[i:i + batch_size]
        job = StoreKnowledgeBatchJob(
            knowledge_objects=batch,
            core_name=core_name
        )
        enqueue("store_knowledge_batch", "store-batch", args=(job.to_dict(),))
        num_batches += 1

    print(f"Enqueued {num_batches} batches")
    return len(all_ko_dicts)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Process MITRE ATT&CK data into KnowledgeObjects")
    parser.add_argument("--cti-path", default="./cti", help="Path to CTI repository")
    parser.add_argument("--core-name", default="organic-chem", help="Core name for storage")
    parser.add_argument("--source", default="mitre-attack", help="Source identifier")
    parser.add_argument("--batch-size", type=int, default=200, help="Batch size for enqueueing")
    parser.add_argument("--enqueue", action="store_true", help="Enqueue to Redis instead of just printing")

    args = parser.parse_args()
    session = str(uuid.uuid4())

    if args.enqueue:
        # Enqueue to Redis
        total = enqueue_all_domains(
            cti_path=args.cti_path,
            core_name=args.core_name,
            source=args.source,
            session=session,
            batch_size=args.batch_size
        )
        print(f"\nEnqueued {total} KnowledgeObjects in batches of {args.batch_size}")
    else:
        # Just process and print stats
        all_kos = process_all_domains(args.cti_path, args.source, session)

        total = sum(len(kos) for kos in all_kos.values())
        print(f"\nTotal KnowledgeObjects created: {total}")

        # Print a sample
        if all_kos.get("enterprise-attack"):
            sample = all_kos["enterprise-attack"][0]
            print(f"\nSample KnowledgeObject:")
            print(f"  ID: {sample.id}")
            print(f"  Text preview: {sample.text[:200]}...")
            print(f"  Entities: {len(sample.entities)}")
            for ent in sample.entities[:3]:
                print(f"    - {ent['name']} ({ent['entity_type']}, {ent['role']})")