from stix2 import FileSystemSource, Filter
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
) -> Dict[str, Any]:
    """Create a manual entity dict for extraction."""
    return {
        "name": name,
        "type": entity_type,
        "role": role,
    }


def build_text_with_entities(stix_obj: Dict[str, Any]) -> tuple[str, List[Dict[str, Any]]]:
    """
    Build the text content with inline identifiers and extract manual entities.

    Returns: (text, entities)
    """
    entities = []
    text_parts = []

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
        entities.append(create_entity(
            name=attack_id,
            entity_type="attack_id",
            role="identifier",
        ))
        entities.append(create_entity(
            name=name,
            entity_type=stix_type,
            role="name",
        ))
    else:
        header = f"{name} ({type_label})"
        entities.append(create_entity(
            name=name,
            entity_type=stix_type,
            role="name",
        ))

    text_parts.append(header)

    # Add tactics if present
    if tactics:
        text_parts.append("\n\nTactics: ")
        text_parts.append(", ".join(tactics))
        for tactic in tactics:
            entities.append(create_entity(
                name=tactic,
                entity_type="tactic",
                role="tactic",
            ))

    # Add platforms if present
    if platforms:
        text_parts.append("\nPlatforms: ")
        text_parts.append(", ".join(platforms))
        for platform in platforms:
            entities.append(create_entity(
                name=platform,
                entity_type="platform",
                role="platform",
            ))

    # Add URL if present
    if attack_url:
        text_parts.append(f"\nURL: {attack_url}")

    # Add description
    if description:
        text_parts.append(f"\n\n{description}")

    return "".join(text_parts), entities


def stix_to_text_item(stix_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a STIX object to a text item with manual entities."""
    # Skip deprecated objects
    if stix_obj.get("x_mitre_deprecated", False):
        return None

    # Skip revoked objects
    if stix_obj.get("revoked", False):
        return None

    text, entities = build_text_with_entities(stix_obj)

    return {
        "text": text,
        "manual_entities": entities if entities else None
    }


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
) -> List[Dict[str, Any]]:
    """
    Process all ATT&CK objects from a domain into text items.

    Args:
        cti_path: Path to the CTI repository
        domain: ATT&CK domain name

    Returns:
        List of text items ({"text": str, "manual_entities": List[Dict]})
    """
    text_items = []

    for stix_obj in load_attack_data(cti_path, domain):
        item = stix_to_text_item(stix_obj)
        if item:
            text_items.append(item)

    return text_items


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
    version: str = "2.1"
) -> List[Dict[str, Any]]:
    """
    Process CAPEC data into text items.

    Args:
        cti_path: Path to the CTI repository
        version: CAPEC STIX version

    Returns:
        List of text items ({"text": str, "manual_entities": List[Dict]})
    """
    text_items = []

    for stix_obj in load_capec_data(cti_path, version):
        item = stix_to_text_item(stix_obj)
        if item:
            text_items.append(item)

    return text_items


def process_all_domains(
    cti_path: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Process all ATT&CK domains and CAPEC from the CTI repository.

    Args:
        cti_path: Path to the CTI repository

    Returns:
        Dict mapping domain names to lists of text items
    """
    # ATT&CK domains including pre-attack
    domains = ["enterprise-attack", "mobile-attack", "ics-attack", "pre-attack"]
    results = {}

    for domain in domains:
        domain_path = os.path.join(cti_path, domain)
        if os.path.exists(domain_path):
            print(f"Processing {domain}...")
            results[domain] = process_attack_domain(cti_path, domain)
            print(f"  Found {len(results[domain])} objects")

    # Process CAPEC separately (different folder structure)
    capec_path = os.path.join(cti_path, "capec")
    if os.path.exists(capec_path):
        print("Processing capec...")
        results["capec"] = process_capec(cti_path)
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
        batch_size: Number of text items per batch message

    Returns:
        Total number of text items enqueued
    """
    from messaging import enqueue
    from models import ExtractAndStoreBatchJob

    all_items = process_all_domains(cti_path)

    # Flatten all text items
    all_text_items = []
    for items in all_items.values():
        all_text_items.extend(items)

    # Enqueue in batches
    num_batches = 0
    for i in range(0, len(all_text_items), batch_size):
        batch = all_text_items[i:i + batch_size]
        job = ExtractAndStoreBatchJob(
            text_items=batch,
            core_name=core_name,
            source=source,
            session=session
        )
        enqueue("extract_and_store_batch", "extract-store-batch", args=(job.to_dict(),))
        num_batches += 1

    print(f"Enqueued {num_batches} batches")
    return len(all_text_items)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Process MITRE ATT&CK data into text items")
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
        print(f"\nEnqueued {total} text items in batches of {args.batch_size}")
    else:
        # Just process and print stats
        all_items = process_all_domains(args.cti_path)

        total = sum(len(items) for items in all_items.values())
        print(f"\nTotal text items created: {total}")

        # Print a sample
        if all_items.get("enterprise-attack"):
            sample = all_items["enterprise-attack"][0]
            print(f"\nSample text item:")
            print(f"  Text preview: {sample['text'][:200]}...")
            entities = sample.get("manual_entities") or []
            print(f"  Entities: {len(entities)}")
            for ent in entities[:3]:
                print(f"    - {ent['name']} ({ent['type']}, {ent['role']})")