import xml.etree.ElementTree as ET
import uuid
from typing import List, Dict, Any, Optional, Generator


# XML namespace for CWE
NS = {"cwe": "http://cwe.mitre.org/cwe-7"}

# Object types to process
CWE_OBJECT_TYPES = ["Weakness", "Category"]


def get_cwe_id(element: ET.Element) -> str:
    """Extract the CWE ID (e.g., 'CWE-1004') from element."""
    raw_id = element.get("ID", "")
    return f"CWE-{raw_id}" if raw_id else None


def get_cwe_url(element: ET.Element) -> str:
    """Build the CWE URL from the ID."""
    raw_id = element.get("ID", "")
    if raw_id:
        return f"https://cwe.mitre.org/data/definitions/{raw_id}.html"
    return None


def get_name(element: ET.Element) -> str:
    """Extract the name attribute."""
    return element.get("Name", "Unknown")


def get_status(element: ET.Element) -> str:
    """Extract the status attribute."""
    return element.get("Status", "")


def get_abstraction(element: ET.Element) -> Optional[str]:
    """Extract the abstraction level (Pillar, Class, Base, Variant)."""
    return element.get("Abstraction")


def get_description(element: ET.Element) -> str:
    """Extract description text, handling mixed content."""
    desc_elem = element.find("cwe:Description", NS)
    if desc_elem is not None:
        return _get_text_content(desc_elem)
    return ""


def get_extended_description(element: ET.Element) -> str:
    """Extract extended description text."""
    ext_desc = element.find("cwe:Extended_Description", NS)
    if ext_desc is not None:
        return _get_text_content(ext_desc)
    return ""


def get_summary(element: ET.Element) -> str:
    """Extract summary text (for Categories)."""
    summary = element.find("cwe:Summary", NS)
    if summary is not None:
        return _get_text_content(summary)
    return ""


def _get_text_content(element: ET.Element) -> str:
    """Recursively extract all text content from an element, handling xhtml tags."""
    if element is None:
        return ""

    texts = []
    if element.text:
        texts.append(element.text.strip())

    for child in element:
        # Handle xhtml:p, xhtml:div, xhtml:br etc.
        child_text = _get_text_content(child)
        if child_text:
            texts.append(child_text)
        if child.tail:
            texts.append(child.tail.strip())

    return " ".join(filter(None, texts))


def get_platforms(element: ET.Element) -> List[str]:
    """Extract applicable platforms (technologies and languages)."""
    platforms = []
    applicable = element.find("cwe:Applicable_Platforms", NS)
    if applicable is not None:
        # Technologies
        for tech in applicable.findall("cwe:Technology", NS):
            name = tech.get("Name") or tech.get("Class")
            if name and name != "Not Technology-Specific":
                platforms.append(name)
        # Languages
        for lang in applicable.findall("cwe:Language", NS):
            name = lang.get("Name") or lang.get("Class")
            if name and name != "Not Language-Specific":
                platforms.append(name)
    return platforms


def get_consequences(element: ET.Element) -> List[Dict[str, str]]:
    """Extract common consequences (scope and impact)."""
    consequences = []
    common_consequences = element.find("cwe:Common_Consequences", NS)
    if common_consequences is not None:
        for consequence in common_consequences.findall("cwe:Consequence", NS):
            scope_elem = consequence.find("cwe:Scope", NS)
            impact_elem = consequence.find("cwe:Impact", NS)
            scope = scope_elem.text if scope_elem is not None else None
            impact = impact_elem.text if impact_elem is not None else None
            if scope or impact:
                consequences.append({"scope": scope, "impact": impact})
    return consequences


def get_related_weaknesses(element: ET.Element) -> List[Dict[str, str]]:
    """Extract related weakness relationships."""
    relationships = []
    related = element.find("cwe:Related_Weaknesses", NS)
    if related is not None:
        for rel in related.findall("cwe:Related_Weakness", NS):
            relationships.append({
                "nature": rel.get("Nature"),
                "cwe_id": rel.get("CWE_ID"),
                "ordinal": rel.get("Ordinal"),
            })
    return relationships


def get_observed_examples(element: ET.Element) -> List[Dict[str, str]]:
    """Extract observed CVE examples."""
    examples = []
    observed = element.find("cwe:Observed_Examples", NS)
    if observed is not None:
        for ex in observed.findall("cwe:Observed_Example", NS):
            ref_elem = ex.find("cwe:Reference", NS)
            desc_elem = ex.find("cwe:Description", NS)
            if ref_elem is not None:
                examples.append({
                    "cve": ref_elem.text,
                    "description": desc_elem.text if desc_elem is not None else "",
                })
    return examples


def get_submission_date(element: ET.Element) -> Optional[str]:
    """Extract the original submission date."""
    history = element.find("cwe:Content_History", NS)
    if history is not None:
        submission = history.find("cwe:Submission", NS)
        if submission is not None:
            date_elem = submission.find("cwe:Submission_Date", NS)
            if date_elem is not None:
                return date_elem.text
    return None


def get_object_type_label(tag: str) -> str:
    """Convert XML tag to human-readable label."""
    return tag  # "Weakness" or "Category"


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


def build_text_with_entities(element: ET.Element, obj_type: str) -> tuple[str, List[Dict[str, Any]]]:
    """
    Build the text content with inline identifiers and extract manual entities.

    Returns: (text, entities)
    """
    entities = []
    text_parts = []

    cwe_id = get_cwe_id(element)
    name = get_name(element)
    abstraction = get_abstraction(element)
    cwe_url = get_cwe_url(element)
    platforms = get_platforms(element)
    consequences = get_consequences(element)
    observed_examples = get_observed_examples(element)

    # Get description based on object type
    if obj_type == "Weakness":
        description = get_description(element)
        extended_desc = get_extended_description(element)
        if extended_desc:
            description = f"{description} {extended_desc}".strip()
    else:  # Category
        description = get_summary(element)

    # Build header: "[CWE-1004] Sensitive Cookie Without 'HttpOnly' Flag (Weakness - Variant)"
    if abstraction:
        header = f"[{cwe_id}] {name} ({obj_type} - {abstraction})"
    else:
        header = f"[{cwe_id}] {name} ({obj_type})"

    # Entity for CWE ID
    entities.append(create_entity(
        name=cwe_id,
        entity_type="cwe_id",
        role="identifier",
    ))

    # Entity for name
    entities.append(create_entity(
        name=name,
        entity_type=obj_type.lower(),
        role="name",
    ))

    # Entity for abstraction level
    if abstraction:
        entities.append(create_entity(
            name=abstraction,
            entity_type="abstraction",
            role="level",
        ))

    text_parts.append(header)

    # Add platforms if present
    if platforms:
        text_parts.append("\n\nPlatforms: ")
        text_parts.append(", ".join(platforms))
        for platform in platforms:
            entities.append(create_entity(
                name=platform,
                entity_type="platform",
                role="platform",
            ))

    # Add consequences if present
    if consequences:
        text_parts.append("\n\nConsequences:")
        for cons in consequences:
            scope = cons.get("scope", "")
            impact = cons.get("impact", "")
            if scope and impact:
                text_parts.append(f"\n- {scope}: {impact}")
                entities.append(create_entity(
                    name=scope,
                    entity_type="impact_scope",
                    role="consequence",
                ))
                entities.append(create_entity(
                    name=impact,
                    entity_type="impact",
                    role="consequence",
                ))

    # Add observed CVE examples (limit to first 5)
    if observed_examples:
        text_parts.append("\n\nObserved Examples:")
        for ex in observed_examples[:5]:
            cve = ex.get("cve", "")
            if cve:
                text_parts.append(f"\n- {cve}")
                entities.append(create_entity(
                    name=cve,
                    entity_type="cve",
                    role="example",
                ))

    # Add URL
    if cwe_url:
        text_parts.append(f"\n\nURL: {cwe_url}")

    # Add description
    if description:
        text_parts.append(f"\n\n{description}")

    return "".join(text_parts), entities


def cwe_to_text_item(
    element: ET.Element,
    obj_type: str,
) -> Optional[Dict[str, Any]]:
    """Convert a CWE XML element to a text item with manual entities."""
    # Skip deprecated/obsolete objects
    status = get_status(element)
    if status in ("Deprecated", "Obsolete"):
        return None

    text, entities = build_text_with_entities(element, obj_type)

    return {
        "text": text,
        "manual_entities": entities if entities else None
    }


def load_cwe_data(xml_path: str) -> Generator[tuple[ET.Element, str], None, None]:
    """
    Load CWE data from the XML file.

    Args:
        xml_path: Path to the CWE XML file

    Yields:
        Tuples of (element, object_type)
    """
    # Parse the XML file
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Process Weaknesses
    weaknesses = root.find("cwe:Weaknesses", NS)
    if weaknesses is not None:
        for weakness in weaknesses.findall("cwe:Weakness", NS):
            yield weakness, "Weakness"

    # Process Categories
    categories = root.find("cwe:Categories", NS)
    if categories is not None:
        for category in categories.findall("cwe:Category", NS):
            yield category, "Category"


def process_cwe(
    xml_path: str,
) -> List[Dict[str, Any]]:
    """
    Process CWE XML file into text items.

    Args:
        xml_path: Path to the CWE XML file

    Returns:
        List of text items ({"text": str, "manual_entities": List[Dict]})
    """
    text_items = []

    for element, obj_type in load_cwe_data(xml_path):
        item = cwe_to_text_item(element, obj_type)
        if item:
            text_items.append(item)

    return text_items


def enqueue_cwe(
    xml_path: str,
    core_name: str,
    source: str,
    session: str,
    batch_size: int = 100
) -> int:
    """
    Process CWE data and enqueue to Redis.

    Args:
        xml_path: Path to the CWE XML file
        core_name: Name of the core/index to store in
        source: Source identifier
        session: Session identifier
        batch_size: Number of text items per batch message

    Returns:
        Total number of text items enqueued
    """
    from messaging import enqueue
    from models import ExtractAndStoreBatchJob

    print(f"Processing CWE data from {xml_path}...")
    text_items = process_cwe(xml_path)

    # Enqueue in batches
    num_batches = 0
    for i in range(0, len(text_items), batch_size):
        batch = text_items[i:i + batch_size]
        job = ExtractAndStoreBatchJob(
            text_items=batch,
            core_name=core_name,
            source=source,
            session=session
        )
        enqueue("extract_and_store_batch", "extract-store-batch", args=(job.to_dict(),))
        num_batches += 1

    print(f"Enqueued {num_batches} batches")
    return len(text_items)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Process CWE data into text items")
    parser.add_argument("--xml-path", default="./cwec_v4.19.xml", help="Path to CWE XML file")
    parser.add_argument("--core-name", default="cwe", help="Core name for storage")
    parser.add_argument("--source", default="cwe", help="Source identifier")
    parser.add_argument("--batch-size", type=int, default=200, help="Batch size for enqueueing")
    parser.add_argument("--enqueue", action="store_true", help="Enqueue to Redis instead of just printing")

    args = parser.parse_args()
    session = str(uuid.uuid4())

    if args.enqueue:
        # Enqueue to Redis
        total = enqueue_cwe(
            xml_path=args.xml_path,
            core_name=args.core_name,
            source=args.source,
            session=session,
            batch_size=args.batch_size
        )
        print(f"\nEnqueued {total} text items in batches of {args.batch_size}")
    else:
        # Just process and print stats
        print(f"Processing CWE data from {args.xml_path}...")
        text_items = process_cwe(args.xml_path)

        print(f"\nTotal text items created: {len(text_items)}")

        # Count by type
        weaknesses = [item for item in text_items if "Weakness" in item["text"][:100]]
        categories = [item for item in text_items if "Category" in item["text"][:100]]
        print(f"  Weaknesses: {len(weaknesses)}")
        print(f"  Categories: {len(categories)}")

        # Print a sample
        if text_items:
            sample = text_items[0]
            print(f"\nSample text item:")
            print(f"  Text preview: {sample['text'][:300]}...")
            entities = sample.get("manual_entities") or []
            print(f"  Entities: {len(entities)}")
            for ent in entities[:5]:
                print(f"    - {ent['name']} ({ent['type']}, {ent['role']})")
