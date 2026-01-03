from models import KnowledgeObject
from datetime import datetime, timezone
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
    start: int,
    end: int
) -> Dict[str, Any]:
    """Create an entity dict for a KnowledgeObject."""
    return {
        "id": str(uuid.uuid4()),
        "name": name,
        "type": entity_type,
        "role": role,
        "start": start,
        "end": end,
    }


def build_text_with_entities(element: ET.Element, obj_type: str) -> tuple[str, List[Dict[str, Any]]]:
    """
    Build the text content for a KnowledgeObject with inline identifiers,
    and extract entities with their positions.

    Returns: (text, entities)
    """
    entities = []
    text_parts = []
    current_pos = 0

    cwe_id = get_cwe_id(element)
    name = get_name(element)
    abstraction = get_abstraction(element)
    status = get_status(element)
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
    id_start = 1  # After '['
    id_end = id_start + len(cwe_id)
    entities.append(create_entity(
        name=cwe_id,
        entity_type="cwe_id",
        role="identifier",
        start=id_start,
        end=id_end
    ))

    # Entity for name
    name_start = id_end + 2  # After '] '
    name_end = name_start + len(name)
    entities.append(create_entity(
        name=name,
        entity_type=obj_type.lower(),
        role="name",
        start=name_start,
        end=name_end
    ))

    # Entity for abstraction level
    if abstraction:
        # Position is after "({obj_type} - "
        abstraction_start = name_end + len(f" ({obj_type} - ")
        abstraction_end = abstraction_start + len(abstraction)
        entities.append(create_entity(
            name=abstraction,
            entity_type="abstraction",
            role="level",
            start=abstraction_start,
            end=abstraction_end
        ))

    text_parts.append(header)
    current_pos = len(header)

    # Add platforms if present
    if platforms:
        text_parts.append("\n\nPlatforms: ")
        current_pos += len("\n\nPlatforms: ")
        platform_strs = []
        for platform in platforms:
            platform_start = current_pos + len(", ".join(platform_strs))
            if platform_strs:
                platform_start += 2  # ", "
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

    # Add consequences if present
    if consequences:
        text_parts.append("\n\nConsequences:")
        current_pos += len("\n\nConsequences:")
        for cons in consequences:
            scope = cons.get("scope", "")
            impact = cons.get("impact", "")
            if scope and impact:
                line = f"\n- {scope}: {impact}"
                text_parts.append(line)
                # Entity for scope
                scope_start = current_pos + 3  # After "\n- "
                entities.append(create_entity(
                    name=scope,
                    entity_type="impact_scope",
                    role="consequence",
                    start=scope_start,
                    end=scope_start + len(scope)
                ))
                # Entity for impact
                impact_start = scope_start + len(scope) + 2  # After ": "
                entities.append(create_entity(
                    name=impact,
                    entity_type="impact",
                    role="consequence",
                    start=impact_start,
                    end=impact_start + len(impact)
                ))
                current_pos += len(line)

    # Add observed CVE examples (limit to first 5)
    if observed_examples:
        text_parts.append("\n\nObserved Examples:")
        current_pos += len("\n\nObserved Examples:")
        for ex in observed_examples[:5]:
            cve = ex.get("cve", "")
            if cve:
                line = f"\n- {cve}"
                text_parts.append(line)
                cve_start = current_pos + 3  # After "\n- "
                entities.append(create_entity(
                    name=cve,
                    entity_type="cve",
                    role="example",
                    start=cve_start,
                    end=cve_start + len(cve)
                ))
                current_pos += len(line)

    # Add URL
    if cwe_url:
        text_parts.append(f"\n\nURL: {cwe_url}")
        current_pos += len(f"\n\nURL: {cwe_url}")

    # Add description
    if description:
        text_parts.append(f"\n\n{description}")

    return "".join(text_parts), entities


def cwe_to_knowledge_object(
    element: ET.Element,
    obj_type: str,
    source: str,
    session: str
) -> Optional[KnowledgeObject]:
    """Convert a CWE XML element to a KnowledgeObject."""
    # Skip deprecated/obsolete objects
    status = get_status(element)
    if status in ("Deprecated", "Obsolete"):
        return None

    # Generate a new KO ID
    ko_id = f"ko_{uuid.uuid4().hex[:12]}"

    text, entities = build_text_with_entities(element, obj_type)

    # Build predicates from relationships
    predicates = []
    related = get_related_weaknesses(element)

    # Check for parent relationship (ChildOf)
    has_parent = any(r["nature"] == "ChildOf" for r in related)
    if has_parent:
        predicates.append({
            "id": str(uuid.uuid4()),
            "name": "child_of",
            "predicate_type": "hierarchy",
            "primary": True,
        })

    # Get creation date
    submission_date = get_submission_date(element)
    if submission_date:
        created_at = submission_date
    else:
        created_at = datetime.now(timezone.utc).isoformat()

    return KnowledgeObject(
        id=ko_id,
        text=text,
        entities=entities,
        predicates=predicates,
        source=source,
        session=session,
        created_at=created_at
    )


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
    source: str,
    session: str
) -> List[KnowledgeObject]:
    """
    Process CWE XML file into KnowledgeObjects.

    Args:
        xml_path: Path to the CWE XML file
        source: Source identifier for KnowledgeObjects
        session: Session identifier for KnowledgeObjects

    Returns:
        List of KnowledgeObjects
    """
    knowledge_objects = []

    for element, obj_type in load_cwe_data(xml_path):
        ko = cwe_to_knowledge_object(element, obj_type, source, session)
        if ko:
            knowledge_objects.append(ko)

    return knowledge_objects


if __name__ == "__main__":
    # Example usage
    import os

    XML_PATH = os.path.join("..", "data", "cwec_v4.19.xml")
    SOURCE = "cwe"
    SESSION = str(uuid.uuid4())

    print(f"Processing CWE data from {XML_PATH}...")

    knowledge_objects = process_cwe(XML_PATH, SOURCE, SESSION)

    print(f"\nTotal KnowledgeObjects created: {len(knowledge_objects)}")

    # Count by type
    weaknesses = [ko for ko in knowledge_objects if "Weakness" in ko.text[:100]]
    categories = [ko for ko in knowledge_objects if "Category" in ko.text[:100]]
    print(f"  Weaknesses: {len(weaknesses)}")
    print(f"  Categories: {len(categories)}")

    # Print a sample
    if knowledge_objects:
        sample = knowledge_objects[0]
        print(f"\nSample KnowledgeObject:")
        print(f"  ID: {sample.id}")
        print(f"  Text preview: {sample.text[:300]}...")
        print(f"  Entities: {len(sample.entities)}")
        for ent in sample.entities[:5]:
            print(f"    - {ent['name']} ({ent['type']}, {ent['role']})")
        print(f"  Predicates: {len(sample.predicates)}")
        for pred in sample.predicates:
            print(f"    - {pred['name']} ({pred['predicate_type']})")
