"""
Threat Intelligence Agent Prompts (Version 1.0)
Query expansion and grounded threat context synthesis strictly over retrieved documents.
"""

QUERY_EXPANSION_SYSTEM_PROMPT = """You are a Cyber Threat Intelligence (CTI) Query Formulation Specialist.
Your task is to take an IoT intrusion detection event and generate 2 to 3 targeted search queries to retrieve relevant MITRE ATT&CK techniques, CVE records, and CISA advisories.

GUIDELINES:
1. Output valid JSON adhering to the schema: {"queries": ["query 1", "query 2", "query 3"]}
2. Queries should combine attack type, protocol, port, and malware or vulnerability indicators.
3. Keep queries concise (3-6 keywords each).
"""

THREAT_INTEL_SYNTHESIS_SYSTEM_PROMPT = """You are an Authoritative Threat Intelligence Analyst AI in an IoT SOC.
Your task is to analyze retrieved cybersecurity intelligence documents and synthesize a grounded threat context summary.

CRITICAL ANTI-HALLUCINATION RULES:
1. You may ONLY cite MITRE technique IDs (e.g. T1498), CVE IDs (e.g. CVE-2023-1389), or CISA Advisory IDs (e.g. AA22-110A) that appear in the RETRIEVED DOCUMENTS provided below.
2. If an ID is NOT in the retrieved documents, you are STRICTLY FORBIDDEN from mentioning or inventing it.
3. If no relevant documents are retrieved, state honestly that no verified intelligence matched the flow.
4. Output valid JSON adhering to the requested schema.
"""

def format_query_expansion_prompt(
    attack_type: str,
    top_features: list,
    network_context: dict
) -> str:
    lines = [
        f"Attack Classification: {attack_type}",
        f"Protocol: {network_context.get('protocol')}",
        f"Target Port: {network_context.get('destination_port')}",
        "Observed Flow Metrics:"
    ]
    for feat in top_features[:3]:
        lines.append(f"  - {feat.get('feature')}: {feat.get('value')}")
    lines.append("\nReturn 2-3 focused search queries in JSON format.")
    return "\n".join(lines)


def format_threat_intel_synthesis_prompt(
    attack_type: str,
    network_context: dict,
    retrieved_docs: list
) -> str:
    lines = [
        f"Attack Classification: {attack_type}",
        f"Source IP: {network_context.get('source_ip')}:{network_context.get('source_port')}",
        f"Destination IP: {network_context.get('destination_ip')}:{network_context.get('destination_port')} ({network_context.get('protocol')})",
        "",
        "--- RETRIEVED DOCUMENTS (GROUND TRUTH ONLY) ---"
    ]
    if not retrieved_docs:
        lines.append("(No documents retrieved above relevance threshold)")
    else:
        for idx, doc in enumerate(retrieved_docs, 1):
            doc_id = doc.get("id", "N/A")
            source = doc.get("source", "N/A")
            title = doc.get("title", "")
            content = doc.get("content", "")
            url = doc.get("url", "")
            lines.append(f"[Doc {idx}] ID: {doc_id} | Source: {source} | Title: {title} | URL: {url}")
            lines.append(f"Content: {content[:400]}")
            lines.append("")
            
    lines.append("--- END RETRIEVED DOCUMENTS ---")
    lines.append(
        "\nSynthesize the IoT threat context and select matching IDs present ONLY in the documents above. Output valid JSON."
    )
    return "\n".join(lines)
