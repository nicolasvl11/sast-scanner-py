from .base import Rule, Severity, Language

UNSAFE_DESERIALIZATION_RULES = [
    Rule(
        id="DESER-001",
        name="Unsafe Java Deserialization (ObjectInputStream)",
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        description="ObjectInputStream.readObject() deserializes untrusted data. Attackers can craft malicious serialized objects to achieve RCE (see Apache Commons exploit chains).",
        remediation="Avoid Java serialization for untrusted data. Use JSON/XML with schema validation. If serialization required, implement a ValidatingObjectInputStream with an allowlist.",
        patterns=[
            r'new\s+ObjectInputStream\s*\(',
            r'readObject\s*\(\s*\)',
            r'readUnshared\s*\(\s*\)',
        ],
        languages=[Language.JAVA],
    ),
    Rule(
        id="DESER-002",
        name="Unsafe Python Pickle Deserialization",
        severity=Severity.CRITICAL,
        cwe="CWE-502",
        description="pickle.loads() on untrusted data enables arbitrary code execution. The __reduce__ method can define any OS command to run on deserialization.",
        remediation="Never unpickle data from untrusted sources. Use json, msgpack, or protobuf instead. If pickle is required, sign and verify payloads before deserializing.",
        patterns=[
            r'pickle\.(loads|load|Unpickler)',
            r'cPickle\.(loads|load)',
            r'_pickle\.(loads|load)',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="DESER-003",
        name="Unsafe YAML Load (Python)",
        severity=Severity.HIGH,
        cwe="CWE-502",
        description="yaml.load() without Loader=yaml.SafeLoader can deserialize arbitrary Python objects, enabling code execution.",
        remediation="Replace yaml.load(data) with yaml.safe_load(data) or yaml.load(data, Loader=yaml.SafeLoader).",
        patterns=[
            r'yaml\.load\s*\(\s*(?!.*SafeLoader)(?!.*BaseLoader)',
            r'yaml\.load\s*\([^,)]+\)',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="DESER-004",
        name="Unsafe Marshal Deserialization (Python)",
        severity=Severity.HIGH,
        cwe="CWE-502",
        description="marshal.loads() on untrusted data can cause crashes or arbitrary code execution.",
        remediation="Do not use marshal for untrusted data. Use json for data interchange.",
        patterns=[
            r'marshal\.(loads|load)\s*\(',
        ],
        languages=[Language.PYTHON],
    ),
    Rule(
        id="DESER-005",
        name="XStream Deserialization (Java)",
        severity=Severity.HIGH,
        cwe="CWE-502",
        description="XStream without security configuration can deserialize arbitrary classes from XML, enabling RCE.",
        remediation="Call xstream.addPermission(NoTypePermission.NONE) and explicitly allowlist required types. Use XStream.setupDefaultSecurity(xstream).",
        patterns=[
            r'new\s+XStream\s*\(',
            r'XStream\s+\w+\s*=\s*new\s+XStream',
        ],
        languages=[Language.JAVA],
    ),
]
