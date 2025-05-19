import hashlib
import magic
import yara
from models import ScanResult
import uuid
import os
from datetime import datetime, timezone
from database import SessionLocal

def compile_yara_rules(folder: str) -> dict:
    rule_files = [os.path.join(folder, f) for f in os.listdir(folder) if f.endswith(".yar")]
    compiled_rules = {}
    for file in rule_files:
        try:
            rule_name = os.path.splitext(os.path.basename(file))[0]
            compiled_rules[rule_name] = yara.compile(filepath=file)
        except yara.YARAError as e:
            print(f"[YARA Compile Error] {file}: {e}")
    return compiled_rules

# Load the rules once globally to avoid reloading on every scan
compiled_yara_rules = compile_yara_rules("../yara_rules")

# In the future, you can add YARA or ML scanning here
def analyze_file(filename: str, contents: bytes) -> dict:
    sha256 = hashlib.sha256(contents).hexdigest()
    md5 = hashlib.md5(contents).hexdigest()
    sha1 = hashlib.sha1(contents).hexdigest()
    sha512 = hashlib.sha512(contents).hexdigest()
    sha3_256 = hashlib.sha3_256(contents).hexdigest()
    blake2b = hashlib.blake2b(contents).hexdigest()
    blake2s = hashlib.blake2s(contents).hexdigest()
    
    # Stub for fake malware check (replace with real ML/YARA later)
    yara_matches = {}
    for rule_name, rule in compiled_yara_rules.items():
        try:
            matches = rule.match(data=contents)
            if matches:
                yara_matches[rule_name] = []
                for match in matches:
                    match_data = {
                        "rule": match.rule,
                        "tags": match.tags,
                        "meta": match.meta,
                        "strings": []
                    }
                    
                    # Process each string match
                    for string in match.strings:
                        identifier = string.identifier.decode() if isinstance(string.identifier, bytes) else str(string.identifier)
                        string_data = {
                            "identifier": identifier
                        }
                        match_data["strings"].append(string_data)
                    
                    yara_matches[rule_name].append(match_data)
        except Exception as e:
            error_type = type(e).__name__
            yara_matches[rule_name] = [f"Unexpected {error_type}: {str(e)}"]
            print(f"[Unexpected Error] Rule '{rule_name}': {error_type} - {e}")

    # Determine malicious status based on YARA matches
    is_malicious = len(yara_matches) > 0

    # Detect file type using libmagic
    mime = magic.Magic(mime=True)
    filetype = mime.from_buffer(contents)

    # Optional: also get human-readable description (e.g., "Python script, ASCII text")
    filetype_desc = magic.Magic().from_buffer(contents)

    scan_result = ScanResult(
        id=uuid.uuid4().hex,
        name=filename,
        md5=md5,
        type="file",
        filetype=filetype_desc,
        timestamp=datetime.now(timezone.utc),
        threat_level="low",
        detected=2,
        total=15
    )
    # Save the scan result to the database
    session = SessionLocal()
    session.add(scan_result)
    session.commit()
    session.close()

    return {
        "filename": filename,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "sha512": sha512,
        "sha3_256": sha3_256,
        "blake2b": blake2b,
        "blake2s": blake2s,
        "filetype": filetype_desc,
        "malicious": is_malicious,
        "yara_matches": yara_matches,
        "status": "scanned"
    }

