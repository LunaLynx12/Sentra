from fastapi import APIRouter, UploadFile, File, HTTPException, Form
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from services import file_scanner  # Make sure this is implemented
import os
import re
import base64
from PIL import Image, JpegImagePlugin, ExifTags, UnidentifiedImageError
import os
import json
import fitz  # PyMuPDF
from pydantic import BaseModel
import uuid
from dotenv import load_dotenv
from google import genai
from google.genai.types import Tool, GenerateContentConfig, GoogleSearch
import pefile
import peutils
import io
import hashlib
import tempfile

# Load environment variables
load_dotenv()
api_key = os.getenv("API_KEY")
max_size = os.getenv("KEY_LENGTH", "10")
if api_key is None:
    print("Error: API key not found in .env file.")
    exit()

if max_size is None:
    print("Error: Key length not found in .env file.")
    exit()

# Initialize Gemini client
client = genai.Client(api_key=api_key)
model_id = "gemini-2.0-flash"
google_search_tool = Tool(google_search=GoogleSearch())

# Setup router
router = APIRouter(prefix="/scan", tags=["Scan"])

# Models
class URLRequest(BaseModel):
    url: str

class FileScanRequest(BaseModel):
    loggedin: bool = False

# PE Analysis Functions
def get_pe_sections(pe):
    sections = []
    for section in pe.sections:
        section_data = {
            "name": section.Name.decode().rstrip('\x00'),
            "virtual_address": hex(section.VirtualAddress),
            "virtual_size": hex(section.Misc_VirtualSize),
            "raw_size": hex(section.SizeOfRawData),
            "entropy": section.get_entropy(),
            "characteristics": hex(section.Characteristics)
        }
        sections.append(section_data)
    return sections

def get_pe_imports(pe):
    imports = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode()
            functions = []
            for imp in entry.imports:
                if imp.name:
                    functions.append(imp.name.decode())
                else:
                    functions.append(f"ordinal_{imp.ordinal}")
            imports[dll] = functions
    return imports

def get_pe_exports(pe):
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode())
            else:
                exports.append(f"ordinal_{exp.ordinal}")
    return exports

def get_pe_resources(pe):
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = str(resource_type.name)
            else:
                name = pefile.RESOURCE_TYPE.get(resource_type.id, str(resource_type.id))
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData,
                                               resource_lang.data.struct.Size)
                            size = resource_lang.data.struct.Size
                            resources.append({
                                "type": name,
                                "size": size,
                                "sha256": hashlib.sha256(data).hexdigest()
                            })
    return resources


def analyze_pdf_text(pdf_path):
    """
    Analyzes a PDF file for hidden or very small text and returns structured findings.
    
    Args:
        pdf_path (str): Path to the input PDF file.
        
    Returns:
        dict: Structured result with "findings" and "full_text".
    """
    doc = fitz.open(pdf_path)
    findings = []
    full_text = ""

    try:
        for page_num in range(doc.page_count):
            page = doc.load_page(page_num)
            text_blocks = page.get_text("dict", flags=11)["blocks"]

            for block in text_blocks:
                if block['type'] == 0:
                    for line in block["lines"]:
                        for span in line["spans"]:
                            text = span["text"].strip()
                            font_size = span["size"]
                            color = span["color"]
                            rendering_mode = span.get("rendering_mode")
                            color_hex = f"#{color:06x}"

                            reasons = []
                            if font_size < 5:
                                reasons.append("Very Small Text")
                            if color >= 0xF0F0F0:
                                reasons.append("Potentially Hidden (Color)")
                            if rendering_mode == 3:
                                reasons.append("Hidden Text (Invisible Rendering)")

                            if reasons and text:
                                findings.append({
                                    "page": page_num + 1,
                                    "reasons": reasons,
                                    "text": text,
                                    "font_size": round(font_size, 2),
                                    "color": color_hex
                                })

            # Extract full text
            full_text += page.get_text("text") + "\n"

    finally:
        doc.close()

    return {
        "findings": findings,
        "full_text": full_text.strip()
    }

def analyze_pe(file_path):
    """Analyze a PE file and return detailed information"""
    try:
        pe = pefile.PE(file_path)

        pe_info = {
            "machine": pe.FILE_HEADER.Machine,
            "compile_time": pe.FILE_HEADER.TimeDateStamp,
            "entry_point": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "image_base": pe.OPTIONAL_HEADER.ImageBase,
            "subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "dll_characteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "sections": get_pe_sections(pe),
            "imports": get_pe_imports(pe),
            "exports": get_pe_exports(pe),
            "resources": get_pe_resources(pe),
            "is_dll": pe.is_dll(),
            "is_exe": pe.is_exe(),
            "is_driver": pe.is_driver()
        }

        # Check for packers using peutils
        # Ensure the signatures.txt file exists; create if not
        signatures_path = '../signatures.txt'
        if not os.path.exists(signatures_path):
            with open(signatures_path, 'w') as sig_file:
                sig_file.write('')  # Create an empty signatures.txt
        signatures = peutils.SignatureDatabase(signatures_path)
        matches = signatures.match(pe, ep_only=True)
        if matches:
            pe_info["packer"] = matches[0][0] if isinstance(matches[0], tuple) else matches[0]
        else:
            pe_info["packer"] = "Unknown"

        return pe_info
    except pefile.PEFormatError as e:
        return {"error": f"Invalid PE file format: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error during PE analysis: {str(e)}"}
    finally:
        if 'pe' in locals():
            pe.close()

def calculate_md5(file_path):
    hasher = hashlib.md5()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    return hasher.hexdigest()

def is_base64_encoded(data):
    try:
        return base64.b64encode(base64.b64decode(data)) == data
    except Exception:
        return False

def check_for_steganography(file_bytes):
    suspicious_strings = [b'STEG', b'steg', b'Hidden', b'Data']
    for s in suspicious_strings:
        if s in file_bytes:
            return True
    return False

def extract_exif_metadata(image_path, exif_findings):
    metadata = {}
    try:
        image = Image.open(image_path)
        exif_data = image._getexif()
        if exif_data:
            exif = {ExifTags.TAGS.get(tag): val for tag, val in exif_data.items() if tag in ExifTags.TAGS}
            metadata["device_make"] = exif.get("Make")
            metadata["device_model"] = exif.get("Model")
            metadata["software"] = exif.get("Software")
            metadata["datetime"] = exif.get("DateTime")

            if len(exif) > 50:
                exif_findings.append("Unusually large number of EXIF tags (possible payload hiding).")
            if 'GPSInfo' in exif:
                exif_findings.append("GPS data present (privacy risk).")
            for key, val in exif.items():
                if isinstance(val, bytes):
                    try:
                        val.decode('utf-8')
                    except Exception:
                        exif_findings.append(f"Non-decodable EXIF tag detected: {key}")
    except Exception:
        pass
    return metadata

def detect_embedded_exe(file_path):
    alerts = []
    exe_offset = None
    extracted = None
    with open(file_path, 'rb') as f:
        data = f.read()
    mz_locations = [m.start() for m in re.finditer(b'MZ', data)]
    for offset in mz_locations:
        if offset + 64 <= len(data):
            exe_offset = offset
            alerts.append(f"⚠️ EXE-like signature (MZ header) found at offset {exe_offset}.")
            extracted = "extracted_payload.exe"
            with open(extracted, 'wb') as out:
                out.write(data[exe_offset:])
            break
    return exe_offset, alerts, extracted

def analyze_image(file_path):
    result = {}
    findings = []
    
    try:
        # Get basic file info
        result["file_name"] = os.path.basename(file_path)
        result["file_size_kB"] = round(os.path.getsize(file_path) / 1024)
        result["md5_checksum"] = calculate_md5(file_path)

        with open(file_path, "rb") as f:
            file_bytes = f.read()
            if check_for_steganography(file_bytes):
                findings.append("🔍 Potential steganography detected (suspicious byte patterns).")

        with Image.open(io.BytesIO(file_bytes)) as img:
            result["file_format"] = img.format
            result["mime_type"] = Image.MIME.get(img.format, "unknown")
            result["dimensions"] = f"{img.width}x{img.height}"
            result["megapixels"] = round((img.width * img.height) / 1_000_000, 2)

            # JPEG comment check
            if img.format == "JPEG":
                info: JpegImagePlugin.JpegImageFile = img
                comment = info.info.get("comment")
                if comment:
                    try:
                        decoded = base64.b64decode(comment).decode('utf-8')
                        result["jpeg_comment"] = decoded
                        findings.append("Base64-encoded comment found in JPEG.")
                    except Exception:
                        try:
                            decoded = comment.decode('utf-8')
                            result["jpeg_comment"] = decoded
                            if "<script>" in decoded.lower():
                                findings.append("🔴 Embedded script tag found in JPEG comment.")
                        except Exception:
                            result["jpeg_comment"] = "Unreadable comment"

            # EXIF metadata
            exif_findings = []
            exif_metadata = extract_exif_metadata(file_path, exif_findings)
            result.update({k: v for k, v in exif_metadata.items() if v})
            findings.extend(exif_findings)

    except UnidentifiedImageError:
        findings.append("❌ File is not a valid image.")
    except Exception as e:
        findings.append(f"Error reading image: {str(e)}")
    
    # Embedded .exe scan
    exe_offset, alerts, extracted = detect_embedded_exe(file_path)
    if exe_offset is not None:
        result["exe_detection"] = f"✅ Embedded .exe detected at offset {exe_offset} and extracted to '{extracted}'"
        findings.extend(alerts)
    else:
        result["exe_detection"] = "❌ No embedded .exe detected"

    # Final findings
    if findings:
        result["security_findings"] = findings

    return result  # Always returns a dict

# File Upload Endpoint
@router.post("/")
async def scan_uploaded_file(file: UploadFile = File(...), loggedin: bool = Form(False)):
    contents = await file.read()
    filename = file.filename or "uploaded_file"

    #TODO Size check
    if len(contents) > int(max_size) * 1024 * 1024:
        return JSONResponse(status_code=200, content={
            "name": filename,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "file",
            "detail": "This file exceeds the 25 MB limit for guest users."
        })

    unique_id = str(uuid.uuid4())
    save_dir = "uploaded_files"
    os.makedirs(save_dir, exist_ok=True)
    saved_path = os.path.join(save_dir, f"{unique_id}_{filename}")

    try:
        with open(saved_path, "wb") as f:
            f.write(contents)
        result = file_scanner.analyze_file(filename, contents)
        # print(f"Analysis result: {result}")

        pe_analysis = {}
        file_type = result.get("filetype", "").lower()
        if any(keyword in file_type for keyword in ["pe", "exe", "dll", "sys"]):
            # print(f"Performing PE analysis on: {saved_path}")
            pe_analysis = analyze_pe(saved_path)
            # print(f"PE analysis result: {pe_analysis}")
        else:
            print(f"Skipping PE analysis: Not a PE file (filetype={file_type})")

        detections = []
        yara_matches = result.get("yara_matches", {})

        for rule_name, matches in yara_matches.items():
            if not isinstance(matches, list):
                # Just add raw result if not a proper match list
                detections.append({"engine": rule_name, "result": str(matches)})
                continue

            for match in matches:
                if not isinstance(match, dict):
                    detections.append({"engine": rule_name, "result": str(match)})
                    continue

                # Extract meaningful info from the match
                detection_entry = {
                    "engine": rule_name,
                    "rule": match.get("rule"),
                    "tags": match.get("tags", []),
                    "meta": match.get("meta", {}),
                    "strings": []
                }

                matched_strings = match.get("strings", [])
                if isinstance(matched_strings, list):
                    for s in matched_strings:
                        if isinstance(s, dict):
                            # Convert offset bytes to actual string value
                            data = s.get("data")
                            detection_entry["strings"].append({
                                "identifier": s.get("identifier")
                            })
                detections.append(detection_entry)

        #if fyletype contains 'PDF document' run analyze_pdf_text and add the extrafields
        pdf_analysis = {}
        if "pdf document" in file_type.lower():
            print(f"Performing PDF analysis on: {saved_path}")
            try:
                pdf_result = analyze_pdf_text(saved_path)
                pdf_analysis = {
                    "findings": pdf_result["findings"],
                    "sample_text": pdf_result["full_text"][:500] + "..." if len(pdf_result["full_text"]) > 500 else pdf_result["full_text"]
                }
                print("PDF analysis completed.")
            except Exception as e:
                print(f"Error during PDF analysis: {e}")
                pdf_analysis = {"error": str(e)}
        else:
            pdf_analysis = None

        image_analysis = {}
        file_type = result.get("filetype", "").lower()
        is_image = any(ext in file_type for ext in ["jpeg", "jpg", "png", "bmp", "gif"])
        
        if is_image:
            print(f"Performing image analysis on: {saved_path}")
            try:
                image_result = analyze_image(saved_path)
                image_analysis = {
                    "findings": image_result.get("security_findings", []),
                    "file_format": image_result.get("file_format"),
                    "dimensions": image_result.get("dimensions"),
                    "megapixels": image_result.get("megapixels"),
                    "device_make": image_result.get("device_make"),
                    "device_model": image_result.get("device_model"),
                    "software": image_result.get("software"),
                    "datetime": image_result.get("datetime"),
                    "exe_detection": image_result.get("exe_detection"),
                    "jpeg_comment": image_result.get("jpeg_comment")
                }
                print("Image analysis completed.")
            except Exception as e:
                print(f"Error during image analysis: {e}")
                image_analysis = {"error": str(e)}
        else:
            image_analysis = None

        response_data = {
            "id": unique_id,
            "type": "file",
            "filetype": file_type,
            "name": filename,
            "hashes": {
                "md5": result["md5"],
                "sha1": result["sha1"],
                "sha256": result["sha256"],
                "sha512": result["sha512"],
                "sha3_256": result["sha3_256"],
                "blake2b": result["blake2b"],
                "blake2s": result["blake2s"]
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "threatLevel": "high" if result.get("malicious", False) else "low",
            "detectionRatio": {
                "detected": len(detections),
                "total": len(file_scanner.compiled_yara_rules)
            },
            "detections": detections,
            "pe_analysis": pe_analysis if pe_analysis and "error" not in pe_analysis else None,
            "pdf_analysis": pdf_analysis if pdf_analysis else None,
            "image_analysis": image_analysis if image_analysis else None
        }
        print("detections:", detections)

    except Exception as e:
        print(f"Error during file processing: {e}")
        return JSONResponse(status_code=500, content={"error": str(e)})
    finally:
        if os.path.exists(saved_path):
            os.remove(saved_path)

    return JSONResponse(content=response_data)



# URL Scan Endpoint
@router.post("/url/")
async def scan_url(request: URLRequest):
    url = request.url
    if not url:
        raise HTTPException(status_code=400, detail="URL is required.")

    prompt = f"""
    Analyze this URL for phishing/safety: {url}
    Respond STRICTLY in this JSON format:
    {{
        "type": "url",
        "name": "example.com",
        "threatlevel": "safe/phishing",
        "analysis": "brief reason"
    }}
    """

    try:
        response = client.models.generate_content(
            model=model_id,
            contents=prompt,
            config=GenerateContentConfig(tools=[google_search_tool], response_modalities=["TEXT"]),
        )
        response_content = response.candidates[0].content.parts[0].text.strip()
        cleaned_response = response_content.replace('```json', '').replace('```', '').strip()

        try:
            json_response = json.loads(cleaned_response)
            analysis_text = json_response.get("analysis", "")
            if isinstance(analysis_text, str):
                analysis_text = re.sub(r'\[.*?\]', '', analysis_text).strip()

            return JSONResponse(content={
                "url": url,
                "threatLevel": json_response.get("threatlevel", "unknown"),
                "type": json_response.get("type", "url"),
                "name": json_response.get("name", url),
                "analysis": analysis_text
            })
        except json.JSONDecodeError:
            return JSONResponse(content={"url": url, "warning": "Model returned non-JSON response", "rawResponse": cleaned_response})
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error communicating with model: {str(e)}")
    

@router.post("/pdf/")
async def scan_pdf(file: UploadFile = File(...)):
    """
    Upload and analyze a PDF file for potentially hidden content.
    """
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are allowed.")

    # Create a temporary directory to store the uploaded file
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_file_path = os.path.join(tmpdir, file.filename)

        # Save the uploaded file to the temporary location
        with open(temp_file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)

        # Run PDF analysis
        try:
            result = analyze_pdf_text(temp_file_path)
            return JSONResponse(content={
                "filename": file.filename,
                "threatLevel": "suspicious" if result["findings"] else "safe",
                "analysis": {
                    "hidden_or_small_text_count": len(result["findings"]),
                    "findings": result["findings"],
                    "sample_text": result["full_text"][:500] + "..." if len(result["full_text"]) > 500 else result["full_text"]
                }
            })
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error analyzing PDF: {str(e)}")