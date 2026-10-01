"""Bounded review transcripts, never a sanitized document or pixel verifier.

Run untrusted parsers in document_review_worker. Office packages are inspected
in memory; relationships, macros and embedded files are never opened/executed.
Every package member and PDF page has an inventory entry, including gaps.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from io import BytesIO, StringIO
import math
import posixpath
import re
import shutil
import subprocess
from zipfile import ZipFile

from defusedxml.ElementTree import fromstring

MAX_FILE_BYTES = 8_000_000
MAX_TEXT_BYTES = 2_000_000
MAX_PAGES = 400
MAX_PARTS = 2_000
MAX_EXPANDED_BYTES = 32_000_000
MAX_SURFACES = 6_000
MAX_OCR_PAGES = 8


class DocumentError(ValueError):
    """Only fixed, source-free codes cross the API boundary."""


@dataclass
class Extraction:
    surfaces: list[dict] = field(default_factory=list)
    inventory: list[dict] = field(default_factory=list)
    gaps: set[str] = field(default_factory=set)
    text_bytes: int = 0

    def add(self, identifier: str, kind: str, text: str, **location) -> None:
        self.text_bytes += len(text.encode("utf-8"))
        if self.text_bytes > MAX_TEXT_BYTES or len(self.surfaces) >= MAX_SURFACES:
            raise DocumentError("TEXT_LIMIT")
        self.surfaces.append({"id": identifier, "kind": kind, "text": text,
                              "location": location, "status": "EXTRACTED" if text.strip() else "EMPTY"})


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _strings(element, tags=("t",), *, paragraph=False) -> str:
    pieces = []
    pending = [element]
    while pending:
        node = pending.pop()
        tag = _local(node.tag)
        # Text-box paragraphs are inventoried independently by the caller.
        # Reading them through their enclosing paragraph duplicates findings
        # and can join unrelated visible text into an invented name.
        if paragraph and node is not element and tag == "p":
            pieces.append("\n")
            continue
        pending.extend(reversed(list(node)))
        if tag in tags:
            pieces.append(node.text or "")
        elif tag == "tab":
            pieces.append("\t")
        elif tag in {"br", "cr"}:
            pieces.append("\n")
    return "".join(pieces)


def _xml(raw: bytes):
    # defusedxml rejects DTD entity expansion and external entities independent
    # of XML encoding. Do not substitute a byte-string check for this parser.
    return fromstring(raw, forbid_dtd=True, forbid_entities=True, forbid_external=True)


def extract_office(raw: bytes, extension: str) -> Extraction:
    result = Extraction()
    try:
        with ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            if (len(members) > MAX_PARTS or sum(item.file_size for item in members) > MAX_EXPANDED_BYTES
                    or any(item.flag_bits & 1 for item in members)):
                raise DocumentError("PACKAGE_LIMIT_OR_ENCRYPTION")
            names = [item.filename for item in members]
            if (len(names) != len(set(names)) or any(len(name) > 512 or "\\" in name
                    or name.startswith("/") or ".." in name.split("/") for name in names)):
                raise DocumentError("INVALID_PACKAGE_PATHS")
            main_part = {"docx": "word/document.xml", "pptx": "ppt/presentation.xml", "xlsx": "xl/workbook.xml"}[extension]
            if main_part not in names or "[Content_Types].xml" not in names:
                raise DocumentError("FORMAT_MISMATCH")
            parsed = {}
            for member in members:
                name = member.filename
                if member.is_dir():
                    result.inventory.append({"id": name, "status": "EMPTY", "kind": "directory"})
                elif name.endswith((".xml", ".rels")):
                    parsed[name] = _xml(archive.read(member))
                else:
                    result.inventory.append({"id": name, "status": "UNMEASURED", "kind": "binary-part"})
                    result.gaps.add("OFFICE_IMAGES_EMBEDDINGS_MACROS_UNMEASURED")

            # Preserve worksheet visibility, names, all cells, formula source,
            # hidden rows/columns, and unused shared strings as separate data.
            sheets = {}
            shared = []
            if extension == "xlsx":
                if "xl/sharedStrings.xml" in parsed:
                    shared = [_strings(node) for node in parsed["xl/sharedStrings.xml"] if _local(node.tag) == "si"]
                rels = {node.attrib.get("Id"): node.attrib.get("Target", "")
                        for node in parsed.get("xl/_rels/workbook.xml.rels", [])
                        if node.attrib.get("TargetMode") != "External"}
                for sheet in parsed[main_part].iter():
                    if _local(sheet.tag) == "sheet":
                        rel = next((v for k, v in sheet.attrib.items() if _local(k) == "id"), None)
                        target = rels.get(rel, "")
                        part = target.lstrip("/") if target.startswith("/") else posixpath.normpath(posixpath.join("xl", target))
                        if part not in parsed:
                            raise DocumentError("MISSING_WORKSHEET")
                        sheets[part] = {"sheet": sheet.attrib.get("name", ""), "visibility": sheet.attrib.get("state", "visible")}

            for name, element in parsed.items():
                kind, location = "office-auxiliary", {"part": name}
                if name in sheets:
                    kind = "xlsx-sheet"
                    location.update(sheets[name])
                    rows = []
                    for row in element.iter():
                        if _local(row.tag) != "row":
                            continue
                        values = []
                        for cell in row:
                            if _local(cell.tag) != "c":
                                continue
                            value = next((node.text or "" for node in cell if _local(node.tag) == "v"), "")
                            if cell.attrib.get("t") == "s" and value:
                                index = int(value)
                                if not 0 <= index < len(shared):
                                    raise DocumentError("INVALID_SHARED_STRING")
                                value = shared[index]
                            elif cell.attrib.get("t") == "inlineStr":
                                value = _strings(cell)
                            formula = next((node.text or "" for node in cell if _local(node.tag) == "f"), "")
                            values.append(value + (" [formula: " + formula + "]" if formula else ""))
                        rows.append("\t".join(values))
                    text = "\n".join(rows)
                    location["hidden_rows"] = sum(node.attrib.get("hidden") == "1" for node in element.iter() if _local(node.tag) == "row")
                    location["hidden_columns"] = sum(node.attrib.get("hidden") == "1" for node in element.iter() if _local(node.tag) == "col")
                elif name.startswith("docProps/"):
                    kind = "metadata"
                    text = "\n".join(f"{node.attrib.get('name', _local(node.tag))}: {''.join(node.itertext()).strip()}"
                                     for node in element if "".join(node.itertext()).strip())
                elif (re.fullmatch(r"word/(?:document|header[0-9]+|footer[0-9]+|comments|footnotes|endnotes|glossary/document)\.xml", name)
                      or name.startswith(("ppt/slides/", "ppt/notesSlides/"))) and not name.endswith(".rels"):
                    kind = "docx-part" if name.startswith("word/") else "pptx-notes" if name.startswith("ppt/notesSlides/") else "pptx-slide"
                    location["visibility"] = "hidden" if element.attrib.get("show") == "0" else "visible"
                    paragraphs = [_strings(node, ("t", "delText", "instrText", "delInstrText"), paragraph=True) for node in element.iter() if _local(node.tag) == "p"]
                    text = "\n".join(paragraphs)
                    # Comments, tracked deletions and alternate object text are
                    # retained for review, regardless of displayed state.
                    extras = [f"{'object name' if _local(key) == 'name' else _local(key)}: {value}" for node in element.iter() for key, value in node.attrib.items()
                              if _local(key) in {"title", "descr", "author", "initials", "name", "instr", "tooltip"} and value]
                    text += ("\n" + "\n".join(extras)) if extras else ""
                    if not paragraphs:
                        text = "\n".join(node.text for node in element.iter() if node.text and node.text.strip()) + text
                else:
                    text = "\n".join(node.text.strip() for node in element.iter() if node.text and node.text.strip())
                    values = [f"{'object name' if _local(key) == 'name' else _local(key)}: {value}" for node in element.iter() for key, value in node.attrib.items()
                              if _local(key) in {"Target", "name", "title", "descr", "author", "UserName"}]
                    text += ("\n" + "\n".join(values)) if values else ""
                if any(node.attrib.get("TargetMode") == "External" for node in element.iter()):
                    result.gaps.add("EXTERNAL_RELATIONSHIPS_NOT_FETCHED")
                if name.startswith("customXml/"):
                    kind = "custom-xml"
                elif name.endswith(".rels"):
                    kind = "package-relationship"
                result.add(name, kind, text, **location)
                result.inventory.append({"id": name, "kind": kind, "status": result.surfaces[-1]["status"], **location})
            result.gaps.add("OFFICE_RENDERING_NOT_VERIFIED")
            return result
    except DocumentError:
        raise
    except Exception:
        raise DocumentError("INVALID_OFFICE_PACKAGE") from None


def _ocr_page(pdf, index: int) -> tuple[str, list[dict]]:
    executable = shutil.which("tesseract")
    if executable is None:
        raise DocumentError("OCR_UNAVAILABLE")
    page = pdf[index]
    try:
        width, height = page.get_width(), page.get_height()
        if not math.isfinite(width * height) or min(width, height) <= 0:
            raise DocumentError("INVALID_PAGE_SIZE")
        scale = min(2.0, math.sqrt(4_000_000 / (width * height)))
        bitmap = page.render(scale=scale, draw_annots=True)
        try:
            pixels = BytesIO()
            bitmap.to_pil().save(pixels, format="PNG")
        finally:
            bitmap.close()
    finally:
        page.close()
    try:
        completed = subprocess.run([executable, "stdin", "stdout", "-l", "eng", "--psm", "3", "tsv"],
                                   input=pixels.getvalue(), stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   timeout=15, check=True)
        if len(completed.stdout) > 1_000_000:
            raise DocumentError("OCR_OUTPUT_LIMIT")
        words, pieces, position, previous_line = [], [], 0, None
        for row in csv.DictReader(StringIO(completed.stdout.decode("utf-8")), delimiter="\t", quoting=csv.QUOTE_NONE):
            word = row.get("text", "").strip()
            if row.get("level") != "5" or not word:
                continue
            line = tuple(row[key] for key in ("block_num", "par_num", "line_num"))
            separator = "" if not pieces else " " if line == previous_line else "\n"
            pieces.append(separator)
            position += len(separator)
            words.append({"start": position, "end": position + len(word), "confidence": float(row["conf"]),
                          "box": [int(row[key]) for key in ("left", "top", "width", "height")], "scale": scale})
            pieces.append(word)
            position += len(word)
            previous_line = line
        return "".join(pieces), words
    except DocumentError:
        raise
    except Exception:
        raise DocumentError("OCR_FAILED") from None


def extract_pdf(raw: bytes, *, ocr: bool) -> Extraction:
    from pypdf import PdfReader

    result = Extraction()
    try:
        reader = PdfReader(BytesIO(raw), strict=True)
        if reader.is_encrypted:
            raise DocumentError("ENCRYPTED_PDF")
        if not 1 <= len(reader.pages) <= MAX_PAGES:
            raise DocumentError("PAGE_LIMIT")
        root = reader.trailer["/Root"]
        for key, value in (reader.metadata or {}).items():
            result.add("metadata:" + str(key), "metadata", f"{str(key).lstrip('/')}: {value}")
        if root.get("/Metadata"):
            xmp = _xml(root["/Metadata"].get_data())
            result.add("metadata:xmp", "metadata", "\n".join(node.text.strip() for node in xmp.iter() if node.text and node.text.strip()))
        for index, (name, item) in enumerate((reader.get_fields() or {}).items()):
            value = item.get("/V", "")
            if hasattr(value, "get_object"):
                value = value.get_object()
            if item.get("/FT") == "/Sig":
                text = "\n".join(f"{key}: {value.get(key, '')}" for key in ("/Name", "/Reason", "/Location", "/M")) if isinstance(value, dict) else ""
                result.add(f"signature:{index}", "signature-metadata", text, field=str(name))
                result.gaps.add("SIGNATURE_VALIDITY_AND_APPEARANCE_UNMEASURED")
            else:
                result.add(f"field:{index}", "pdf-form-field", f"{name}: {value}", field=str(name))
        for key in ("/OCProperties", "/Names", "/OpenAction", "/AA", "/AF", "/Collection"):
            if key in root:
                result.inventory.append({"id": "root:" + key, "kind": "pdf-structure", "status": "UNMEASURED"})
                result.gaps.add("PDF_LAYERS_ACTIONS_ATTACHMENTS_UNMEASURED")
        ocr_targets = []
        for index, page in enumerate(reader.pages):
            number = index + 1
            try:
                text = page.extract_text() or ""
                result.add(f"page:{number}:native", "pdf-native", text, page=number)
                native_status = "EXTRACTED" if text.strip() else "EMPTY"
            except DocumentError:
                raise
            except Exception:
                native_status, text = "UNMEASURED", ""
                result.gaps.add("PDF_TEXT_EXTRACTION_FAILED")
            # OCR all small documents and a bounded selection in long files.
            # Native extraction and OCR are separate witnesses, never conflated.
            # XObjects can contain scans, including images nested in forms.
            # Sparse native text (such as a header) is not evidence that all
            # visible content was extracted. Inline images may lack XObjects.
            sparse_text = len(text.strip()) < 200
            resources = page.get("/Resources", {})
            has_xobjects = bool(resources.get_object().get("/XObject")) if hasattr(resources, "get_object") else bool(resources.get("/XObject"))
            needs_ocr = (len(reader.pages) <= MAX_OCR_PAGES or sparse_text or has_xobjects
                         or "/OCProperties" in root or "/AcroForm" in root)
            item = {"id": f"page:{number}", "kind": "pdf-page", "page": number,
                    "status": native_status, "ocr": "UNMEASURED", "visual": "UNMEASURED"}
            result.inventory.append(item)
            if needs_ocr:
                ocr_targets.append((index, item, (bool(text.strip()), not sparse_text)))
            for annotation_index, reference in enumerate(page.get("/Annots", [])):
                annotation = reference.get_object()
                value = "\n".join(f"{key}: {annotation[key]}" for key in ("/T", "/Contents", "/Subj") if key in annotation)
                result.add(f"page:{number}:annotation:{annotation_index}", "pdf-annotation", value, page=number)
                result.gaps.add("PDF_ANNOTATION_APPEARANCES_UNMEASURED")
        if ocr and ocr_targets:
            try:
                import pypdfium2 as pdfium
                with pdfium.PdfDocument(raw) as pdf:
                    # Empty/failed native pages take precedence over duplicates.
                    ordered = sorted(ocr_targets, key=lambda target: (target[2], target[0]))
                    for index, item, _ in ordered[:MAX_OCR_PAGES]:
                        try:
                            text, words = _ocr_page(pdf, index)
                            result.add(f"page:{index + 1}:ocr", "pdf-ocr", text, page=index + 1, engine="tesseract-eng-psm3")
                            result.surfaces[-1]["words"] = words
                            item["ocr"] = "EXTRACTED" if text.strip() else "EMPTY"
                            if any(word["confidence"] < 60 for word in words):
                                result.gaps.add("OCR_LOW_CONFIDENCE")
                        except DocumentError as error:
                            if str(error) == "TEXT_LIMIT":
                                raise
                            item["ocr"] = "UNMEASURED"
                            result.gaps.add(str(error))
            except DocumentError:
                raise
            except Exception:
                result.gaps.add("OCR_UNAVAILABLE_OR_RENDER_FAILED")
        if any(item.get("ocr") == "UNMEASURED" for item in result.inventory):
            result.gaps.add("PDF_OCR_INCOMPLETE")
        result.gaps.update({"PDF_PIXELS_HANDWRITING_QR_UNMEASURED", "OCR_TEXT_AGREEMENT_UNVERIFIED"})
        return result
    except DocumentError:
        raise
    except Exception:
        raise DocumentError("INVALID_PDF") from None
