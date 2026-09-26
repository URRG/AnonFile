"""The batch preview is synthetic-only, ephemeral and never a release."""
import base64
from io import BytesIO

import pytest

from test_demo_inspect_api import demo_client
from test_access import auth, client


def file(identifier, name, content):
    raw = content.encode("utf-8") if isinstance(content, str) else content
    return {"id": identifier, "name": name, "content_base64": base64.b64encode(raw).decode("ascii")}


def payload():
    return {"synthetic_only": True, "files": [
        file("email", "thread.txt", "From: Riya <riya@example.test>\nTo: Sita <sita@example.test>\n\nHi Sita, Riya will call you."),
        file("record", "clients.json", '[{"full_name":"Riya","email":"riya@example.test"},{"full_name":"Sita"}]'),
    ]}


def test_batch_links_consistent_surrogates_and_explicit_relationship(demo_client):
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=payload())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["posture"] == "SYNTHETIC_DEMO_ONLY"
    assert body["release_authorized"] is False and body["export_available"] is False
    assert body["summary"]["files"] == 2
    riya = next(e for e in body["entities"] if e["source"] == "Riya")
    sita = next(e for e in body["entities"] if e["source"] == "Sita")
    assert len(riya["alias"]) == 4 and riya["alias"] != "Riya"
    assert riya["alias"] in body["documents"][0]["candidate_text"]
    assert riya["alias"] in body["documents"][1]["candidate_text"]
    assert body["relationships"] == [{"source_id": riya["id"], "target_id": sita["id"],
                                      "type": "EMAILED", "document_id": "email",
                                      "basis": "explicit From/To or Cc header"}]
    assert body["documents"][1]["structure_check"] == "pass"
    assert body["verification"]["status"] == "REVIEW_REQUIRED"
    assert any(check["status"] == "NOT_MEASURED" for check in body["verification"]["checks"])
    assert demo_client.app.state.store.datasets == {}
    assert demo_client.app.state.store.releases == {}


def test_manual_name_and_alias_override_rerender_without_persistence(demo_client):
    request = payload()
    request["files"][1] = file("record", "note.txt", "Riya and Sita met Tara.")
    request["manual_names"] = ["Tara"]
    first = demo_client.post("/demo/batch/inspect", headers=auth(), json=request).json()
    tara = next(e for e in first["entities"] if e["source"] == "Tara")
    request["alias_overrides"] = {tara["id"]: "Nina"}
    second = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert second.status_code == 200, second.text
    assert request["alias_overrides"][tara["id"]] in second.json()["documents"][1]["candidate_text"]


def test_manual_sensitive_phrase_corrects_same_value_across_files_without_release(demo_client):
    request = payload()
    request["files"][0] = file("email", "thread.txt", "Booking DEMO-4821 belongs to Riya.")
    request["files"][1] = file("record", "note.json", '{"note":"Review DEMO-4821 before sharing."}')
    request["manual_findings"] = [{"value": "DEMO-4821", "kind": "OTHER_SENSITIVE"}]
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    finding = next(entity for entity in body["entities"] if entity["source"] == "DEMO-4821")
    assert finding["kind"] == "OTHER_SENSITIVE" and finding["mentions"] == 2
    assert all(match["origin"] == "MANUAL" for document in body["documents"] for match in document["matches"]
               if match["entity_id"] == finding["id"])
    assert all("DEMO-4821" not in document["candidate_text"] for document in body["documents"])
    assert body["release_authorized"] is False and body["export_available"] is False


@pytest.mark.parametrize("findings", [
    [{"value": "missing", "kind": "OTHER_SENSITIVE"}],
    [{"value": "riya@example.test", "kind": "OTHER_SENSITIVE"}],
    [{"value": "DEMO-4821", "kind": "EMAIL"}],
    [{"value": "a\nb", "kind": "OTHER_SENSITIVE"}],
    [{"value": ["DEMO-4821"], "kind": "OTHER_SENSITIVE"}],
])
def test_manual_sensitive_phrase_rejects_missing_overlap_and_unsafe_values(demo_client, findings):
    request = payload()
    request["manual_findings"] = findings
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 422
    assert "riya@example.test" not in response.text


def test_one_alias_edit_does_not_change_another_persons_alias(demo_client):
    first = demo_client.post("/demo/batch/inspect", headers=auth(), json=payload()).json()
    riya = next(e for e in first["entities"] if e["source"] == "Riya")
    sita = next(e for e in first["entities"] if e["source"] == "Sita")
    request = payload()
    request["alias_overrides"] = {riya["id"]: "Nina"}
    second = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert second.status_code == 200, second.text
    assert next(e for e in second.json()["entities"] if e["source"] == "Sita")["alias"] == sita["alias"]


def test_reviewer_can_exclude_a_noncritical_false_positive_without_hiding_the_decision(demo_client):
    first = demo_client.post("/demo/batch/inspect", headers=auth(), json=payload()).json()
    riya = next(entity for entity in first["entities"] if entity["source"] == "Riya")
    request = payload()
    request["review_exclusions"] = {riya["id"]: "FALSE_POSITIVE_CONFIRMED"}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    assert next(entity for entity in body["entities"] if entity["id"] == riya["id"])["excluded"] is True
    assert body["summary"]["suppressed_mentions"] == riya["mentions"]
    assert body["summary"]["detected_mentions"] == body["summary"]["transformed_mentions"] + riya["mentions"]
    assert all(not match["applied"] for doc in body["documents"] for match in doc["matches"] if match["entity_id"] == riya["id"])
    assert "Riya" in body["documents"][0]["candidate_text"]
    assert next(check for check in body["verification"]["checks"] if check["name"] == "Reviewer exclusions")["status"] == "REVIEW"
    assert next(check for check in body["verification"]["checks"] if check["name"] == "Residual known-rule scan")["status"] == "REVIEW"
    assert body["release_authorized"] is False and body["export_available"] is False


def test_reviewer_exclusion_rejects_unknown_critical_or_conflicting_entities(demo_client):
    first = demo_client.post("/demo/batch/inspect", headers=auth(), json=payload()).json()
    riya = next(entity for entity in first["entities"] if entity["source"] == "Riya")
    for excluded, override in [({"E999": "FALSE_POSITIVE_CONFIRMED"}, {}),
                               ({riya["id"]: "TRUST_ME"}, {}),
                               ({riya["id"]: "FALSE_POSITIVE_CONFIRMED"}, {riya["id"]: "Nina"})]:
        request = payload()
        request["review_exclusions"] = excluded
        request["alias_overrides"] = override
        assert demo_client.post("/demo/batch/inspect", headers=auth(), json=request).status_code == 422
    request = payload()
    request["files"][1] = file("record", "record.csv", "passport_number\nDEMO123456\n")
    first = demo_client.post("/demo/batch/inspect", headers=auth(), json=request).json()
    passport = next(entity for entity in first["entities"] if entity["kind"] == "GOVERNMENT_ID")
    request["review_exclusions"] = {passport["id"]: "FALSE_POSITIVE_CONFIRMED"}
    assert demo_client.post("/demo/batch/inspect", headers=auth(), json=request).status_code == 422


def test_two_mail_messages_do_not_create_cartesian_relationships(demo_client):
    request = payload()
    request["files"][0] = file("email", "thread.txt", "From: Riya <riya@example.test>\nTo: Sita <sita@example.test>\n\nReply\nFrom: Tara <tara@example.test>\nTo: Riya <riya@example.test>")
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    entities = {entity["source"]: entity["id"] for entity in response.json()["entities"]}
    edges = {(edge["source_id"], edge["target_id"]) for edge in response.json()["relationships"]}
    assert edges == {(entities["Riya"], entities["Sita"]), (entities["Tara"], entities["Riya"])}


def test_structured_account_owner_link_requires_both_names_in_one_record(demo_client):
    request = payload()
    request["files"][1] = file("record", "clients.json", '[{"account_owner":"Riya","client_name":"Sita"},{"account_owner":"Tara"},{"client_name":"Maya"}]')
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    ids = {entity["source"]: entity["id"] for entity in body["entities"]}
    assert {"Riya", "Sita", "Tara", "Maya"}.issubset(ids)
    role_edges = [edge for edge in body["relationships"] if edge["type"] == "ACCOUNT_OWNER_OF"]
    assert role_edges == [{"source_id": ids["Riya"], "target_id": ids["Sita"],
                           "type": "ACCOUNT_OWNER_OF", "document_id": "record",
                           "basis": "same JSON record account_owner/client_name"}]
    assert body["summary"]["explicit_relationships"] == 2  # plus the separate mail-header edge
    assert "Riya" not in body["documents"][1]["candidate_text"]


def test_csv_role_links_do_not_cross_rows(demo_client):
    request = payload()
    request["files"][1] = file("record", "clients.csv", "account_owner,client_name\nRiya,Sita\nTara,Maya\n")
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    ids = {entity["source"]: entity["id"] for entity in body["entities"]}
    role_edges = {(edge["source_id"], edge["target_id"], edge["basis"])
                  for edge in body["relationships"] if edge["type"] == "ACCOUNT_OWNER_OF"}
    assert role_edges == {(ids["Riya"], ids["Sita"], "same CSV record account_owner/client_name"),
                          (ids["Tara"], ids["Maya"], "same CSV record account_owner/client_name")}


@pytest.mark.parametrize(("filename", "content", "expected"), [
    ("record.json", '[{"full_name":"Riya","passport_number":"DEMO123456","date_of_birth":"1990-01-01"}]',
     {"PERSON_NAME", "GOVERNMENT_ID", "DATE_OF_BIRTH"}),
    ("record.csv", 'full_name,passport_number,date_of_birth\nRiya,DEMO123456,1990-01-01\n',
     {"PERSON_NAME", "GOVERNMENT_ID", "DATE_OF_BIRTH"}),
])
def test_sensitive_structured_fields_are_transformed_and_reparse(demo_client, filename, content, expected):
    request = payload()
    request["files"][1] = file("record", filename, content)
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    document = response.json()["documents"][1]
    assert expected.issubset({match["kind"] for match in document["matches"]})
    assert "DEMO123456" not in document["candidate_text"]
    assert "1990-01-01" not in document["candidate_text"]
    assert document["structure_check"] == "pass"


@pytest.mark.parametrize("change", [
    lambda item: item.pop("synthetic_only"),
    lambda item: item.update(synthetic_only=False),
    lambda item: item.update(files=item["files"][:1]),
    lambda item: item.update(files=item["files"] + item["files"]),
    lambda item: item["files"][0].update(name="screenshot.png"),
    lambda item: item.update(alias_overrides={"E999": "Gita"}),
    lambda item: item.update(manual_names=["Nobody"]),
])
def test_batch_rejects_invalid_or_unattested_requests(demo_client, change):
    request = payload()
    change(request)
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 422
    assert "riya@example.test" not in response.text


def test_batch_pdf_is_rasterized_into_new_image_only_candidate_preview(demo_client):
    reportlab = pytest.importorskip("reportlab.pdfgen.canvas")
    stream = BytesIO()
    canvas = reportlab.Canvas(stream)
    canvas.drawString(72, 720, "From: Riya <riya@example.test>")
    canvas.drawString(72, 700, "To: Sita <sita@example.test>")
    canvas.save()
    request = payload()
    request["files"][0] = file("email", "thread.pdf", stream.getvalue())
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    document = response.json()["documents"][0]
    assert document["kind"] == "pdf"
    assert document["preview_fidelity"] == "raster_ocr_review"
    assert "Riya" not in document["candidate_text"]
    media = document["media_preview"]
    assert len(media["pages"]) == 1
    assert media["pages"][0]["source_png_base64"] != media["pages"][0]["candidate_png_base64"]
    assert base64.b64decode(media["pages"][0]["candidate_png_base64"]).startswith(b"\x89PNG\r\n\x1a\n")
    assert media["pdf_raster_evidence"]["pages"] == 1
    assert media["pdf_raster_evidence"]["source_objects_copied"] is False
    assert media["self_ocr_residual_sources"] == 0
    assert response.json()["export_available"] is False


def test_image_ocr_preview_reencodes_pixels_without_source_metadata(demo_client):
    from PIL import Image, ImageDraw, ImageFont, PngImagePlugin
    from pathlib import Path
    import reportlab

    image = Image.new("RGB", (900, 230), "white")
    draw = ImageDraw.Draw(image)
    font = ImageFont.truetype(str(Path(reportlab.__file__).parent / "fonts" / "Vera.ttf"), 30)
    draw.text((40, 35), "From: Riya <riya@example.test>", font=font, fill="black")
    draw.text((40, 90), "To: Sita <sita@example.test>", font=font, fill="black")
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Secret", "DO_NOT_COPY_SOURCE_METADATA")
    stream = BytesIO()
    image.save(stream, format="PNG", pnginfo=metadata)
    request = payload()
    request["files"][0] = file("email", "thread.png", stream.getvalue())
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    document = response.json()["documents"][0]
    assert document["kind"] == "image" and document["preview_fidelity"] == "raster_ocr_review"
    assert "Riya" not in document["candidate_text"]
    media = document["media_preview"]
    candidate = base64.b64decode(media["pages"][0]["candidate_png_base64"])
    assert b"DO_NOT_COPY_SOURCE_METADATA" not in candidate
    candidate_image = Image.open(BytesIO(candidate))
    assert candidate_image.size == (900, 230)
    from app.media_preview import _ocr_lines
    candidate_text = " ".join(line["text"] for line in _ocr_lines(candidate_image))
    assert "Riya" not in candidate_text and "Sita" not in candidate_text
    assert "Gita" in candidate_text
    assert media["pdf_raster_evidence"] is None
    assert media["self_ocr_residual_sources"] == 0
    assert response.json()["release_authorized"] is False


def test_media_rejects_oversized_pixels_before_ocr(demo_client):
    from PIL import Image

    stream = BytesIO()
    Image.new("RGB", (2000, 2000), "white").save(stream, format="PNG")
    request = payload()
    request["files"][0] = file("email", "large.png", stream.getvalue())
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 422
    assert "riya@example.test" not in response.text


def test_batch_rejects_excess_total_media_pixels_before_candidate(monkeypatch):
    from PIL import Image
    from app import demo_batch
    from app.contracts import PayloadError

    def fake_read(item):
        return {"id": item["id"], "name": item["name"], "kind": "image", "text": "Riya",
                "size_bytes": 100, "preview_fidelity": "raster_ocr_review",
                "_media_pages": [{"image": Image.new("RGB", (1600, 1000)), "lines": []}]}

    monkeypatch.setattr(demo_batch, "_read_file", fake_read)
    with pytest.raises(PayloadError, match="three-million-pixel"):
        demo_batch.analyze_batch({"synthetic_only": True, "files": [
            {"id": "one", "name": "one.png"}, {"id": "two", "name": "two.png"},
        ]})


def test_batch_route_is_not_registered_without_demo_opt_in(client):
    assert client.post("/demo/batch/inspect", headers=auth(), json=payload()).status_code == 404


def test_reference_labels_measure_exact_reviewed_spans_without_approval(demo_client):
    request = payload()
    email_text = "From: Riya <riya@example.test>\nTo: Sita <sita@example.test>\n\nHi Sita, Riya will call you."
    record_text = '[{"full_name":"Riya","email":"riya@example.test"},{"full_name":"Sita"}]'
    def label(text, value, kind):
        start = text.index(value)
        return {"start": start, "end": start + len(value), "entity_type": kind}
    request["reference_annotations"] = {"basis": "REVIEWER_ATTESTED_EXHAUSTIVE", "documents": [
        {"id": "email", "annotations": [label(email_text, "Riya", "PERSON_NAME"),
                                        label(email_text, "riya@example.test", "EMAIL"),
                                        label(email_text, "Sita", "PERSON_NAME"),
                                        label(email_text, "sita@example.test", "EMAIL"),
                                        label(email_text, "Riya will", "OTHER_SENSITIVE")]},
        {"id": "record", "annotations": [label(record_text, "Riya", "PERSON_NAME"),
                                         label(record_text, "riya@example.test", "EMAIL"),
                                         label(record_text, "Sita", "PERSON_NAME")]},
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    score = body["verification"]["annotation_score"]
    assert score["basis"] == "REVIEWER_ATTESTED_EXHAUSTIVE"
    assert score["status"] == "OBSERVATIONAL_ONLY"
    assert score["labelled_documents"] == 2 and score["gold_annotations"] == 8
    assert score["exact"]["false_negatives"] >= 1
    assert score["per_type"]["OTHER_SENSITIVE"]["false_negatives"] == 1
    assert [item["id"] for item in score["per_document"]] == ["email", "record"]
    assert sum(item["exact"]["false_negatives"] for item in score["per_document"]) == score["exact"]["false_negatives"]
    assert {"start": email_text.index("Riya will"), "end": email_text.index("Riya will") + len("Riya will"),
            "entity_type": "OTHER_SENSITIVE"} in score["per_document"][0]["missed"]
    assert body["release_authorized"] is False and body["export_available"] is False
    assert next(check for check in body["verification"]["checks"] if check["name"] == "Reference-label agreement")["status"] == "REVIEW"


@pytest.mark.parametrize("change", [
    lambda manifest: manifest.update(basis="INDEPENDENTLY_VERIFIED"),
    lambda manifest: manifest["documents"].pop(),
    lambda manifest: manifest["documents"][1].update(id="email"),
    lambda manifest: manifest["documents"][0]["annotations"].append({"start": 0, "end": 1000, "entity_type": "EMAIL"}),
    lambda manifest: manifest["documents"][0]["annotations"].append({"start": 0, "end": 4, "entity_type": "UNKNOWN"}),
])
def test_reference_labels_fail_closed_on_invalid_manifest(demo_client, change):
    request = payload()
    request["reference_annotations"] = {"basis": "REVIEWER_ATTESTED_EXHAUSTIVE", "documents": [
        {"id": "email", "annotations": []}, {"id": "record", "annotations": []},
    ]}
    change(request["reference_annotations"])
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 422
    assert "riya@example.test" not in response.text


def test_curated_three_file_sample_has_scored_misses_and_cannot_be_forged(demo_client):
    from app.demo_batch import SAMPLE_REFERENCE_VALUES
    texts = {
        "01-email-thread.txt": "From: Riya <riya@example.test>\nTo: Sita <sita@example.test>\nSubject: Flight change\n\nHi Sita, Riya can review the itinerary. Please call +1 415 555 0134.",
        "02-passenger-list.csv": "full_name,email,passport_number,date_of_birth,booking_reference\nRiya,riya@example.test,DEMO123456,1990-01-01,DEMO-4821\nSita,sita@example.test,DEMO654321,1992-02-02,DEMO-4822\n",
        "03-support-record.json": '{"client_name":"Sita","account_owner":"Riya","note":"Riya emailed Sita about DEMO-4822."}',
    }
    request = {"synthetic_only": True, "files": [], "reference_annotations": {
        "basis": "CURATED_SYNTHETIC_SAMPLE", "documents": []}}
    for index, (name, text) in enumerate(texts.items()):
        identifier = f"sample_{index}"
        request["files"].append(file(identifier, name, text))
        annotations = []
        for value, kind in SAMPLE_REFERENCE_VALUES[name]:
            start = 0
            while (start := text.find(value, start)) >= 0:
                annotations.append({"start": start, "end": start + len(value), "entity_type": kind})
                start += len(value)
        request["reference_annotations"]["documents"].append({"id": identifier, "annotations": annotations})
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    score = response.json()["verification"]["annotation_score"]
    assert score["basis"] == "CURATED_SYNTHETIC_SAMPLE"
    assert score["exact"]["false_negatives"] >= 3  # booking references are not in the bounded detector
    assert score["automatic_exact"] == score["exact"]
    assert sum(item["exact"]["true_positives"] for item in score["per_document"]) == score["exact"]["true_positives"]
    assert any(span["entity_type"] == "OTHER_SENSITIVE" for item in score["per_document"] for span in item["missed"])
    request["manual_findings"] = [{"value": "DEMO-4821", "kind": "OTHER_SENSITIVE"},
                                  {"value": "DEMO-4822", "kind": "OTHER_SENSITIVE"}]
    corrected = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert corrected.status_code == 200, corrected.text
    corrected_score = corrected.json()["verification"]["annotation_score"]
    assert corrected_score["automatic_exact"] == score["automatic_exact"]
    assert corrected_score["exact"]["false_negatives"] == 0
    request.pop("manual_findings")
    removed = request["reference_annotations"]["documents"][0]["annotations"].pop()
    assert demo_client.post("/demo/batch/inspect", headers=auth(), json=request).status_code == 422
    request["reference_annotations"]["documents"][0]["annotations"].append(removed)
    request["files"][0] = file("sample_0", "01-email-thread.txt", texts["01-email-thread.txt"] + " extra")
    assert demo_client.post("/demo/batch/inspect", headers=auth(), json=request).status_code == 422
