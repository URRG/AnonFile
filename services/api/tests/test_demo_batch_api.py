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


def test_batch_pdf_is_text_only_not_rewritten(demo_client):
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
    assert document["preview_fidelity"] == "extracted_text_only"
    assert "Riya" not in document["candidate_text"]
    assert response.json()["export_available"] is False


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
    removed = request["reference_annotations"]["documents"][0]["annotations"].pop()
    assert demo_client.post("/demo/batch/inspect", headers=auth(), json=request).status_code == 422
    request["reference_annotations"]["documents"][0]["annotations"].append(removed)
    request["files"][0] = file("sample_0", "01-email-thread.txt", texts["01-email-thread.txt"] + " extra")
    assert demo_client.post("/demo/batch/inspect", headers=auth(), json=request).status_code == 422
