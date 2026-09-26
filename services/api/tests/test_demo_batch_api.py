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


def test_two_mail_messages_do_not_create_cartesian_relationships(demo_client):
    request = payload()
    request["files"][0] = file("email", "thread.txt", "From: Riya <riya@example.test>\nTo: Sita <sita@example.test>\n\nReply\nFrom: Tara <tara@example.test>\nTo: Riya <riya@example.test>")
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    entities = {entity["source"]: entity["id"] for entity in response.json()["entities"]}
    edges = {(edge["source_id"], edge["target_id"]) for edge in response.json()["relationships"]}
    assert edges == {(entities["Riya"], entities["Sita"]), (entities["Tara"], entities["Riya"])}


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
