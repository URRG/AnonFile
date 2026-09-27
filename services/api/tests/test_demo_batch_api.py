"""The batch preview is synthetic-only, ephemeral and never a release."""
import base64
from io import BytesIO
import json
from pathlib import Path

import pytest

from app.contracts import PayloadError
from app.demo_batch import _choose_alias, analyze_batch
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
    riya_email = next(e for e in body["entities"] if e["source"] == "riya@example.test")
    assert riya_email["alias"] == f"{riya['alias'].lower()}@example.test"
    assert riya_email["alias"] in body["documents"][0]["candidate_text"]
    assert riya_email["alias"] in body["documents"][1]["candidate_text"]
    assert "[EMAIL_" not in body["documents"][0]["candidate_text"]
    assert body["verification"]["source_value_residuals"] == 0
    assert body["relationships"] == [{"source_id": riya["id"], "target_id": sita["id"],
                                      "type": "EMAILED", "document_id": "email",
                                      "basis": "explicit From/To or Cc header"}]
    assert body["documents"][1]["structure_check"] == "pass"
    assert body["verification"]["status"] == "REVIEW_REQUIRED"
    assert any(check["status"] == "NOT_MEASURED" for check in body["verification"]["checks"])
    assert demo_client.app.state.store.datasets == {}
    assert demo_client.app.state.store.releases == {}


def test_entity_graph_uses_typed_explicit_evidence_and_never_source_labels(demo_client):
    request = {"synthetic_only": True, "files": [
        file("mail", "thread.txt", "From: Maya Patel <maya.patel@private.example>\n"
             "To: Isha Rao <isha.rao@client.example>\n\n"
             "Name: Lina Chen\nTitle: Assistant to Maya Patel\nCompany: Harborline Systems\n\n"
             "Isha Rao is a client of Harborline Systems.\n"
             "Lina Chen is assistant for Harborline Systems.\n"
             "Arjun Mehta works on Duplicate Dispatch Guard.\n"
             "Duplicate Dispatch Guard is assigned to Arjun Mehta."),
        file("roles", "roles.json", '[{"person_name":"Maya Patel","works_at":"Harborline Systems"},'
             '{"assistant":"Lina Chen","assistant_for":"Harborline Systems"}]'),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    graph = response.json()["entity_graph"]
    assert {node["kind"] for node in graph["nodes"]} == {"person", "organization", "project"}
    assert {edge["type"] for edge in graph["edges"]} == {
        "sent_to", "assistant_to", "assistant_for", "works_at", "client_of", "works_on", "assigned_to"}
    assert all(node["label"].startswith(("Organization ", "Project ")) or node["kind"] == "person"
               for node in graph["nodes"])
    assert all(set(edge) == {"id", "type", "source_id", "target_id", "evidence"} for edge in graph["edges"])
    assert all(set(item) == {"document_id", "rule", "field"}
               for edge in graph["edges"] for item in edge["evidence"])
    public_graph = json.dumps(graph)
    for source in ("Maya Patel", "Isha Rao", "Lina Chen", "Arjun Mehta", "Harborline Systems",
                   "Duplicate Dispatch Guard", "private.example", "client.example"):
        assert source not in public_graph


def test_entity_graph_abstains_on_proximity_headers_and_cross_record_values(demo_client):
    request = {"synthetic_only": True, "files": [
        file("mail", "thread.txt", "From: Maya Patel <maya@harborline.example>\n"
             "To: Isha Rao <isha@client.example>\n\n"
             "Maya Patel works with Harborline Systems. Isha Rao is a client for Harborline Systems."),
        file("records", "records.json", '[{"person_name":"Maya Patel"},'
             '{"works_at":"Harborline Systems"},{"client_name":"Isha Rao"},'
             '{"client_for":"Harborline Systems"},{"project_name":"Duplicate Dispatch Guard"},'
             '{"assigned_to":"Maya Patel"}]'),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    graph = response.json()["entity_graph"]
    assert [edge["type"] for edge in graph["edges"]] == ["sent_to"]
    assert all(node["kind"] == "person" for node in graph["nodes"])


def test_entity_graph_groups_cross_file_evidence_for_the_same_claim(demo_client):
    request = {"synthetic_only": True, "files": [
        file("first", "first.json", '[{"person_name":"Maya Patel","works_at":"Harborline Systems"}]'),
        file("second", "second.csv", "person_name,works_at\nMaya Patel,Harborline Systems\n"),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    graph = response.json()["entity_graph"]
    assert len(graph["edges"]) == 1
    assert graph["edges"][0]["type"] == "works_at"
    assert {item["document_id"] for item in graph["edges"][0]["evidence"]} == {"first", "second"}


def test_entity_graph_does_not_turn_a_generic_assistant_title_into_assistant_for(demo_client):
    request = {"synthetic_only": True, "files": [
        file("signature", "signature.txt", "Name: Lina Chen\nTitle: Assistant\nCompany: Harborline Systems"),
        file("record", "record.json", '[{"full_name":"Lina Chen"}]'),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    assert {edge["type"] for edge in response.json()["entity_graph"]["edges"]} == {"works_at"}


def test_entity_graph_marks_an_excluded_person_as_source_retained(demo_client):
    request = payload()
    first = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert first.status_code == 200, first.text
    riya_id = next(entity["id"] for entity in first.json()["entities"] if entity["source"] == "Riya")
    request["review_exclusions"] = {riya_id: "FALSE_POSITIVE_CONFIRMED"}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    riya_node = next(node for node in response.json()["entity_graph"]["nodes"] if node["id"] == riya_id)
    assert riya_node["label"] == "Source retained"


def test_full_person_names_get_realistic_same_width_aliases_across_files(demo_client):
    request = {"synthetic_only": True, "files": [
        file("mail", "mail.txt", "From: Maya Patel <maya.patel@example.test>\n"
             "To: Isha Rao <isha.rao@example.test>\n\nMaya Patel asked Isha Rao to review the case."),
        file("calendar", "calendar.txt", "Organizer: Maya Patel <maya.patel@example.test>\n"
             "Invitees: Isha Rao <isha.rao@example.test>\nTitle: 1:1 with Maya Patel"),
        file("record", "people.csv", "full_name,email\nMaya Patel,maya.patel@example.test\n"
             "Isha Rao,isha.rao@example.test\n"),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    by_source = {entity["source"]: entity for entity in body["entities"]}
    maya_alias = by_source["Maya Patel"]["alias"]
    isha_alias = by_source["Isha Rao"]["alias"]
    assert [len(part) for part in maya_alias.split()] == [4, 5]
    assert [len(part) for part in isha_alias.split()] == [4, 3]
    assert isha_alias != "Isha Rao" and isha_alias != maya_alias
    assert all(part.isalpha() for alias in (maya_alias, isha_alias) for part in alias.split())
    assert by_source["maya.patel@example.test"]["alias"] == maya_alias.casefold().replace(" ", "") + "@example.test"
    assert all(maya_alias in document["candidate_text"] for document in body["documents"])
    assert all("Maya Patel" not in document["candidate_text"] for document in body["documents"])
    assert body["verification"]["source_value_residuals"] == 0


def test_name_alias_avoids_existing_source_names_even_with_matching_components(demo_client):
    request = {"synthetic_only": True, "files": [
        file("mail", "mail.txt", "From: Maya Patel <maya.patel@example.test>\n"
             "To: John <john@example.test>\n"),
        file("record", "people.csv", "full_name,email\nMaya Patel,maya.patel@example.test\n"
             "John,john@example.test\n"),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    aliases = {entity["source"]: entity["alias"] for entity in response.json()["entities"]}
    assert not aliases["Maya Patel"].startswith("John ")
    assert aliases["Maya Patel"] != "Maya Patel"
    assert response.json()["verification"]["source_value_residuals"] == 0


def test_unsupported_name_shape_requires_reviewer_alias_instead_of_axxxx(demo_client):
    request = {"synthetic_only": True, "files": [
        file("record", "people.csv", "full_name\nAlexandrianus\n"),
        file("note", "note.txt", "Alexandrianus joined the review."),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 422
    assert response.json() == {"detail": "Unsupported payload"}
    assert "Alexandrianus" not in response.text
    with pytest.raises(PayloadError, match="same-length alias"):
        _choose_alias("Alexandrianus", set(), set())


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


def test_slack_roster_names_and_emails_are_linked_across_batch(demo_client):
    request = {"synthetic_only": True, "files": [
        file("thread", "slack.txt", "PARTICIPANTS\nArjun Mehta | arjun.mehta@harborline.test | ID HS-EMP-1042\n"
             "Neha Kapoor | neha.kapoor@harborline.test | ID HS-EMP-1057\n"
             "09:03\nArjun Mehta\nThe queue is stable. Neha Kapoor confirmed."),
        file("mail", "mail.txt", "From: Isha Rao <isha.rao@bluebird-air.test>\n"
             "To: Arjun Mehta <arjun.mehta@harborline.test>\n\nPlease confirm, Neha Kapoor."),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    entities = {entity["source"]: entity for entity in body["entities"]}
    for name, address in (("Arjun Mehta", "arjun.mehta@harborline.test"),
                          ("Neha Kapoor", "neha.kapoor@harborline.test")):
        alias = entities[name]["alias"]
        assert "x" * 3 not in alias.casefold()
        assert entities[address]["alias"].split("@", 1)[0] == alias.casefold().replace(" ", "")
        assert alias in body["documents"][0]["candidate_text"]
        assert name not in body["documents"][0]["candidate_text"]
    assert body["verification"]["source_value_residuals"] == 0


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
    assert next(e for e in second.json()["entities"] if e["source"] == "riya@example.test")["alias"] == "nina@example.test"
    assert next(e for e in second.json()["entities"] if e["source"] == "sita@example.test")["alias"] == \
        next(e for e in first["entities"] if e["source"] == "sita@example.test")["alias"]


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
    assert body["verification"]["source_value_residuals"] > 0
    assert next(check for check in body["verification"]["checks"] if check["name"] == "Source-value persistence")["status"] == "REVIEW"
    assert next(check for check in body["verification"]["checks"] if check["name"] == "Reviewer exclusions")["status"] == "REVIEW"
    assert next(check for check in body["verification"]["checks"] if check["name"] == "Residual known-rule scan")["status"] == "REVIEW"
    assert body["release_authorized"] is False and body["export_available"] is False


def test_email_surrogates_preserve_batch_domain_equivalence_without_live_domains(demo_client):
    request = {"synthetic_only": True, "files": [
        file("mail", "thread.txt", "From: Riya <riya@airline.com>\nTo: Sita <sita@client.org>\n\nHi Sita."),
        file("rows", "contacts.csv", "full_name,email\nRiya,riya@airline.com\nSita,sita@client.org\n"),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    entities = {entity["source"]: entity for entity in body["entities"]}
    riya_alias = entities["riya@airline.com"]["alias"]
    sita_alias = entities["sita@client.org"]["alias"]
    assert riya_alias == f"{entities['Riya']['alias'].lower()}@org1.test"
    assert sita_alias == f"{entities['Sita']['alias'].lower()}@org2.test"
    assert riya_alias in body["documents"][0]["candidate_text"] and riya_alias in body["documents"][1]["candidate_text"]
    assert "airline.com" not in body["documents"][0]["candidate_text"]
    assert "client.org" not in body["documents"][1]["candidate_text"]
    assert body["verification"]["source_value_residuals"] == 0


def test_email_without_explicit_owner_uses_generic_surrogate(demo_client):
    request = {"synthetic_only": True, "files": [
        file("mail", "thread.txt", "Contact help@airline.com about the case."),
        file("rows", "contacts.json", '{"emailAddress":"help@airline.com","note":"Call the desk"}'),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    alias = next(entity["alias"] for entity in body["entities"] if entity["source"] == "help@airline.com")
    assert alias == "contact1@org1.test"
    assert all(alias in doc["candidate_text"] for doc in body["documents"])


def test_format_aware_demo_surrogates_are_non_issuable_and_batch_consistent(demo_client):
    request = {"synthetic_only": True, "files": [
        file("mail", "thread.txt", "Riya: SSN: 123-45-6789; PAN ABCPD1234F; call +1 415 555 0134."),
        file("rows", "people.csv", "full_name,pan,ssn,phone,drivers_license\n"
             "Riya,ABCPD1234F,123-45-6789,+1 415 555 0134,123456789\n"),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    by_source = {entity["source"]: entity for entity in body["entities"]}
    assert by_source["ABCPD1234F"]["kind"] == "PAN"
    assert by_source["ABCPD1234F"]["strategy"] == "PAN_INVALID_TEST"
    assert by_source["ABCPD1234F"]["alias"] == "TSTZA0001A"
    assert by_source["123-45-6789"]["strategy"] == "US_SSN_INVALID"
    assert by_source["123-45-6789"]["alias"] == "000-01-0001"
    assert by_source["+1 415 555 0134"]["strategy"] == "NANP_FICTIONAL"
    assert by_source["+1 415 555 0134"]["alias"] == "+1 202 555 0100"
    assert by_source["123456789"]["strategy"] == "OPAQUE_REDACTION"
    assert all("ABCPD1234F" not in doc["candidate_text"] for doc in body["documents"])
    assert all("123-45-6789" not in doc["candidate_text"] for doc in body["documents"])
    assert body["verification"]["source_value_residuals"] == 0
    assert body["release_authorized"] is False


def test_unlabelled_nine_digit_value_and_other_region_phone_stay_opaque(demo_client):
    request = {"synthetic_only": True, "files": [
        file("one", "contact.txt", "Call +91 98765 43210"),
        file("two", "record.json", '{"drivers_license":"123456789","phone":"+91 98765 43210"}'),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    by_source = {entity["source"]: entity for entity in response.json()["entities"]}
    assert by_source["123456789"]["strategy"] == "OPAQUE_REDACTION"
    assert by_source["+91 98765 43210"]["strategy"] == "OPAQUE_REDACTION"


def test_conflicting_email_owner_evidence_is_rejected(demo_client):
    request = {"synthetic_only": True, "files": [
        file("mail", "thread.txt", "From: Riya <shared@example.test>\nTo: Sita <sita@example.test>"),
        file("rows", "contacts.csv", "full_name,email\nGita,shared@example.test\n"),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 422
    assert "shared@example.test" not in response.text


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
    assert "gita@example.test" in document["candidate_text"]
    assert "[EMAIL_" not in document["candidate_text"]
    media = document["media_preview"]
    assert len(media["pages"]) == 1
    assert media["pages"][0]["source_png_base64"] != media["pages"][0]["candidate_png_base64"]
    assert base64.b64decode(media["pages"][0]["candidate_png_base64"]).startswith(b"\x89PNG\r\n\x1a\n")
    assert media["pdf_raster_evidence"]["pages"] == 1
    assert media["pdf_raster_evidence"]["source_objects_copied"] is False
    assert media["self_ocr_residual_sources"] == 0
    assert response.json()["export_available"] is False


def test_pdf_text_layer_sensitive_value_missing_from_ocr_rejects_candidate(demo_client, monkeypatch):
    reportlab = pytest.importorskip("reportlab.pdfgen.canvas")
    from app import media_preview
    stream = BytesIO()
    canvas = reportlab.Canvas(stream)
    canvas.drawString(72, 720, "Contact riya@example.test")
    canvas.save()
    monkeypatch.setattr(media_preview, "_ocr_lines", lambda _, **kwargs: [
        {"text": "Contact", "box": (20, 20, 100, 50), "confidence": 1.0}])
    request = payload()
    request["files"][0] = file("email", "thread.pdf", stream.getvalue())
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 422
    assert "riya@example.test" not in response.text


def test_curated_mixed_media_demo_fixture_is_reviewable_as_one_batch(demo_client):
    root = Path(__file__).resolve().parents[3]
    media = root / "apps" / "web" / "public" / "demo-media"
    request = {"synthetic_only": True, "files": [
        file("mail", "01-email-thread.pdf", (media / "01-email-thread.pdf").read_bytes()),
        file("note", "02-service-note.png", (media / "02-service-note.png").read_bytes()),
        file("record", "03-support-record.json",
             '{"client_name":"Sita","account_owner":"Riya","note":"Riya emailed Sita about DEMO-4822."}'),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["summary"]["files"] == 3
    assert {doc["kind"] for doc in body["documents"]} == {"pdf", "image", "json"}
    assert all(doc["media_preview"]["pages"] for doc in body["documents"][:2])
    assert body["summary"]["explicit_relationships"] == 2
    assert "Riya" not in body["documents"][0]["candidate_text"]
    assert "gita@example.test" in body["documents"][0]["candidate_text"]
    assert "Sita" not in body["documents"][1]["candidate_text"]
    assert body["verification"]["status"] == "REVIEW_REQUIRED"
    assert body["export_available"] is False


def test_rich_three_file_fixture_redacts_contextual_values_without_releasing(demo_client):
    root = Path(__file__).resolve().parents[3] / "apps" / "web" / "public" / "demo-media"
    request = {"synthetic_only": True, "files": [
        file("mail", "11-p0-client-email-thread.pdf", (root / "11-p0-client-email-thread.pdf").read_bytes()),
        file("slack", "12-developer-slack-thread.pdf", (root / "12-developer-slack-thread.pdf").read_bytes()),
        file("calendar", "13-calendar-events.txt", (root / "13-calendar-events.txt").read_bytes()),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    if response.status_code != 200:
        # The public route correctly suppresses rejection details. Keep a
        # fixture-only diagnostic so platform-specific OCR mismatches can be
        # fixed without weakening that fail-closed response contract.
        analyze_batch(request)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verification"]["status"] == "REVIEW_REQUIRED"
    assert body["release_authorized"] is False and body["export_available"] is False
    assert {"client_of", "assistant_to", "assistant_for", "works_at", "works_on", "assigned_to"}.issubset(
        {edge["type"] for edge in body["entity_graph"]["edges"]})
    assert {"EMPLOYEE_ID", "INTERNAL_URL", "ADDRESS"}.issubset({entity["kind"] for entity in body["entities"]})
    assert {"CONTEXTUAL_REVIEW_REF", "INTERNAL_URL_RESERVED_DOMAIN"}.issubset(
        {entity["strategy"] for entity in body["entities"]})
    candidate = "\n".join(document["candidate_text"] for document in body["documents"])
    assert "HS-EMP-1042" not in candidate
    assert "25 Sample Street" not in candidate
    assert "github.example.test" not in candidate
    assert "confluence.example.test" not in candidate
    assert "review-" in candidate and ".invalid/resource" in candidate
    assert body["verification"]["source_value_residuals"] == 0


def test_contextual_structured_fields_link_across_json_and_csv(demo_client):
    address = "25 Sample Street, Example City, CA 90000"
    link = "https://intranet.example.test/private/HS-EMP-1042"
    request = {"synthetic_only": True, "files": [
        file("json", "staff.json", json.dumps([{"employee_id": "HS-EMP-1042",
                                               "internal_url": link, "office_address": address}])),
        file("csv", "staff.csv", "employee_id,runbook_url,mailing_address\n"
             f'HS-EMP-1042,{link},"{address}"\n'),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    for kind, source in (("EMPLOYEE_ID", "HS-EMP-1042"), ("INTERNAL_URL", link), ("ADDRESS", address)):
        entity = next(item for item in body["entities"] if item["kind"] == kind and item["source"] == source)
        assert entity["mentions"] == 2
        assert all(entity["alias"] in document["candidate_text"] for document in body["documents"])
        assert all(source not in document["candidate_text"] for document in body["documents"])
    assert all(document["structure_check"] == "pass" for document in body["documents"])


def test_explicit_structured_international_address_is_reviewed_without_classifying_public_link(demo_client):
    address = "Flat 4, 12 Sample Road, Pune"
    public_link = "https://public.example.com/pr/4"
    request = {"synthetic_only": True, "files": [
        file("json", "staff.json", json.dumps([{"office_address": address, "review_link": public_link}])),
        file("csv", "staff.csv", f'office_address,review_link\n"{address}",{public_link}\n'),
    ]}
    response = demo_client.post("/demo/batch/inspect", headers=auth(), json=request)
    assert response.status_code == 200, response.text
    body = response.json()
    address_entity = next(item for item in body["entities"] if item["kind"] == "ADDRESS")
    assert address_entity["source"] == address
    assert address_entity["alias"].startswith("Postal address [review ")
    assert address_entity["mentions"] == 2
    assert all(address not in doc["candidate_text"] for doc in body["documents"])
    assert all(public_link in doc["candidate_text"] for doc in body["documents"])
    assert not any(item["kind"] == "INTERNAL_URL" for item in body["entities"])


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
