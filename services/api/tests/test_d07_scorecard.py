from app.d07_scorecard import ScorecardError, scorecard
from app.evaluation import Annotation, GoldDocument


def inputs():
    documents = (GoldDocument("one", "Ada a@example.test", (Annotation(0, 3, "PERSON_NAME"), Annotation(4, 18, "EMAIL"))),
                 GoldDocument("two", "Bob", (Annotation(0, 3, "PERSON_NAME"),)))
    automatic = [{"id": "one", "annotations": [{"start": 0, "end": 3, "entity_type": "PERSON_NAME"}]},
                 {"id": "two", "annotations": []}]
    reviewed = [{"id": "one", "annotations": [{"start": 0, "end": 3, "entity_type": "PERSON_NAME"}, {"start": 4, "end": 18, "entity_type": "EMAIL"}]},
                {"id": "two", "annotations": [{"start": 0, "end": 3, "entity_type": "PERSON_NAME"}]}]
    return dict(documents=documents, formats={"one": "text", "two": "json"}, automatic=automatic,
                reviewer_corrected=reviewed, abstentions={"two": "LOW_CONFIDENCE"},
                graph_gold={("works_at", "E1", "organization_1")}, graph_automatic=set(),
                graph_reviewer_corrected={("works_at", "E1", "organization_1")}, primary_engine="rapidocr")


def test_scorecard_separates_automatic_reviewed_format_type_and_graph_results():
    report = scorecard(**inputs())
    assert report["automatic"]["exact"]["corpus"]["false_negatives"] == 1
    assert report["reviewer_corrected"]["exact"]["corpus"]["false_negatives"] == 0
    assert report["by_format"]["text"]["automatic"]["exact"]["per_entity"]["EMAIL"]["false_negatives"] == 1
    assert report["by_format"]["json"]["automatic"] == {"documents": 0, "status": "NO_DOCUMENTS", "exact": None}
    assert report["abstentions"] == {"abstained_documents": 1, "assessed_documents": 1, "by_reason": {"LOW_CONFIDENCE": 1}}
    assert report["graph"]["automatic"]["exact"]["false_negatives"] == 1
    assert report["graph"]["reviewer_corrected"]["exact"]["true_positives"] == 1
    assert "Ada" not in str(report) and "a@example.test" not in str(report)


def test_coverage_aware_recall_retains_abstained_gold_positives_in_bounds():
    full_report = scorecard(**inputs())
    assert full_report["schema_version"] == "d07-scorecard-v2"
    report = full_report["coverage_aware_recall"]
    automatic = report["automatic"]["all_formats"]
    corpus = automatic["corpus"]
    assert automatic["status"] == "SCORED"
    assert corpus == {
        "eligible_documents": 2, "assessed_documents": 1, "abstained_documents": 1,
        "eligible_gold_positives": 3, "assessed_gold_positives": 2, "abstained_gold_positives": 1,
        "assessed_true_positives": 1, "assessed_false_negatives": 1,
        "conditional_recall": 0.5,
        "operational_recall_lower_bound": 1 / 3,
        "operational_recall_upper_bound": 2 / 3,
    }
    person = automatic["per_entity"]["PERSON_NAME"]
    assert (person["eligible_gold_positives"], person["assessed_gold_positives"],
            person["abstained_gold_positives"], person["conditional_recall"],
            person["operational_recall_lower_bound"], person["operational_recall_upper_bound"]) == (2, 1, 1, 1.0, 0.5, 1.0)
    email = automatic["per_entity"]["EMAIL"]
    assert (email["eligible_gold_positives"], email["conditional_recall"],
            email["operational_recall_lower_bound"], email["operational_recall_upper_bound"]) == (1, 0.0, 0.0, 0.0)
    json_slice = report["automatic"]["by_format"]["json"]
    assert json_slice["status"] == "ABSTAINED"
    assert json_slice["corpus"]["eligible_gold_positives"] == 1
    assert json_slice["corpus"]["operational_recall_lower_bound"] == 0.0
    assert json_slice["corpus"]["operational_recall_upper_bound"] == 1.0


def test_coverage_bounds_are_per_format_and_type_and_zero_gold_is_never_perfect():
    documents = (
        GoldDocument("text", "Ada", (Annotation(0, 3, "PERSON_NAME"),)),
        GoldDocument("json", "a@example.test", (Annotation(0, 14, "EMAIL"),)),
        GoldDocument("image", "no labels", ()),
    )
    automatic = [
        {"id": "text", "annotations": [{"start": 0, "end": 3, "entity_type": "PERSON_NAME"}]},
        {"id": "json", "annotations": []},
        {"id": "image", "annotations": []},
    ]
    values = dict(documents=documents, formats={"text": "text", "json": "json", "image": "image"},
                  automatic=automatic, reviewer_corrected=automatic, abstentions={},
                  graph_gold=None, graph_automatic=None, graph_reviewer_corrected=None, primary_engine="synthetic")
    report = scorecard(**values)["coverage_aware_recall"]["automatic"]["by_format"]
    text_person = report["text"]["per_entity"]["PERSON_NAME"]
    assert (text_person["eligible_documents"], text_person["assessed_documents"],
            text_person["abstained_documents"], text_person["eligible_gold_positives"],
            text_person["conditional_recall"], text_person["operational_recall_lower_bound"],
            text_person["operational_recall_upper_bound"]) == (1, 1, 0, 1, 1.0, 1.0, 1.0)
    json_email = report["json"]["per_entity"]["EMAIL"]
    assert (json_email["eligible_gold_positives"], json_email["assessed_gold_positives"],
            json_email["abstained_gold_positives"], json_email["conditional_recall"],
            json_email["operational_recall_lower_bound"], json_email["operational_recall_upper_bound"]) == (1, 1, 0, 0.0, 0.0, 0.0)
    image = report["image"]["corpus"]
    assert (image["eligible_documents"], image["eligible_gold_positives"], image["conditional_recall"],
            image["operational_recall_lower_bound"], image["operational_recall_upper_bound"]) == (1, 0, None, None, None)


def test_all_abstained_documents_have_no_span_metrics_or_format_scores():
    values = inputs(); values["abstentions"] = {"one": "LOW_CONFIDENCE", "two": "NO_DEFENSIBLE_LOCATOR"}
    report = scorecard(**values)
    expected = {"status": "ABSTAINED", "reason": "NO_ASSESSED_DOCUMENTS", "exact": None}
    assert report["automatic"] == expected
    assert report["reviewer_corrected"] == expected
    assert all(value["automatic"] == {"documents": 0, "status": "NO_DOCUMENTS", "exact": None}
               and value["reviewer_corrected"] == {"documents": 0, "status": "NO_DOCUMENTS", "exact": None}
               for value in report["by_format"].values())
    assert report["abstentions"]["assessed_documents"] == 0
    bounds = report["coverage_aware_recall"]["automatic"]["all_formats"]
    assert bounds["status"] == "ABSTAINED"
    assert bounds["reason"] == "NO_ASSESSED_DOCUMENTS"
    assert bounds["corpus"]["conditional_recall"] is None
    assert bounds["corpus"]["operational_recall_lower_bound"] == 0.0
    assert bounds["corpus"]["operational_recall_upper_bound"] == 1.0


def test_same_engine_or_missing_final_validation_abstains_not_independent():
    assert scorecard(**inputs())["final_artifact_validation"] == {"status": "ABSTAINED", "reason": "INDEPENDENT_ENGINE_UNAVAILABLE"}
    report = scorecard(**inputs(), final_validation={"engine_id": "rapidocr", "artifact_kind": "pixels", "assessed_units": 3, "residual_units": 0})
    assert report["final_artifact_validation"] == {"status": "ABSTAINED", "reason": "NO_EXECUTABLE_BOUND_INDEPENDENT_VALIDATOR"}


def test_spoofed_distinct_engine_is_not_independent_validation():
    report = scorecard(**inputs(), final_validation={"engine_id": "tesseract", "artifact_kind": "pixels", "assessed_units": 3, "residual_units": 1})
    assert report["final_artifact_validation"] == {
        "status": "ABSTAINED", "reason": "NO_EXECUTABLE_BOUND_INDEPENDENT_VALIDATOR"}


def test_invalid_document_coverage_or_abstention_fails_closed():
    values = inputs(); values["abstentions"] = {"missing": "LOW_CONFIDENCE"}
    try:
        scorecard(**values)
    except ScorecardError as error:
        assert str(error) == "Invalid D07 scorecard input."
    else:
        assert False


def test_graph_container_type_and_bounds_fail_closed():
    values = inputs(); values["graph_gold"] = [("works_at", "E1", "organization_1")]
    try:
        scorecard(**values)
    except ScorecardError as error:
        assert str(error) == "Invalid D07 scorecard input."
    else:
        assert False


def test_missing_graph_gold_and_review_state_abstains():
    values = inputs(); values.update(graph_gold=None, graph_automatic=None, graph_reviewer_corrected=None)
    report = scorecard(**values)
    assert report["graph"] == {
        "automatic": {"status": "ABSTAINED", "reason": "NO_GRAPH_GOLD_OR_REVIEW_STATE"},
        "reviewer_corrected": {"status": "ABSTAINED", "reason": "NO_GRAPH_GOLD_OR_REVIEW_STATE"},
    }


def test_graph_relation_ontology_and_opaque_endpoint_ids_fail_closed():
    for claim in [("Ada", "E1", "organization_1"), ("works_at", "Ada", "organization_1"),
                  ("works_at", "E1", "Ada")]:
        values = inputs(); values["graph_gold"] = {claim}
        try:
            scorecard(**values)
        except ScorecardError as error:
            assert str(error) == "Invalid D07 scorecard input."
        else:
            assert False


def test_malformed_format_abstention_and_direct_gold_document_fail_closed():
    for field, value in [("formats", {"one": [], "two": "json"}),
                         ("abstentions", {"two": []})]:
        values = inputs(); values[field] = value
        try:
            scorecard(**values)
        except ScorecardError as error:
            assert str(error) == "Invalid D07 scorecard input."
        else:
            assert False
    values = inputs(); values["documents"] = (GoldDocument("one", "Ada", (Annotation(0, 9, "PERSON_NAME"),)),)
    try:
        scorecard(**values)
    except ScorecardError as error:
        assert str(error) == "Invalid D07 scorecard input."
    else:
        assert False
