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
                graph_gold={("works_at", "p1", "o1")}, graph_automatic=set(),
                graph_reviewer_corrected={("works_at", "p1", "o1")}, primary_engine="rapidocr")


def test_scorecard_separates_automatic_reviewed_format_type_and_graph_results():
    report = scorecard(**inputs())
    assert report["automatic"]["exact"]["corpus"]["false_negatives"] == 2
    assert report["reviewer_corrected"]["exact"]["corpus"]["false_negatives"] == 0
    assert report["by_format"]["text"]["automatic"]["exact"]["per_entity"]["EMAIL"]["false_negatives"] == 1
    assert report["abstentions"] == {"abstained_documents": 1, "assessed_documents": 1, "by_reason": {"LOW_CONFIDENCE": 1}}
    assert report["graph"]["automatic"]["exact"]["false_negatives"] == 1
    assert report["graph"]["reviewer_corrected"]["exact"]["true_positives"] == 1
    assert "Ada" not in str(report) and "a@example.test" not in str(report)


def test_same_engine_or_missing_final_validation_abstains_not_independent():
    assert scorecard(**inputs())["final_artifact_validation"] == {"status": "ABSTAINED", "reason": "INDEPENDENT_ENGINE_UNAVAILABLE"}
    report = scorecard(**inputs(), final_validation={"engine_id": "rapidocr", "artifact_kind": "pixels", "assessed_units": 3, "residual_units": 0})
    assert report["final_artifact_validation"] == {"status": "ABSTAINED", "reason": "NO_DEFENSIBLE_INDEPENDENT_VALIDATION"}


def test_distinct_engine_can_only_report_aggregate_final_validation():
    report = scorecard(**inputs(), final_validation={"engine_id": "tesseract", "artifact_kind": "pixels", "assessed_units": 3, "residual_units": 1})
    assert report["final_artifact_validation"]["status"] == "ASSESSED"
    assert "Ada" not in str(report)


def test_invalid_document_coverage_or_abstention_fails_closed():
    values = inputs(); values["abstentions"] = {"missing": "LOW_CONFIDENCE"}
    try:
        scorecard(**values)
    except ScorecardError as error:
        assert str(error) == "Invalid D07 scorecard input."
    else:
        assert False
