from datetime import date
from app.orchestration.models import Disposition
from tests.conftest import context


def test_supported_answer_and_trace(workflow):
    answer=workflow.ask("When must Alpha facilities report a sample result?",context("alpha-analyst"),"FEDERAL",date(2026,6,1))
    assert answer.disposition==Disposition.ANSWER
    assert all(v.status=="SUPPORTED" for v in answer.verification)
    assert [x["node"] for x in answer.trace][-1]=="audit"


def test_unsupported_topic_abstains(workflow):
    answer=workflow.ask("What cybersecurity encryption algorithm is mandatory?",context("alpha-analyst"),"FEDERAL",date(2026,6,1))
    assert answer.disposition==Disposition.ABSTAIN


def test_future_version_excluded(workflow):
    answer=workflow.ask("When must Alpha facilities report a sample result?",context("alpha-analyst"),"FEDERAL",date(2026,6,1))
    assert "18 hours" not in answer.answer
