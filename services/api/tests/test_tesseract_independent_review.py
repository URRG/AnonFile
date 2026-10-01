"""Independent QA of normalized residual comparisons on final PDF bytes."""
from dataclasses import replace

import pytest

from app.tesseract_verifier import FinalOcrVerificationError
from test_tesseract_verifier import FakeProcess, verifier


@pytest.mark.parametrize("source,transcript", [
    ("José Alvarez", "JOSE\u0301\nALVAREZ"),
    ("Straße", "ＳＴＲＡＳＳＥ"),
    ("Maya Patel", "ＭＡＹＡ\t\u00a0ＰＡＴＥＬ"),
])
def test_final_pdf_rejects_combinations_of_normalization_variants(source, transcript):
    rasterized = []
    checked = replace(verifier(lambda *_args, **_kwargs: FakeProcess(stdout=transcript.encode())),
                      pdf_rasterizer=lambda data: rasterized.append(data) or (b"final-raster",))
    with pytest.raises(FinalOcrVerificationError, match="found residual content") as error:
        checked.verify_pdf(b"exact-final-pdf", (source,))
    assert rasterized == [b"exact-final-pdf"]
    assert source not in str(error.value) and transcript not in str(error.value)
