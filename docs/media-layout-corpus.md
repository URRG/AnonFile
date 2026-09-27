# D05 media-layout corpus

`scripts/generate-media-layout-corpus.py` creates the corpus at test time.
Every string, name, identifier and image in it is fictional; generated binary
files are intentionally not committed.

From the repository root, generate a copy or run the tests directly:

```powershell
.venv\Scripts\python.exe scripts\generate-media-layout-corpus.py --output .media-layout-corpus
cd services/api
..\..\.venv\Scripts\python.exe -m pytest tests/test_media_preview.py tests/test_media_layout_corpus.py -q
```

The corpus covers a single-column PDF control, two columns, a ruled table, a
static form, an interactive AcroForm boundary, a screenshot PNG, a faint
low-contrast scan, and an EXIF-rotated JPEG. The tests run the installed OCR
engine against the two-column, table, static-form and screenshot inputs. A
case passes only when it returns bounded page/text output or returns one of the
explicit review abstentions; the suite does not pin model-specific OCR words.

The pixel oracle checks both directions relevant to repaint fidelity: no pixel
may change outside an applied OCR-line box or a reviewer manual box, and a
separate fictional `Maya Patel` source region is fully cleared when its
replacement is empty. This is evidence about the raster candidate only, not a
claim that OCR coverage, entity detection, or anonymization is complete.

The corpus verifies the present conservative geometry guards for overlapping
OCR boxes, competing same-baseline column/cell boxes, and an actual padded repaint box that
touches an otherwise unprocessed OCR neighbor. It does **not** establish
general table parsing, multi-column reading order, general scan quality, or
that every three-or-more-cell table is rejected. The interactive AcroForm is
required to abstain before OCR. The faint scan's low-confidence response is
tested with a deterministic provider result because real OCR confidence is
hardware/model dependent.
