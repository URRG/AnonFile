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
low-contrast scan, a catastrophic-blur provider-claim case, dedicated
unprocessed-neighbor and material-OCR-overlap rasters, and an EXIF-rotated
JPEG. The tests run the installed OCR
engine against the two-column, table, static-form and screenshot inputs. A
case passes only when it returns bounded page/text output or returns one of the
explicit review abstentions. The screenshot replacement regression intentionally
pins one large fictional `Name: Maya Patel` OCR line: a model change that loses
that line must fail the demo test rather than silently produce an incomplete
candidate. Other corpus cases do not pin model-specific OCR words.

The pixel oracle checks both directions relevant to repaint fidelity: no pixel
may change outside an applied OCR-line box or a reviewer manual box, and a
separate fictional `Maya Patel` source region is fully cleared when its
replacement is empty. This is evidence about the raster candidate only, not a
claim that OCR coverage, entity detection, or anonymization is complete.

The corpus verifies the present conservative geometry guards for overlapping
OCR boxes, competing same-baseline two- and three-cell rows, repeated
vertically staggered column bands, and an actual padded repaint box that
touches an otherwise unprocessed OCR neighbor. It also rejects one overbroad
OCR line whose box contains a separate, unrecognised fictional ink region: a
local edge alone cannot authorize repainting both regions. Separate islands in
either horizontal or vertical bands and detached long thin rule-like connected
components abstain. Before a repaint, the source pixels in the padded ring
between an OCR line's tight ink box and its erased box must also be free of
dark pixels (at most 245); an unseen dark glyph there abstains. The only
exception is a one-pixel antialiased fringe directly adjacent to dark ink inside the
claim, which accounts for half-open detector geometry rather than a second
glyph. These are local geometry guards, not proof that OCR geometry contains
only the recognised text. A real OCR screenshot case also
repaints a fictional name and checks that pixels outside its OCR box are
unchanged. This does **not** establish general table parsing, multi-column
reading order, or general scan quality. The interactive AcroForm is required
to abstain before OCR. The faint scan's low-confidence response is tested with
a deterministic provider result because real OCR confidence is
hardware/model dependent.

The catastrophic-blur fixture separately supplies a confident fictional
provider claim whose claimed box has no measurable raster edge; it must fail
closed before a candidate is created. The dedicated unprocessed-neighbor and
material-overlap fixtures likewise assert fail-closed exceptions before pixel
mutation or a reading order is invented. These expected `abstain` outcomes are
not a `NOT_QUALIFIED` measurement, and neither they nor the low-contrast case
claims OCR completeness.
