"""Disposable local-review parser. stdout is exactly one bounded JSON value."""
import json
import resource
import sys

resource.setrlimit(resource.RLIMIT_AS, (2_000_000_000, 2_000_000_000))
resource.setrlimit(resource.RLIMIT_CPU, (120, 120))
resource.setrlimit(resource.RLIMIT_FSIZE, (32_000_000, 32_000_000))

from app.document_extract import DocumentError  # noqa: E402
from app.document_review import MAX_REQUEST_BYTES, decode_review_payload  # noqa: E402

try:
    request = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(request) > MAX_REQUEST_BYTES:
        raise DocumentError("FILE_LIMIT")
    result = decode_review_payload(json.loads(request))
except DocumentError as error:
    result = {"error": str(error)}
except Exception:
    result = {"error": "PARSER_FAILED"}
sys.stdout.write(json.dumps(result))
