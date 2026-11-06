# PDF Timestamp Utilty

This repository contains a Python CLI script that attaches an RFC 3161 document timestamp to a PDF using [pyHanko](https://github.com/MatthiasValvekens/pyHanko).

A qualified timestamp depends on your TSA provider. To produce a qualified timestamp, use a qualified TSA endpoint with `--tsa-url`.

## Install

Requires [uv](https://docs.astral.sh/uv/). It installs the Python version from `.python-version` and the locked dependencies from `uv.lock`:

```bash
uv sync
```

## Usage

Sign one or more PDFs in-place:

```bash
uv run timestamp-pdf.py sign input.pdf another.pdf \
  --tsa-url "https://your-qualified-tsa.example/rfc3161"
```

Use a fixed signature field name when signing:

```bash
uv run timestamp-pdf.py sign input.pdf --field-name DocTimeStamp
```

Don't embed LTV validation info (DSS/VRI) after signing:

```bash
uv run timestamp-pdf.py sign input.pdf --no-ltv
```

Extract RFC3161 timestamp values from one or more PDFs:

```bash
uv run timestamp-pdf.py extract input.pdf another.pdf
```

## Tests

```bash
uv run python -m unittest discover -s tests -p "test_*.py" -v
```

## Notes

- `--md-algorithm` defaults to `sha256`.
- The script creates an incremental update in the PDF, preserving prior revisions.
- `sign` skips PDFs that already contain an RFC3161 document timestamp and reports them as skipped (exit code 0). Other signatures don't prevent signing.
- If your TSA requires custom auth headers or mTLS, extend the script's `HTTPTimeStamper` configuration.
