# PDF Qualified Timestamp CLI (pyHanko)

This repository contains a Python CLI that attaches an RFC 3161 document timestamp to a PDF using `pyHanko`.

A qualified timestamp depends on your TSA provider. To produce a qualified timestamp, use a qualified TSA endpoint with `--tsa-url`.

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python timestamp-pdf.py input.pdf [another.pdf ...] \
  --tsa-url "https://your-qualified-tsa.example/rfc3161"
```

The script timestamps each provided input file in-place.

Optional validation of TSA certs/revocation:

```bash
python timestamp-pdf.py input.pdf another.pdf \
  --tsa-url "https://your-qualified-tsa.example/rfc3161" \
  --validate-tsa
```

Verify signatures without modifying files:

```bash
python timestamp-pdf.py input.pdf another.pdf --verify
```

Sign and extract with separate commands (multiple PDFs supported):

```bash
python timestamp-pdf.py sign test.pdf another.pdf
python timestamp-pdf.py extract test.pdf another.pdf
```

## Notes

- `--md-algorithm` defaults to `sha256`.
- The script creates an incremental update in the PDF, preserving prior revisions.
- If your TSA requires custom auth headers or mTLS, extend the script's `HTTPTimeStamper` configuration.
