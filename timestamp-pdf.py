#!/usr/bin/env python3
"""Attach an RFC 3161 document timestamp to a PDF using pyHanko.

A "qualified" timestamp depends on the TSA service you use.
To obtain a qualified timestamp, point --tsa-url to a qualified TSA endpoint
provided by a trust service provider.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Attach an RFC 3161 document timestamp signature to a PDF using pyHanko."
        )
    )
    parser.add_argument(
        "input_pdfs",
        nargs="+",
        type=Path,
        help="Path(s) to input PDF file(s)",
    )
    parser.add_argument(
        "--tsa-url",
        default="https://timestamp.sectigo.com/qualified",
        help="RFC 3161 TSA URL (use a qualified TSA endpoint for qualified timestamps)",
    )
    parser.add_argument(
        "--field-name",
        default="DocTimeStamp",
        help="Name of the timestamp signature field (default: %(default)s)",
    )
    parser.add_argument(
        "--md-algorithm",
        default="sha256",
        help="Hash algorithm for timestamping (default: %(default)s)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="TSA request timeout in seconds (default: %(default)s)",
    )
    parser.add_argument(
        "--validate-tsa",
        action="store_true",
        help=(
            "Validate TSA certificates and allow fetching revocation data while timestamping"
        ),
    )
    return parser


def attach_timestamp(args: argparse.Namespace) -> bool:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.sign import signers, timestamps
    from pyhanko_certvalidator import ValidationContext

    tsa_client = timestamps.HTTPTimeStamper(url=args.tsa_url, timeout=args.timeout)

    validation_context = None
    if args.validate_tsa:
        validation_context = ValidationContext(allow_fetching=True)

    pdf_timestamper = signers.PdfTimeStamper(
        timestamper=tsa_client,
        field_name=args.field_name,
    )

    has_errors = False
    for input_pdf in args.input_pdfs:
        try:
            if not input_pdf.exists():
                raise FileNotFoundError(f"Input file not found: {input_pdf}")
            if input_pdf.is_dir():
                raise IsADirectoryError(f"Input path is a directory: {input_pdf}")

            with input_pdf.open("rb+") as input_stream:
                writer = IncrementalPdfFileWriter(input_stream)
                pdf_timestamper.timestamp_pdf(
                    writer,
                    md_algorithm=args.md_algorithm,
                    validation_context=validation_context,
                    in_place=True,
                )
        except (FileNotFoundError, IsADirectoryError, OSError, ValueError) as exc:
            print(f"Error for {input_pdf}: {exc}", file=sys.stderr)
            has_errors = True
        else:
            print(f"Timestamp added successfully: {input_pdf}")

    return has_errors


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        has_errors = attach_timestamp(args)
    except ImportError as exc:  # pragma: no cover
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
