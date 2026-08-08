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

from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import signers, timestamps
from pyhanko_certvalidator import ValidationContext


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Attach an RFC 3161 document timestamp signature to a PDF using pyHanko."
        )
    )
    parser.add_argument("input_pdf", type=Path, help="Path to the input PDF file")
    parser.add_argument("output_pdf", type=Path, help="Path for the timestamped PDF")
    parser.add_argument(
        "--tsa-url",
        required=True,
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
    parser.add_argument(
        "--in-place",
        action="store_true",
        help="Apply timestamp incrementally to the input file directly",
    )
    return parser


def _ensure_inputs(args: argparse.Namespace) -> None:
    if not args.input_pdf.exists():
        raise FileNotFoundError(f"Input file not found: {args.input_pdf}")
    if args.in_place and args.output_pdf != args.input_pdf:
        raise ValueError("With --in-place, output_pdf must be the same path as input_pdf.")
    if not args.in_place and args.output_pdf.exists() and args.output_pdf.is_dir():
        raise IsADirectoryError(f"Output path is a directory: {args.output_pdf}")


def attach_timestamp(args: argparse.Namespace) -> None:
    tsa_client = timestamps.HTTPTimeStamper(url=args.tsa_url, timeout=args.timeout)

    validation_context = None
    if args.validate_tsa:
        validation_context = ValidationContext(allow_fetching=True)

    pdf_timestamper = signers.PdfTimeStamper(
        timestamper=tsa_client,
        field_name=args.field_name,
    )

    with args.input_pdf.open("rb") as input_stream:
        writer = IncrementalPdfFileWriter(input_stream)
        if args.in_place:
            pdf_timestamper.timestamp_pdf(
                writer,
                md_algorithm=args.md_algorithm,
                validation_context=validation_context,
                in_place=True,
            )
        else:
            with args.output_pdf.open("wb") as output_stream:
                pdf_timestamper.timestamp_pdf(
                    writer,
                    md_algorithm=args.md_algorithm,
                    validation_context=validation_context,
                    output=output_stream,
                )


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        _ensure_inputs(args)
        attach_timestamp(args)
    except Exception as exc:  # pragma: no cover
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    target = args.input_pdf if args.in_place else args.output_pdf
    print(f"Timestamp added successfully: {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
