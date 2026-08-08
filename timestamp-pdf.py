#!/usr/bin/env python3
"""Sign PDFs with RFC3161 timestamps and extract RFC3161 timestamp values."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Sign PDFs with RFC3161 timestamps and extract timestamp values."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    sign_parser = subparsers.add_parser(
        "sign",
        help="Attach a new RFC3161 timestamp signature",
    )
    sign_parser.add_argument(
        "pdfs",
        nargs="+",
        type=Path,
        help="Path(s) to the PDF file(s) to timestamp",
    )
    sign_parser.add_argument(
        "--tsa-url",
        default="https://timestamp.sectigo.com/qualified",
        help="RFC3161 TSA URL (default: %(default)s)",
    )
    sign_parser.add_argument(
        "--md-algorithm",
        default="sha256",
        help="Hash algorithm for timestamping (default: %(default)s)",
    )
    sign_parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="TSA request timeout in seconds (default: %(default)s)",
    )
    sign_parser.add_argument(
        "--field-name",
        default="DocTimeStamp",
        help="Signature field name to use when signing (default: %(default)s)",
    )

    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract and print RFC3161 timestamp values",
    )
    extract_parser.add_argument(
        "pdfs",
        nargs="+",
        type=Path,
        help="Path(s) to signed PDF file(s)",
    )
    extract_parser.add_argument(
        "--field-name",
        default=None,
        help="Optional signature field name to extract from",
    )
    return parser


def extract_rfc3161_gen_time(signature_dict: dict[str, Any]) -> str:
    """Return RFC3161 genTime from a signature dictionary."""
    from asn1crypto import cms, tsp

    contents = bytes(signature_dict["/Contents"]).rstrip(b"\x00")
    if not contents:
        raise ValueError("signature /Contents is empty")

    token = cms.ContentInfo.load(contents)
    signed_data = token["content"]
    encap_content_info = signed_data["encap_content_info"]
    payload = encap_content_info["content"]
    if payload is None:
        raise ValueError("RFC3161 token has no encapsulated content")

    payload_native = payload.native
    if isinstance(payload_native, dict):
        gen_time = payload_native.get("gen_time")
        if gen_time is None:
            raise ValueError("RFC3161 token missing gen_time")
    else:
        tst_info = tsp.TSTInfo.load(payload_native)
        gen_time = tst_info["gen_time"].native
    return gen_time.isoformat() if hasattr(gen_time, "isoformat") else str(gen_time)


def _ensure_pdf_path(pdf_path: Path) -> None:
    if not pdf_path.exists():
        raise FileNotFoundError(f"Input file not found: {pdf_path}")
    if pdf_path.is_dir():
        raise IsADirectoryError(f"Input path is a directory: {pdf_path}")


def sign_pdf(
    pdf_path: Path,
    tsa_url: str,
    md_algorithm: str,
    timeout: int,
    field_name: str,
) -> str:
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.misc import PdfReadError
    from pyhanko.sign import signers, timestamps

    _ensure_pdf_path(pdf_path)

    timestamper = timestamps.HTTPTimeStamper(url=tsa_url, timeout=timeout)
    pdf_timestamper = signers.PdfTimeStamper(
        timestamper=timestamper,
        field_name=field_name,
    )

    try:
        with pdf_path.open("rb+") as inout_stream:
            writer = IncrementalPdfFileWriter(inout_stream)
            pdf_timestamper.timestamp_pdf(
                writer,
                md_algorithm=md_algorithm,
                in_place=True,
            )
    except PdfReadError as exc:
        raise ValueError(f"Input PDF appears malformed: {pdf_path}") from exc

    return field_name


def extract_timestamps(
    pdf_path: Path,
    field_name: str | None = None,
) -> list[tuple[str, str]]:
    from pyhanko.pdf_utils.misc import PdfReadError
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.fields import enumerate_sig_fields

    _ensure_pdf_path(pdf_path)

    try:
        with pdf_path.open("rb") as input_stream:
            reader = PdfFileReader(input_stream)
            found_timestamps: list[tuple[str, str]] = []
            for found_field_name, value_ref, _ in enumerate_sig_fields(reader):
                if field_name is not None and found_field_name != field_name:
                    continue
                if value_ref is None:
                    if field_name is None:
                        continue
                    raise ValueError(f"Signature field '{field_name}' is empty.")

                signature_dict = value_ref.get_object()
                subfilter = str(signature_dict.get("/SubFilter", ""))
                if subfilter != "/ETSI.RFC3161":
                    if field_name is None:
                        continue
                    raise ValueError(
                        f"Signature field '{field_name}' is not RFC3161 "
                        f"(SubFilter={subfilter})."
                    )

                gen_time = extract_rfc3161_gen_time(signature_dict)
                found_timestamps.append((found_field_name, gen_time))

            if found_timestamps:
                return found_timestamps

            if field_name is not None:
                raise ValueError(f"Could not find signature field: {field_name}")
            raise ValueError("No RFC3161 timestamp signatures found in the PDF.")
    except PdfReadError as exc:
        raise ValueError(f"Signed PDF appears malformed after update: {pdf_path}") from exc


def main() -> int:
    args = build_parser().parse_args()
    has_errors = False

    if args.command == "sign":
        for pdf_path in args.pdfs:
            try:
                field_name = sign_pdf(
                    pdf_path=pdf_path,
                    tsa_url=args.tsa_url,
                    md_algorithm=args.md_algorithm,
                    timeout=args.timeout,
                    field_name=args.field_name,
                )
                print(f"Signed {pdf_path}: field {field_name}")
            except (
                FileNotFoundError,
                IsADirectoryError,
                ImportError,
                OSError,
                ValueError,
            ) as exc:
                print(f"Error for {pdf_path}: {exc}", file=sys.stderr)
                has_errors = True

    elif args.command == "extract":
        for pdf_path in args.pdfs:
            try:
                timestamps = extract_timestamps(
                    pdf_path=pdf_path,
                    field_name=args.field_name,
                )
                print(f"PDF: {pdf_path}")
                for extracted_field_name, gen_time in timestamps:
                    print(f"  Field: {extracted_field_name}")
                    print(f"  RFC3161 genTime: {gen_time}")
            except (
                FileNotFoundError,
                IsADirectoryError,
                ImportError,
                OSError,
                ValueError,
            ) as exc:
                print(f"Error for {pdf_path}: {exc}", file=sys.stderr)
                has_errors = True

    return 1 if has_errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
