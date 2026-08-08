import importlib.util
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from asn1crypto import keys as asn1_keys
from asn1crypto import x509 as asn1_x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyhanko.pdf_utils import generic, writer
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import timestamps, validation
from pyhanko.sign.fields import enumerate_sig_fields
from pyhanko.sign.validation.pdf_embedded import EmbeddedPdfSignature
from pyhanko_certvalidator import ValidationContext

SCRIPT_PATH = Path(__file__).resolve().parent.parent / "timestamp-pdf.py"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("timestamp_pdf_script", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module spec from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _create_simple_pdf(path: Path) -> None:
    pdf_writer = writer.PdfFileWriter()
    stream = generic.StreamObject(stream_data=b"BT ET")
    page = writer.PageObject(
        contents=pdf_writer.add_object(stream),
        media_box=(0, 0, 300, 300),
        resources=generic.DictionaryObject(),
    )
    pdf_writer.insert_page(page)

    with path.open("wb") as out_stream:
        pdf_writer.write(out_stream)


def _make_dummy_tsa_material() -> tuple[asn1_x509.Certificate, asn1_keys.PrivateKeyInfo]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = crypto_x509.Name(
        [
            crypto_x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            crypto_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test TSA"),
            crypto_x509.NameAttribute(NameOID.COMMON_NAME, "Local Dummy TSA"),
        ]
    )

    cert = (
        crypto_x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(crypto_x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc) - timedelta(days=1))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .add_extension(crypto_x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key, hashes.SHA256())
    )

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    key_der = private_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    return asn1_x509.Certificate.load(cert_der), asn1_keys.PrivateKeyInfo.load(key_der)


class TimestampPdfIntegrationTest(unittest.TestCase):
    def test_sign_and_verify_timestamp_signature(self):
        timestamp_pdf = _load_script_module()

        with tempfile.TemporaryDirectory() as temp_dir:
            pdf_path = Path(temp_dir) / "sample.pdf"
            _create_simple_pdf(pdf_path)

            tsa_cert, tsa_key = _make_dummy_tsa_material()
            dummy_timestamper = timestamps.DummyTimeStamper(
                tsa_cert=tsa_cert,
                tsa_key=tsa_key,
            )

            original_http_timestamper = timestamp_pdf.timestamps.HTTPTimeStamper
            timestamp_pdf.timestamps.HTTPTimeStamper = lambda url, timeout: dummy_timestamper
            try:
                field_name = timestamp_pdf.sign_pdf(
                    pdf_path=pdf_path,
                    tsa_url="https://example.invalid/rfc3161",
                    md_algorithm="sha256",
                    timeout=5,
                    field_name="DocTimeStamp",
                )
            finally:
                timestamp_pdf.timestamps.HTTPTimeStamper = original_http_timestamper

            extracted = timestamp_pdf.extract_timestamps(pdf_path, field_name=field_name)
            self.assertEqual(len(extracted), 1)
            self.assertEqual(extracted[0][0], field_name)
            self.assertTrue(extracted[0][1])

            with pdf_path.open("rb") as input_stream:
                reader = PdfFileReader(input_stream)
                target_field_ref = None
                for found_field_name, value_ref, field_ref in enumerate_sig_fields(reader):
                    if found_field_name == field_name and value_ref is not None:
                        target_field_ref = field_ref
                        break

                self.assertIsNotNone(target_field_ref)
                if target_field_ref is None:
                    self.fail(f"Signed field {field_name} was not found in the PDF")

                embedded_sig = EmbeddedPdfSignature(
                    reader,
                    target_field_ref.get_object(),
                    field_name,
                )

                status = validation.validate_pdf_timestamp(
                    embedded_sig,
                    validation_context=ValidationContext(
                        allow_fetching=False,
                        extra_trust_roots=[tsa_cert],
                    ),
                )

            self.assertTrue(status.intact)
            self.assertTrue(status.valid)
            self.assertTrue(status.trusted)
            self.assertTrue(status.intact and status.valid and status.trusted)


if __name__ == "__main__":
    unittest.main()
