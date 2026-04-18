import os
from datetime import datetime, timezone
from electrum.logging import get_logger

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography.x509.oid import NameOID


logger = get_logger(__name__)

# Map cryptography NameOIDs to the short names returned by OpenSSL get_components()
_OID_TO_SHORT = {
    NameOID.COMMON_NAME: b"CN",
    NameOID.COUNTRY_NAME: b"C",
    NameOID.STATE_OR_PROVINCE_NAME: b"ST",
    NameOID.LOCALITY_NAME: b"L",
    NameOID.ORGANIZATION_NAME: b"O",
    NameOID.ORGANIZATIONAL_UNIT_NAME: b"OU",
    NameOID.EMAIL_ADDRESS: b"emailAddress",
    NameOID.SERIAL_NUMBER: b"serialNumber",
}


class CertificateValidator:
    def __init__(self):
        logger.debug("In __init__")

    def validate_certificate_chain(self, device_pem, device_type):
        logger.debug("In validate_certificate_chain")

        USE_TEST_CA = True

        is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error = (
            self._validate_chain(device_pem, device_type, use_test=False)
        )
        if is_valid:
            return is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        elif USE_TEST_CA:
            logger.warning("Certificate chains NOT VALID for production PKI")
            (
                is_valid_test,
                device_pubkey_test,
                txt_ca_test,
                txt_subca_test,
                txt_device_test,
                txt_error_test,
            ) = self._validate_chain(device_pem, device_type, use_test=True)
            if is_valid_test:
                is_valid_test = False
                txt_error_test = "WARNING: Chain certificate validated with TEST CA! NOT FOR PRODUCTION!"
                return (
                    is_valid_test,
                    device_pubkey_test,
                    txt_ca_test,
                    txt_subca_test,
                    txt_device_test,
                    txt_error_test,
                )
            else:
                return is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        return is_valid, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

    def _validate_chain(self, device_pem, device_type, use_test=False):
        logger.debug("In _validate_chain")

        txt_ca = txt_subca = txt_device = txt_error = ""
        device_pubkey = bytes(65 * [0])

        directory = os.path.join(os.path.dirname(__file__), "certs")
        if not use_test:
            path_ca = os.path.join(directory, "ca.cert")
            if device_type == "SeedKeeper":
                path_subca = os.path.join(directory, "subca-seedkeeper.cert")
            elif device_type == "Satochip":
                path_subca = os.path.join(directory, "subca-satochip.cert")
            elif device_type == "Satodime":
                path_subca = os.path.join(directory, "subca-satodime.cert")
            else:
                txt_error = "Unknown card_type: " + str(device_type)
                return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
        else:
            path_ca = os.path.join(directory, "test-ca.cert")
            if device_type == "SeedKeeper":
                path_subca = os.path.join(directory, "test-subca-seedkeeper.cert")
            elif device_type == "Satochip":
                path_subca = os.path.join(directory, "test-subca-satochip.cert")
            elif device_type == "Satodime":
                path_subca = os.path.join(directory, "test-subca-satodime.cert")
            else:
                txt_error = "Unknown card_type: " + str(device_type)
                return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        try:
            with open(path_ca, "r", encoding="utf-8") as f:
                ca_pem = f.read()
            with open(path_subca, "r", encoding="utf-8") as f:
                subca_pem = f.read()
        except FileNotFoundError as ex:
            txt_error = "Certificate file not found: " + str(ex)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        try:
            parsed_ca = self._load_pem_cert(ca_pem)
            txt_ca = self._cert_to_text(parsed_ca)
            logger.debug("CA cert: " + txt_ca)

            parsed_subca = self._load_pem_cert(subca_pem)
            txt_subca = self._cert_to_text(parsed_subca)
            logger.debug("SUBCA cert: " + txt_subca)

            parsed_device = self._load_pem_cert(device_pem)
            txt_device = self._cert_to_text(parsed_device)
            logger.debug("DEVICE cert: " + txt_device)
        except Exception as ex:
            txt_error = "Exception during pem certificates parsing: " + str(ex)
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        # The vendored cert files contain OpenSSL text output before the PEM block
        # so we serialize to DER SubjectPublicKeyInfo and extract the last 65 bytes
        # which correspond to the uncompressed EC point (0x04 + 32b X + 32b Y)
        pubkey_der = parsed_device.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        logger.debug("DEVICE pubkey asn1: " + pubkey_der.hex())
        device_pubkey = pubkey_der[-65:]

        if not self._verify_cert_signature(parsed_subca, parsed_ca):
            txt_error = (
                "Exception during subca validation: signature verification failed"
            )
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        if not self._verify_cert_signature(parsed_device, parsed_subca):
            txt_error = "Exception during device certificate validation: signature verification failed"
            return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        now = datetime.now(timezone.utc)
        for label, cert in [
            ("CA", parsed_ca),
            ("SubCA", parsed_subca),
            ("Device", parsed_device),
        ]:
            if now > cert.not_valid_after_utc:
                txt_error = f"{label} certificate has expired"
                return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error
            if now < cert.not_valid_before_utc:
                txt_error = f"{label} certificate is not yet valid"
                return False, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

        return True, device_pubkey, txt_ca, txt_subca, txt_device, txt_error

    @staticmethod
    def _load_pem_cert(pem_data):
        """Load a PEM certificate from string data.

        Handles both pure PEM and combined text+PEM formats
        (the vendored cert files include OpenSSL text output before the PEM block).
        """
        if isinstance(pem_data, str):
            pem_data = pem_data.encode("utf-8")

        begin_marker = b"-----BEGIN CERTIFICATE-----"
        if begin_marker in pem_data:
            start = pem_data.index(begin_marker)
            pem_data = pem_data[start:]

        return x509.load_pem_x509_certificate(pem_data)

    @staticmethod
    def _cert_to_text(cert):
        lines = [
            "Certificate:",
            f"    Data:",
            f"        Version: {cert.version.name} ({cert.version.value})",
            f"        Serial Number: {cert.serial_number} (0x{cert.serial_number:x})",
            f"        Signature Algorithm: {cert.signature_algorithm_oid._name}",
            f"        Issuer: {cert.issuer.rfc4514_string()}",
            f"        Validity:",
            f"            Not Before: {cert.not_valid_before_utc}",
            f"            Not After : {cert.not_valid_after_utc}",
            f"        Subject: {cert.subject.rfc4514_string()}",
            f"        Subject Public Key Info:",
            f"            Public Key Algorithm: {cert.public_key().curve.name if isinstance(cert.public_key(), ec.EllipticCurvePublicKey) else 'unknown'}",
        ]
        return "\n".join(lines)

    @staticmethod
    def _verify_cert_signature(cert, issuer_cert):
        issuer_public_key = issuer_cert.public_key()
        try:
            if isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    ec.ECDSA(cert.signature_hash_algorithm),
                )
            elif isinstance(issuer_public_key, rsa.RSAPublicKey):
                issuer_public_key.verify(
                    cert.signature,
                    cert.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    cert.signature_hash_algorithm,
                )
            else:
                raise ValueError(f"Unsupported key type: {type(issuer_public_key)}")
            return True
        except (InvalidSignature, Exception):
            return False

    @staticmethod
    def _name_to_dict(name):
        result = {}
        for attr in name:
            key = _OID_TO_SHORT.get(attr.oid, attr.oid.dotted_string.encode("utf-8"))
            value = (
                attr.value.encode("utf-8")
                if isinstance(attr.value, str)
                else attr.value
            )
            result[key] = value
        return result

    def parse_pem_certificate(self, cert_pem):
        cert_dict = {}
        cert = self._load_pem_cert(cert_pem)

        is_expired = datetime.now(timezone.utc) > cert.not_valid_after_utc
        cert_dict["is_expired"] = is_expired
        cert_dict["issuer"] = self._name_to_dict(cert.issuer)
        cert_dict["subject"] = self._name_to_dict(cert.subject)

        return cert_dict
