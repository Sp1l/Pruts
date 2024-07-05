"""Operations on certificate blobs and files"""

import re
import subprocess

from hashlib import sha1
from pathlib import Path
from tempfile import NamedTemporaryFile

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from lib.zip import create_zip_blob, clean_name

import logging

logger = logging.getLogger(__name__)

CERT_PEM_REGEX = re.compile(
    b"-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----\r?\n",
    re.DOTALL,
)

"""
A Root CA cert:
    1. has a SubjectKeyId but no AuthorityKeyId
    2. has Basic Constraint CA:TRUE
    3. has Key Usage Certificate Sign
    4. Issuer and Subject are the same
An Intermediate or subordinate CA cert:
    1. has a SubjectKeyId as well as an AuthorityKeyId (link to signer)
    2. has Basic Constraint CA:TRUE
    3. has Key Usage Certificate Sign
A leaf cert:
    1. should have a SubjectKeyId as well as an AuthorityKeyId
"""

def get_cert_detail(certificate: str|bytes) -> dict:
    """Extract details from certificate

    Args:
        certificate (str|bytes): DER or PEM encoded certificate

    Returns:
        dict: cert_detail dictionary with attributes
            fingerprint_sha1: SHA1 fingerprint of certificate
            fingerprint_sha256: SHA256 fingerprint of certificate
            serial: Serial number of certificate
            not_before: Validity start date (datetime)
            not_after: Validity end date (datetime)
            common_name: CN attribute of certificate
            issuer: CN of issuer of certificate
            issuer_subject: Full subject of certificate issuer
            names: Subject Alternative Names
            modulus_SHA1: SHA1 hash of the public key modulus
            subjectKeyId: Subject Key Identifier extension (if it exists)
            authorityKeyId: Authority Key Identifier extension (if it exists)
            CA: Basic Constraint CA (boolean)
            RootCA: Certificate is a self-signed root (boolean)
            self-signed: Certificate is self-signed (boolean)
            precert: Precertificate status (boolean)
    """

    if isinstance(certificate, memoryview):
        certificate = certificate.tobytes()
    elif isinstance(certificate, str):
        certificate = certificate.encode()

    try:
        if re.search(
            b"-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----",
            certificate,
            re.DOTALL
        ) is not None:
            cert = x509.load_pem_x509_certificate(certificate, default_backend())
        else:
            cert = x509.load_der_x509_certificate(certificate, default_backend())
    except Exception:  # pylint: disable=broad-exception-caught
        logger.error("get_cert_detail: load cert failed")
        return None

    msg = str(cert.fingerprint(hashes.SHA1()).hex())
    logger.debug("get_cert_detail: %s", msg)
    fingerprint_sha1 = cert.fingerprint(hashes.SHA1()).hex()
    result = {"serial": hex(cert.serial_number)}
    result["fingerprint_sha1"] = fingerprint_sha1
    result["fingerprint_sha256"] = cert.fingerprint(hashes.SHA256()).hex()
    result["not_before"] = cert.not_valid_before_utc
    result["not_after"] = cert.not_valid_after_utc
    try:
        result["CN"] = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        result["common_name"] = result["CN"].lower()
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    try:
        result["issuer"] = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
        result["issuer_subject"] = str(cert.issuer)
    except Exception:  # pylint: disable=broad-exception-caught
        pass
    try:
        names = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        result["names"] = []
        for name in names.value.get_values_for_type(x509.DNSName):
            result["names"].append(name.lower())
    except x509.ExtensionNotFound:
        result["names"] = []
    try:
        subject_key_id = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.SUBJECT_KEY_IDENTIFIER
        ).value
        result["subjectKeyId"] = subject_key_id.digest.hex()
    except x509.ExtensionNotFound:
        result["subjectKeyId"] = None
    try:
        authority_key_id = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        ).value
        result["authorityKeyId"] = authority_key_id.key_identifier.hex()
    except x509.ExtensionNotFound:
        result["authorityKeyId"] = None
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.BASIC_CONSTRAINTS
        ).value
        result["CA"] = basic_constraints.ca
    except x509.ExtensionNotFound:
        result["CA"] = False
    try:
        cert.extensions.get_extension_for_oid(x509.ExtensionOID.PRECERT_POISON)
        result["precert"] = True
    except Exception:  # pylint: disable=broad-exception-caught
        result["precert"] = False
    if result["CA"] and not result["authorityKeyId"] \
            and "issuer_subject" in result \
            and result["issuer_subject"] == str(cert.subject):
        result["RootCA"] = True
    elif result["CA"] \
            and result["authorityKeyId"] and result["subjectKeyId"] \
            and result["authorityKeyId"] == result["subjectKeyId"]:
        result["RootCA"] = True
    else:
        result["RootCA"] = False
    if "issuer_subject" in result \
            and result["issuer_subject"] == str(cert.subject):
        result["self-signed"] = True
    else:
        result["self-signed"] = False

    # Public key modulus / EC points as bytes
    if isinstance(cert.public_key(), RSAPublicKey):
        n = cert.public_key().public_numbers().n
        n = n.to_bytes((n.bit_length() + 7) // 8, "big")
        result["modulus_SHA1"] = sha1(n).hexdigest()
    elif isinstance(cert.public_key(), EllipticCurvePublicKey):
        x = cert.public_key().public_numbers().x
        y = cert.public_key().public_numbers().y
        x = x.to_bytes((x.bit_length() + 7) // 8, "big")
        y = y.to_bytes((y.bit_length() + 7) // 8, "big")
        result["modulus_SHA1"] = sha1(x+y).hexdigest()

    return result


def cert_to_pem(certificate: str|bytes|memoryview) -> str:
    """Convert memory view or DER encoded cert to PEM encoding

    Args:
        certificate (str|bytes|memoryview): certificate

    Returns:
        str: PEM encoded certificate
    """

    if isinstance(certificate, memoryview):
        certificate = certificate.tobytes()

    if isinstance(certificate, bytes):
        search_re = b"-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----"
    else:
        search_re = "-----BEGIN CERTIFICATE-----\r?\n.+?\r?\n-----END CERTIFICATE-----"

    if re.search(search_re, certificate, re.DOTALL) is None:
        certificate = x509.load_der_x509_certificate(certificate, default_backend())
        return certificate.public_bytes(serialization.Encoding.PEM)
    if isinstance(certificate, bytes):
        return certificate
    else:
        return certificate.encode()


def store_cert(cert_dir: str, fingerprint_sha1: str, cert: str|bytes|memoryview):
    """Store a certficate in a file

    Args:
        cert_dir (str): Directory containing PEM certificates
        fingerprint_sha1 (str): SHA1 fingerprint hash of certificate
        cert (str|bytes|memoryview): Certificate (will be converted to PEM)
    """
    cert = cert_to_pem(cert)

    logger.debug("storeCert: %s", fingerprint_sha1)
    cert_dir = Path(cert_dir)
    if not cert_dir.is_dir():
        raise ValueError(f"cert_dir \"{cert_dir}\" does not exist")

    certfile = cert_dir / f"{fingerprint_sha1}.pem"
    # don't clobber files
    if not certfile.is_file():
        logger.debug("storeCert: Creating %s", certfile)
        certfile.write_bytes(cert)
    else:
        logger.info("storeCert: %s already exists, not saved", certfile)
        return


def load_cert(cert_dir: str, fingerprint_sha1: str) -> bytes:
    """Load the certficate from file.

    Args:
        cert_dir (str): Directory containing PEM certificates
        fingerprint_sha1 (str): SHA1 hash fingerprint of certificate

    Returns:
        bytes: File contents (should be a PEM encoded cert)
    """

    logger.debug("load_cert: %s", fingerprint_sha1)
    cert_dir = Path(cert_dir)
    if not cert_dir.is_dir():
        raise ValueError(f"cert_dir \"{cert_dir}\" does not exist")

    certfile = cert_dir / f"{fingerprint_sha1}.pem"

    try:
        return certfile.read_bytes()
    except FileNotFoundError:
        logger.debug("load_cert: No such file %s", certfile)
        return None


def delete_cert(cert_dir: str, fingerprint_sha1: str) -> bool:
    """Delete the certficate file from the filesystem.

    Args:
        cert_dir (str): Directory containing PEM certificates
        fingerprint_sha1 (str): SHA1 hash fingerprint of certificate

    Returns:
        bool: True if file was deleted, False if file didn't exist
    """

    logger.debug("deleteCert: %s", fingerprint_sha1)
    cert_dir = Path(cert_dir)
    if not cert_dir.is_dir():
        raise ValueError(f"cert_dir \"{cert_dir}\" does not exist")

    certfile = cert_dir / f"{fingerprint_sha1}.pem"

    try:
        certfile.unlink()
        logger.debug("deleteCert: Deleted file %s", certfile)
        return True
    except FileNotFoundError:
        logger.warning("deleteCert: No such file %s", certfile)
        return False


def split_pem(fullchain: str) -> list[str]:
    """Split PEM fullchain into list of PEM certs

    Args:
        fullchain (str): concatenated cert + chain

    Returns:
        list: list of PEM encoded cert strings
    """

    if isinstance(fullchain, str):
        fullchain = fullchain.encode()

    return CERT_PEM_REGEX.findall(fullchain)


def split_fullchain(fullchain: str) -> list[dict]:
    """Split PEM fullchain into list of certs

    Args:
        fullchain (str): concatenated cert + chain

    Returns:
        list: list of cert_detail dicts
    """
    # First pass: find the boundary of each certificate in the chain.
    # TODO: This will silently skip over any "explanatory text" in between boundaries,
    # which is prohibited by RFC8555.

    result = []
    for certificate in split_pem(fullchain):
        cert = get_cert_detail(certificate)
        cert["pem"] = certificate
        result.append(cert)

    return result


def fullchain_to_p7b(fullchain: list[dict]) -> bytes:
    """Generate a PKCS#7 file from a chain of certs

    Args:
        fullchain (list[dict]): list of cert_detail dicts containing "PEM" attr

    Returns:
        bytes: certificate chain in PKCS#7 format including the Root CA
    """
    pemchain = NamedTemporaryFile("w+b")
    for cert in fullchain:
        if isinstance(cert["PEM"], str):
            cert["PEM"] = cert["PEM"].encode()
        pemchain.write(cert["PEM"])

    p7b = subprocess.run(
        ["openssl", "crl2pkcs7", "-nocrl", "-certfile", pemchain.name],
        capture_output=True, check=True
    )
    if p7b.returncode != 0:
        logger.error("External openssl crl2pkcs7 command returned an error")

    return p7b.stdout


# pylint: disable-next=dangerous-default-value
def create_zip_bundle(
        filename: str,
        fullchain: str,
        textfragments: dict = {}
    ) -> bytes:
    """Generate a Zip blob from a certificate chain

    Args:
        filename (str): filename (without extension)
        fullchain (list[dict]): list of cert_detail dict with "PEM" attr
        textfragments (dict, optional): textfragments dict 
            {"filename.txt": "plaintext blob",}. Defaults to {}.

    Returns:
        bytes: ZIP blob
    """
    files = {}

    p7b = fullchain_to_p7b(fullchain)
    files[f"{filename}.p7b"] = p7b

    pemchain = b""
    for cert in fullchain:
        if pemchain == b"":
            certname = filename
        else:
            certname = clean_name(cert["CN"])
        if "IsRoot" not in cert:
            if isinstance(cert["PEM"], str):
                pemchain += cert["PEM"].encode()
            else:
                pemchain += cert["PEM"]
        files[f"{certname}.cer"] = cert["PEM"]

    if isinstance(fullchain, str):
        fullchain = fullchain.encode()

    files[f"{filename}_fullchain.cer"] = pemchain
    files.update(textfragments)

    zipblob = create_zip_blob(files)
    return zipblob
