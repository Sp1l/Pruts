"""Functions to deal with CSR files and PKCS#10 blobs"""

import re

from os import path, remove

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.x509.oid import AttributeOID, ExtensionOID, NameOID

from django.conf import settings

import logging

logger = logging.getLogger(__name__)

def sha1(data) -> str:
    """Genererate a SHA1 hash from a bytestring

    Args:
        data (bytes): blob to hash

    Returns:
        str: SHA1 hex string of data
    """
    digest = hashes.Hash(hashes.SHA1())
    digest.update(data)
    return digest.finalize().hex()


def csr_to_der(signing_request: str) -> bytes:
    """Convert a PEM encoded CSR (AKA PKCS#10) to DER

    Args:
        signing_request (str): PEM encoded CSR

    Returns:
        bytes: DER encoded CSR
    """

    if isinstance(signing_request, str):
        signing_request = signing_request.encode("utf-8")

    return x509.load_pem_x509_csr(signing_request).public_bytes(serialization.Encoding.DER)


def validate_csr(signing_request) -> dict:
    """Check if this CSR can be signed successfully by LetsEncrypt

    Args:
        signing_request (dict): Signing Request details

    Returns:
        dict: issues["LEVEL"]["message"] (none if no validation isssues)
    """

    dns1 = settings.DNS
    dns2 = settings.DNS2

    def resolve(hostname: str):
        """Try to resolve using both resolvers"""
        result = dns1.resolve(hostname)
        if result is None and dns2 is not None:
            return dns2.resolve(hostname)
        return result

    def zone_for_name(hostname: str):
        """Try to determine the start-of-authority for hostname"""
        result = dns1.zone_for_name(hostname)
        if result is None and dns2 is not None:
            return dns2.zone_for_name(hostname)
        return result

    def is_fqdn(hostname: str) -> bool:
        """https://en.m.wikipedia.org/wiki/Fully_qualified_domain_name"""
        # pylint: disable-next=line-too-long
        return re.match(r"^(?!.{255}|.{253}[^.])([a-z0-9](?:[-a-z-0-9]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?[.]?$", hostname, re.IGNORECASE)

    result = {"FATAL": [], "WARN": []}  # to collect issues in

    # Check signature
    if not signing_request["CSR"].is_signature_valid:
        result["FATAL"] += ["Invalid signature (modified CSR)"]

    # Check hash algorithm
    hashalgo = signing_request["CSR"].signature_hash_algorithm.name
    if hashalgo == "sha1":
        result["FATAL"] += [f"Invalid hash algorithm '{hashalgo}' (use SHA256)"]

    # Check key size
    if signing_request["pubkeyType"] == "RSA" and signing_request["pubkeySize"] < 2048:
        result["FATAL"] += [f'{signing_request["pubkeySize"]}-bit RSA key too small (minumum 2048)']

    # Check common_name
    if signing_request["common_name"] is not None:
        common_name = signing_request["common_name"]
        if common_name[:2] == "*.":
            result["WARN"] += [f"Common Name {common_name} is a wildcard"]
        elif resolve(common_name) is None:
            result["WARN"] += [f"Common Name {common_name} does not resolve"]
        if not is_fqdn(common_name.removeprefix("*.")):
            result["FATAL"] += [f"Common Name {common_name} is not a valid FQDN"]
        soa = zone_for_name(common_name)
        if soa not in settings.DDICONF["SOAmname"]:
            result["FATAL"] += [f"{common_name} is not DDI managed ({soa})"]

    # Check SANs
    if len(signing_request["SubjectAltNames"]) == 0 and signing_request["common_name"] is None:
        result["FATAL"] += [
            "Signing Request must have at least one of CommonName and SubjectAltName"
        ]
    for subject_alt_name in signing_request["SubjectAltNames"]:
        if subject_alt_name[:2] == "*.":
            result["WARN"] += [f"Subject Alternative Name {common_name} is a wildcard"]
        elif resolve(subject_alt_name) is None:
            result["WARN"] += [
                f"Subject Alternative Name {subject_alt_name} does not resolve"
            ]
        if not is_fqdn(subject_alt_name.removeprefix("*.")):
            result["FATAL"] += [f"Subject Alternative Name {subject_alt_name} is not a valid FQDN"]
        soa = zone_for_name(subject_alt_name)
        if soa  not in settings.DDICONF["SOAmname"]:
            result["FATAL"] += [f"{common_name} is not DDI managed ({soa})"]

    if "SubjectAltIPs" in signing_request:
        result["FATAL"] += [
            f'IP Address not supported in ACME ({signing_request["SubjectAltIPs"]})'
        ]

    if result != {"FATAL": [], "WARN": []}:
        return result
    else:
        return None


def parse_pkcs10(pkcs10, lint: bool = True) -> dict:
    """Parse a PKCS#10 Certificate SigningRequest (PEM)
    and extract relevant attributes

    Args:
        pkcs10 (str|bytes|x509.CertificateSigningRequest): CSR
        lint (bool, optional): Check for issues. Defaults to True.

    Returns:
        dict: Details of the signing request
            CSR:            x509.CertificateSigningRequest object
            SHA1:           SHA1 hash of DER-encoded CSR
            signature_SHA1: SHA1 hash of CSR's signature
            modulus_SHA1:   SHA1 hash of CSR's public key modulus
            common_name:    commonName attribute from CSR Subject
            SANs:           list of SubjectAlternativeNames from CSR
            issues:         dict of errors and warnings about CSR (if lint=True)
            isvalid:        True or False, None if lint = False
    """

    if isinstance(pkcs10, str):
        pkcs10 = pkcs10.encode()
    if isinstance(pkcs10, x509.base.CertificateSigningRequest):
        signing_request = pkcs10
    else:
        signing_request = x509.load_pem_x509_csr(pkcs10)

    result = {}
    result["CSR"] = signing_request
    result["SHA1"] = sha1(signing_request.public_bytes(serialization.Encoding.DER))

    # Signature is unique
    result["signature_SHA1"] = sha1(signing_request.signature)
    # Public key modulus / EC points as bytes
    if isinstance(signing_request.public_key(), rsa.RSAPublicKey):
        result["pubkeyType"] = "RSA"
        result["pubkeySize"] = signing_request.public_key().key_size
        n = signing_request.public_key().public_numbers().n
        n = n.to_bytes((n.bit_length() + 7) // 8, "big")
        result["modulus_SHA1"] = sha1(n)
    elif isinstance(signing_request.public_key(), EllipticCurvePublicKey):
        result["pubkeyType"] = signing_request.public_key().curve.name
        result["pubkeySize"] = signing_request.public_key().key_size
        x = signing_request.public_key().public_numbers().x
        y = signing_request.public_key().public_numbers().y
        x = x.to_bytes((x.bit_length() + 7) // 8, "big")
        y = y.to_bytes((y.bit_length() + 7) // 8, "big")
        result["modulus_SHA1"] = sha1(x + y)

    try:
        common_name = signing_request.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        if len(common_name) > 0:
            result["common_name"] = common_name[0].value
        else:
            result["common_name"] = None
    except x509.ExtensionNotFound:
        result["common_name"] = None

    try:
        result["SubjectAltNames"] = signing_request.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        result["SubjectAltNames"] = []
    try:
        subject_alt_ip = signing_request.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.IPAddress)
        if len(subject_alt_ip) != 0:
            result["SubjectAltIPs"] = subject_alt_ip
    except x509.ExtensionNotFound:
        pass

    if lint:
        try:
            result["issues"] = validate_csr(result)
        # pylint: disable-next=broad-exception-caught
        except Exception as e:
            logger.error("Exception from validate_csr: %s", e)
            result["issues"] = {"FATAL": ["Unexpected error during validation, " \
                + "contact administrators."], "WARN": []}
        if result["issues"] is not None and result["issues"]["FATAL"] != []:
            result["isvalid"] = False
        else:
            result["isvalid"] = True
    else:
        result["isvalid"] = None

    return result


def store_csr(fingerprint_sha1, pkcs10) -> (str | None):
    """Store a certficate in a file

    Args:
        fingerprint_sha1 (str): SHA1 hash of the CSR
        pkcs10 (str|bytes): Certificate Signing Request (will be converted to PEM)
    
    Returns:
        str:    Path to CSR if file was stored
    """

    logger.debug("storeCSR: %s", fingerprint_sha1)
    certfile = path.join(settings.DIRS["CSRs"], fingerprint_sha1 + ".pem")
    # don't clobber files
    if not path.isfile(certfile):
        logger.debug("storeCSR: Creating %s", certfile)
        outfile = open(certfile, "w+b")
        outfile.write(pkcs10.encode())
        outfile.close()
        return str(certfile)
    else:
        logger.debug("storeCSR: %s already exists", certfile)
        return None


def load_csr(fingerprint_sha1: str, encoding: str = "PEM") -> (bytes | None):
    """Load the certficate from file

    Args:
        fingerprint_sha1 (str): SHA1 hash fingerprint of certificate
        encoding ("DER"|"PEM"): encoding to return CSR in. Defaults to "PEM"

    Returns: 
        bytes: File contents
    """

    logger.debug("loadCSR: %s", fingerprint_sha1)
    certfile = path.join(settings.DIRS["CSRs"], fingerprint_sha1 + ".pem")

    if path.isfile(certfile):
        with open(certfile, "r+b") as handle:
            contents = handle.read()
    else:
        logger.debug("loadCSR: No file for %s", fingerprint_sha1)
        return None

    return csr_to_der(contents) if encoding == "DER" else contents


def delete_csr(fingerprint_sha1) -> bool:
    """Delete the certficate file from the filesystem if it exists

    Args:
        fingerprint_sha1 (str): SHA1 hash fingerprint of certificate

    Returns
        bool: True if deleted, False if file not found
    """

    logger.debug("deleteCSR: %s", fingerprint_sha1)
    certfile = path.join(settings.DIRS["CSRs"], fingerprint_sha1 + ".pem")

    if path.isfile(certfile):
        remove(certfile)
        logger.debug("deleteCSR: Deleted file %s", certfile)
        return True
    else:
        logger.debug("deleteCSR: No such file %s", certfile)
        return False


def create_random_csr(common_namea: str, sans: list):
    """Generate a CSR for testing

    Args:
        common_namea (str): CommonName for CSR
        sans (list): Subject Alternative Names for CSR

    Returns:
        str: PEM encoded Certificate Signing Request (PKCS#10)
    """
    # https://cryptography.io/en/latest/x509/reference/#x-509-csr-certificate-signing-request-builder-object

    # Generate a temporary private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    builder = x509.CertificateSigningRequestBuilder()
    if common_namea is not None:
        builder = builder.subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.COMMON_NAME, common_namea),
                ]
            )
        )
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True,
    )
    builder = builder.add_attribute(AttributeOID.CHALLENGE_PASSWORD, b"changeit")
    dns_names = x509.SubjectAlternativeName(
        [x509.DNSName(subject_alt_name) for subject_alt_name in sans]
    )
    if sans is not None:
        builder = builder.add_extension(dns_names, critical=False)

    signing_request = builder.sign(private_key, hashes.SHA256())
    return signing_request.public_bytes(serialization.Encoding.PEM)

