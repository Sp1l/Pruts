"""Interact with crt.sh"""

# https://github.com/malvidin/crt.sh/blob/master/crtsh.py

# Bundled
import re
from datetime import datetime

# pip
import psycopg2
from psycopg2.extras import DictCursor

import logging
logger = logging.getLogger(__name__)


class CrtSh:
    """Interact with crt.sh to find certificates and CA's
    Process crt.sh certificate results
    """

    def __init__(self):
        self.stmt_find_by_name = None
        self.stmt_get_cert_by_sha1 = None
        self.stmt_get_by_serial = None
        self.stmt_get_cert_by_id = None
        self.stmt_get_ca_by_name = None
        self.stmt_get_ca_by_id = None
        self.stmt_get_by_authkeyid = None

        self._connect_certwatch()
        self._setup_cursor()
        self.execend = datetime.now()

        self.clean_str = re.compile(" +")

    def _connect_certwatch(self):
        """Connect to crt.sh PostgreSQL database"""

        self.conn = psycopg2.connect(
            dbname="certwatch",
            user="guest",
            host="crt.sh",
            cursor_factory=DictCursor,
        )
        self.conn.set_session(readonly=True, autocommit=True)

    def _setup_cursor(self, dup=False):
        """Initialize cursor for interacting with DB

        Args:
            dup (bool): Reliability: try again in case of error.
        """
        try:
            self.cur = self.conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            self.curstart = datetime.now()
        except psycopg2.InterfaceError:
            self._connect_certwatch()
            if not dup:
                self._setup_cursor(dup=True)
            else:
                raise

    def _cur_exec(self, statement, params):
        """Execute statement in DB with retries

        Args:
            statement (str): The SQL statement
            params (tuple): Late-binding parameters for statement

        Returns:
            bool: True if execute returned no errors
        """
        depth = 1
        while depth < 6:
            try:
                self.cur.execute(statement, params)
                self.execend = datetime.now()
                return True
            except Exception as e:
                if str(e) == "SSL connection has been closed unexpectedly\n":
                    duration = datetime.now() - self.execend
                    seconds = duration.total_seconds()
                    logger.warning("_cur_exec depth: Connection timeout %ss", seconds)
                elif e.pgcode == "40001":
                    logger.debug("_cur_exec depth: %s: Recovery conflict", depth)
                else:
                    msg = (
                        self.clean_str.sub(" ", statement[:100].replace("\n", " ").strip())
                        + ": " + str(e).strip()
                    )
                    logger.error("_cur_exec depth %s: %s", depth, msg)
                self._setup_cursor()
            depth += 1
        return False

    def get_ca_by_authkeyid(self, auth_key_id: str) -> dict:
        """Get a CertificateAuthority from crt.sh by Authority Key Id

        Args:
            auth_key_id (str): hex representation of Auth Key

        Returns: 
            dict: from crt.sh ca table
        """

        if not self.stmt_get_by_authkeyid:
            self.stmt_get_by_authkeyid = """SELECT ca.ID ca_id, cert.ID crtsh_id,
                    cert.ISSUER_CA_ID, ca.NAME, ca.NUM_ISSUED, ca.NUM_EXPIRED,
                    ca.LAST_NOT_AFTER, ca.NEXT_NOT_AFTER, 
                    x509_notBefore(cert.CERTIFICATE) NOT_BEFORE,
                    x509_notAfter(cert.CERTIFICATE) NOT_AFTER,
                    cert.CERTIFICATE
                FROM  certificate cert,
                      ca
                WHERE x509_subjectKeyIdentifier(cert.CERTIFICATE) = decode(%s, 'hex')
                  AND x509_publicKey(cert.certificate) = ca.PUBLIC_KEY;"""

        self._setup_cursor()

        result = self._cur_exec(self.stmt_get_by_authkeyid, (auth_key_id,))

        # We potentially get multiple certs
        # extract the cert with latest expiry date
        ca = {}
        for row in self.cur.fetchall():
            if not ca or row["not_after"] > ca["not_after"]:
                ca = row
            #     continue

        return {"result": result, "CertificateAuthority": ca}

    def get_ca_by_id(self, ca_id: int) -> dict:
        """Get a CertificateAuthority from crt.sh by id

        Args:
            ca_id (int): crt.sh Certificate Authority id

        Returns:
            tuple: crt.sh ca tuple
        """

        logger.info("get_ca_by_id: processing %s", ca_id)

        if not self.stmt_get_ca_by_id:
            self.stmt_get_ca_by_id = """SELECT ca.ID ca_id, cert.ID crtsh_id,
                    cert.ISSUER_CA_ID, ca.NAME, ca.NUM_ISSUED, ca.NUM_EXPIRED,
                    ca.LAST_NOT_AFTER, ca.NEXT_NOT_AFTER, cert.CERTIFICATE
                FROM   ca, ca_certificate catocert, certificate cert
                WHERE  ca.ID = %s
                AND  ca.ID = catocert.CA_ID
                AND  catocert.CERTIFICATE_ID = cert.ID"""

        result = self._cur_exec(self.stmt_get_ca_by_id, (str(ca_id),))

        row = {}
        for key, value in self.cur.fetchone().items():
            row[key] = value

        return {"result": result, "CertificateAuthority": row}

    def get_ca_by_name(self, name: str) -> dict:
        """Get a CertificateAuthority from crt.sh by name

        Args:
            name (str): Common Name of certificate authority

        Returns: 
            dict: from crt.sh ca table
        """

        logger.info("get_ca_by_name: processing %s", name)

        if not self.stmt_get_ca_by_name:
            self.stmt_get_ca_by_name = """SELECT ca.ID ca_id, cert.ID crtsh_id,
                    cert.ISSUER_CA_ID, ca.NAME, ca.NUM_ISSUED, ca.NUM_EXPIRED,
                    ca.LAST_NOT_AFTER, ca.NEXT_NOT_AFTER, cert.CERTIFICATE
                FROM   ca, ca_certificate catocert, certificate cert
                WHERE  lower(ca.NAME) = lower(%s)
                AND  ca.ID = catocert.CA_ID
                AND  catocert.CERTIFICATE_ID = cert.ID"""

        result = self._cur_exec(self.stmt_get_ca_by_name, (str(name),))

        row = {}
        for key, value in self.cur.fetchone().items():
            row[key] = value

        return {"result": result, "CertificateAuthority": row}

    def get_cert_by_id(self, crtsh_id: int) -> tuple:
        """Retrieve a certificate by crtsh_id

        Args: 
            crtsh_id (int): crt.sh cert id to retrieve

        Returns: 
            dict: { crtsh_id (int): crtsh certificate id
                    timestamp (datetime): first entry timestamp
                    ca_id (int): crtsh CA id
                    certficate (memoryview): blob
                  }
        """

        logger.debug("get_cert_by_id: %s", crtsh_id)

        if self.stmt_get_cert_by_id is None:
            self.stmt_get_cert_by_id = """SELECT DISTINCT
                ci.ID crtsh_id,
                le.MIN_ENTRY_TIMESTAMP created,
                ci.ISSUER_CA_ID ca_id,
                ci.CERTIFICATE certificate
            FROM certificate ci
                LEFT JOIN LATERAL (
                    SELECT min(ctle.ENTRY_TIMESTAMP) MIN_ENTRY_TIMESTAMP
                    FROM ct_log_entry ctle
                    WHERE ctle.CERTIFICATE_ID = ci.id
                ) le ON TRUE
            WHERE ci.ID = %s ;"""
        self._setup_cursor()

        self.cur.execute(self.stmt_get_cert_by_id, (str(crtsh_id),))
        return self.cur.fetchone()

    def get_cert_by_name(self, domainname: str, last_updated: datetime) -> list:
        """Get certificate results for domainname from crt.sh.

        Args:
            domainname (str): name to search for
            lastUpdated (datetime): search only for certs registered after date

        Returns: 
            dict: { 
                status (bool): True if we have a result
                rows (list):
                    * crtsh_id (int)
                    * timestamp (datetime)
                    * CA id (int)
                    * certificate (memoryview)
            }
        """

        logger.debug("get_cert_by_name: processing %s", domainname)

        if not self.stmt_find_by_name:
            if isinstance(last_updated, datetime):
                self.stmt_find_by_name = """SELECT DISTINCT
                    cai.CERTIFICATE_ID crtsh_id,
                    le.MIN_ENTRY_TIMESTAMP created,
                    cai.ISSUER_CA_ID ca_id,
                    cai.CERTIFICATE certificate
                FROM certificate ci,
                    unnest(identities(certificate)),
                    certificate_and_identities cai
                    LEFT JOIN LATERAL (
                        SELECT min(ctle.ENTRY_TIMESTAMP) MIN_ENTRY_TIMESTAMP
                        FROM ct_log_entry ctle
                        WHERE ctle.CERTIFICATE_ID = ci.id
                    ) le ON TRUE
                WHERE cai.CERTIFICATE_ID = ci.id
                AND identities(ci.certificate) @@ %s
                AND le.MIN_ENTRY_TIMESTAMP > %s
                AND coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp)
                    >= date_trunc('year', now() AT TIME ZONE 'UTC')
                AND x509_notafter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC';"""
            else:
                # Same without le.MIN_ENTRY_TIMESTAMP filter
                self.stmt_find_by_name = """SELECT DISTINCT
                    cai.CERTIFICATE_ID crtsh_id,
                    le.MIN_ENTRY_TIMESTAMP created,
                    cai.ISSUER_CA_ID ca_id,
                    cai.CERTIFICATE certificate
                FROM certificate ci,
                    unnest(identities(certificate)),
                    certificate_and_identities cai
                    LEFT JOIN LATERAL (
                        SELECT min(ctle.ENTRY_TIMESTAMP) MIN_ENTRY_TIMESTAMP
                        FROM ct_log_entry ctle
                        WHERE ctle.CERTIFICATE_ID = ci.id
                    ) le ON TRUE
                WHERE cai.CERTIFICATE_ID = ci.id
                AND identities(ci.certificate) @@ %s
                AND coalesce(x509_notAfter(cai.CERTIFICATE), 'infinity'::timestamp)
                    >= date_trunc('year', now() AT TIME ZONE 'UTC')
                AND x509_notafter(cai.CERTIFICATE) >= now() AT TIME ZONE 'UTC';"""

        if isinstance(last_updated, datetime):
            result = self._cur_exec(self.stmt_find_by_name, (domainname, last_updated))
        else:
            result = self._cur_exec(self.stmt_find_by_name, (domainname,))

        if result:
            return {"status": result, "rows": self.cur.fetchall()}
        else:
            return {"status": result, "rows": []}

    def get_cert_by_serial(self, serial: str) -> list:
        """Retrieve certificates by Serial Number

        Args:
            serial (str): Serial number as hex string

        Returns: 
            list of OrderedDict {
                crtsh id,
                created,
                CA id and
                certificate blob
                }
        """

        logger.debug("get_cert_by_serial: %s", serial)

        if not self.stmt_get_by_serial:
            self.stmt_get_by_serial = """SELECT c.ID crtsh_id,
                le.ENTRY_TIMESTAMP created,
                c.ISSUER_CA_ID ca_id,
                c.CERTIFICATE certificate
                FROM certificate c
                        LEFT JOIN LATERAL (
                            SELECT min(ctle.ENTRY_TIMESTAMP) ENTRY_TIMESTAMP
                                FROM ct_log_entry ctle
                                WHERE ctle.CERTIFICATE_ID = c.ID
                        ) le ON TRUE
                WHERE x509_serialNumber(c.CERTIFICATE) = %s
                ORDER BY le.ENTRY_TIMESTAMP DESC NULLS LAST;"""
        # WHERE x509_serialNumber(c.CERTIFICATE) = decode(%s, 'hex')

        # Fixups to make sure we have a valid Hex string
        serial = serial.replace(":", "").removeprefix("0x")
        if len(serial) % 2 == 1:
            serial = "0" + serial
        try:
            serial = bytes.fromhex(serial)
        except Exception:
            logger.error("get_cert_by_serial: %s is not a valid Hex string", serial)
            return None

        self._setup_cursor()

        self._cur_exec(self.stmt_get_by_serial, (serial,))

        return self.cur.fetchall()

    def get_cert_by_sha1(self, sha1: str) -> tuple:
        """Retrieve certificate from crt.sh by SHA1

        Args:
               sha1 (str): SHA1 hex string
            or list of sha1 hex strings

        Returns: list  with crtsh_id, timestamp, CA id and
                 certificate blob
                 OR None
        """

        logger.debug("get_cert_by_sha1: %s", sha1)

        if not self.stmt_get_cert_by_sha1:
            self.stmt_get_cert_by_sha1 = """SELECT DISTINCT
                ci.ID crtsh_id,
                le.MIN_ENTRY_TIMESTAMP created,
                ci.ISSUER_CA_ID ca_id,
                ci.CERTIFICATE certificate
            FROM certificate ci
            LEFT JOIN LATERAL (
                    SELECT min(ctle.ENTRY_TIMESTAMP) MIN_ENTRY_TIMESTAMP
                    FROM ct_log_entry ctle
                    WHERE ctle.CERTIFICATE_ID = ci.id
                ) le ON TRUE
            WHERE digest(CERTIFICATE, 'sha1') IN %s ;"""

        hashes = []
        if isinstance(sha1, str):
            hashes.append(bytes.fromhex(sha1))
        else:
            for item in sha1:
                hashes.append(bytes.fromhex(item))
        hashes = tuple(hashes)

        self._setup_cursor()

        self._cur_exec(self.stmt_get_cert_by_sha1, (hashes,))

        return self.cur.fetchone()

