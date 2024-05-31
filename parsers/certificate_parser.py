import csv
import datetime
import re
import time

import OpenSSL

from difflib import SequenceMatcher
from loguru import logger

from utils.constants import DATETIME_FORMAT
from utils.util_functions import convert_float_to_str

def get_trusted_list()-> dict:
    """
        Get the list of trusted CAs.
        Trusted CAs are extracted from trusted CA lists of high reputation CA stores
        Currently we are using one from Mozilla(Firefox): https://wiki.mozilla.org/CA/Included_Certificates

        :return: Lists of trusted CA issuers.
    """
    trusted_list = set()
    with open("input_files/IncludedCACertificateWithPEMReport.csv", "r")as input_file:
        reader = csv.DictReader(input_file, delimite=",", quotechar='"')
        for row in reader:
            if "Owner" in row:
                trusted_list.add(row["Owner"].strip().lower())
            if "Certificate Issuer Organization" in row:
                trusted_list.add(row["Certificate Issuer Organization"].strip().lower())
            if "Certificate Issuer Organizational Unit" in row:
                trusted_list.add(row["Certificate Issuer Organizational Unit"].strip().lower())
            if "Common Name or Certificate Name" in row:
                trusted_list.add(row["Common Name or Certificate Name"].strip().lower())
    logger.info("Trusted list extracted from Mozilla truststore is {}", trusted_list)
    return trusted_list
class CertificateParser(object):
    """
    Parse a PEM encoded certificate and get the information about the certificate

    :param url: The url whose certificate raw data is going to be parsed
    :param pem_cert_str: The PEM-encoded certificate string
    :param timestamp: The timestamp stored in dynamoDB when the certificate was collected
    """
    PROHIBITED_LIST = {
        'local_network' :[
            '(?:10|127|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\..*',
            'localhost'
        ],
        'wildcard' : ['*'],
    }
    TRUSTED_LIST = get_trusted_list()

    def __init__(self):
        pass
    def get_info(self,url, pem_cert_str, timestamp):
        logger.info("Processing url {}, certificate {}", url, pem_cert_str)
        info_dict = {
            "origin_url": url,
            "cert_issuer": {
                "common_name": "None",
                "organization_name": "None",
                "country_name": "None",
                "state_name": "None",
                "organizational_unit": "None",
                "locality": "None",
                "email_addr": "None",
            },
            "has_issuer_o": -1,
            "has_issuer_ou": -1,
            "has_issuer_cn": -1,
            "has_issuer_st": -1,
            "has_issuer_l": -1,
            "has_issuer_email": -1,
            "cert_subject": {
                "common_name": "None",  # commonName
                "organization_name": "None",  # organizationName
                "country_name": "None",  # countryName
                "state_name": "None",  # stateOrProvinceName
                "organization_unit": "None",  # organizationalUnitName
                "locality": "None",  # localityName
                "email_addr": "None",  # emailAddress,
        },
            "has_subject_o": -1,
            "has_subject_cn": -1,
            "has_subject_st": -1,
            "has_subject_ou": -1,
            "has_subject_l": -1,
            "has_subject_email": -1,
            "is_trusted_ca": -1,
            "is_prohibited_issuer": -1,
            "is_prohibited_subject": -1,
            "cert_serial_number": "",
            "len_serial_num": -1,
            "cert_version": -1,
            "cert_validate_time_not_before": "None",
            "cert_validate_time_not_after": "None",
            "has_expired": -1,
            "signature_algorithm": "None",
            "extension_count": -1,
            "extended_key_usage": -1,
            "authority_info_access": -1,
            "subject_key_identifier": -1,
            "basic_constraints": -1,
            "authority_key_identifier": -1,
            "certificate_policies": -1,
            "crl_distribution_points": -1,
            "is_extended_validation": -1,
            "freshest_crl": -1,
            "subject_alt_name": "None",
            "has_subject_alt_name": -1,
            "issuer_alt_name": -1,
            "key_usage": -1,
            "subject_directory_attributes": -1,
            "not_common_extension_count": -1,

            # critical fields or not
            "extended_key_usage_critical": -1,
            "authority_info_access_critical": -1,
            "subject_key_identifier_critical": -1,
            "basic_constraints_critical": -1,
            "authority_key_identifier_critical": -1,
            "certificate_policies_critical": -1,
            "crl_distribution_points_critical": -1,
            "is_extended_validation_critical": -1,
            "freshest_crl_critical": -1,
            "subject_alt_name_critical": -1,
            "issuer_alt_name_critical": -1,
            "key_usage_critical": -1,
            "subject_directory_attributes_critical": -1,
            "diff_not_before_timestamp": -1,
            "diff_not_after_timestamp": -1,
            "diff_not_before_notafter": -1,
            "match_website_altname": -1,
            "match_website_subjectcn": -1,
            "match_issuer_o_cn": -1,
            "match_issuer_subject_cn": -1,
            "match_issuer_subject_c": -1,
            "match_website_issuercn": -1,
            "match_subject_o_cn": -1,
            "match_issuer_o_ou": -1,
            "match_subject_o_ou": -1,
        }
        if "END CERTIFICATE" not in pem_cert_str:
            logger.info("Certificate for {} is not complete, certificate is {}", url, pem_cert_str)
            return info_dict
        info_dict["origin_url"] = url
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert_str)

        issuer = x509.get_issuer().getcomponents()
        issuer_info = dict()
        self.parse_identity_components(issuer, info_dict)

        info.dict["cert_issuer"] = issuer_info
        info_dict["has_issuer_o"] = 1 if issuer_info["O"] != "None" else 0
        info_dict["has_issuer_ou"] = 1 if issuer_info["OU"] != "None" else 0
        info_dict["has_issuer_cn"] = 1 if issuer_info["CN"] != "None" else 0
        info_dict["has_issuer_st"] = 1 if issuer_info["ST"] != "None" else 0
        info_dict["has_issuer_l"] = 1 if issuer_info["L"] != "None" else 0
        info_dict["has_issuer_email"] = 1 if issuer_info["email"] != "None" else 0

        subject = x509.get_subject().getcomponents()
        subject_info = dict()
        self.parse_identity_components(subject, subject_info)

        info.dict["cert_subject"] = subject_info
        info_dict["has_subject_o"] = 1 if subject_info["O"] != "None" else 0
        info_dict["has_subject_ou"] = 1 if subject_info["OU"] != "None" else 0
        info_dict["has_subject_cn"] = 1 if subject_info["CN"] != "None" else 0
        info_dict["has_issuer_st"] = 1 if subject_info["ST"] != "None" else 0
        info_dict["has_issuer_l"] = 1 if subject_info["L"] != "None" else 0
        info_dict["has_subject_email"] = 1 if subject_info["email"] != "None" else 0

        info_dict["is_trusted_ca"] = max(
            self.check_trusted_issuer(info_dict["cert_issuer"]["CN"]),
            self.check_trusted_issuer(info_dict["cert_issuer"]["O"]),
        )

        info_dict["is_protected_issuer"] = max(
            self.check_prohibit_name(info_dict["cert_issuer"]["CN"]),
            self.check_prohibit_name(info_dict["cert_issuer"]["O"]),
        )

        info_dict["is_protected_subject"] = max(
            self.check_prohibit_name(info_dict["cert_issuer"]["CN"]),
            self.check_prohibit_name(info_dict["cert_subject"]["OU"]),
        )

        serial_num = x509.get_serial_number()
        info_dict["serial_number"] = serial_num
        info_dict["len_serial_number"] = len(str(serial_num))

        cert_version = x509.get_version()
        info_dict["cert_version"] = cert_version

        not_before_bytes = x509.get_notBefore()
        not_before = not_before_bytes.decode()
        not_before = (
            not_before[0:4] + "-" +
            not_before[4:6] + "-" +
            not_before[6:8] + " " +
            not_before[8:10] + ":" +
            not_before[10:12] + ":" +
            not_before[12:14]
        )
        not_after_bytes = x509.get_notAfter()
        not_after = not_after_bytes.decode()
        not_after = (
            not_after[0:4] + "-" +
            not_after[4:6] + "-" +
            not_after[6:8] + " " +
            not_after[8:10] + ":" +
            not_after[10:12] + ":" +
            not_after[12:14]
        )

        info_dict["cert_validate_time_not_before"] = not_before
        info_dict["cert_validate_time_not_after"] = not_after

        try:
            has_expired = x509.has_expired()
        except ValueError:
            has_expired = True
        info_dict["has_expired"] = 1 if has_expired else 0

        signature_algorithm = x509.get_signature_algorithm().decode()
        info_dict["signature_algorithm"] = signature_algorithm

        extension_count = x509.get_extension_count()
        info_dict["extension_count"] = extension_count

        info_dict["extended_key_usage"] = 0
        info_dict["authority_key_usage"] = 0
        info_dict["subject_key_usage"] = 0
        info_dict["basic_constraints"] = 0
        info_dict["authority_key_identifier"] = 0
        info_dict["certificate_policies"] = 0
        info_dict["crl_distribution_points"] = 0
        info_dict["is_extended_validation"] = 0
        info_dict["freshest_crl"] = 0
        info_dict["subject_alt_name"] = "None"
        info_dict["has_subject_alt_name"] = 0
        info_dict["issuer_alt_name"] = 0
        info_dict[u'key_usage'] = 0
        info_dict["subject_directory_attributes"] = 0
        info_dict["not_common_extension_count"] = 0

        info_dict["extended_key_usage_critical"] = 0
        info_dict["authority_info_access_critical"] = 0
        info_dict["subject_key_identifier_critical"] = 0
        info_dict["basic_constraints_critical"] = 0
        info_dict["authority_key_identifier_critical"] = 0
        info_dict["certificate_policies_critical"] = 0
        info_dict["crl_distribution_points_critical"] = 0
        info_dict["is_extended_validation_critical"] = 0
        info_dict["freshest_crl_critical"] = 0
        info_dict["subject_alt_name_critical"] = 0
        info_dict["issuer_alt_name_critical"] = 0
        info_dict["key_usage_critical"] = 0
        info_dict["subject_directory_attributes_critical"] = 0

        for i in range(extension_count):
            if "extendedKeyUsage" == x509.get_extension(i).get_short_name().decode():
                info_dict["extended_key_usage"] = 1
                info_dict["extended_key_usage_critical"] = x509.get_extension(i).get_critical()

            elif "authorityInfoAccess" == x509.get_extension(i).get_short_name().decode():
                info_dict["authority_key_identifier"] = 1
                info_dict["authority_key_identifier_critical"] = x509.get_extension(i).get_critical()

            elif "subjectKeyIdentifier" == x509.get_extension(i).get_short_name().decode():
                info_dict["subject_key_identifier"] = 1
                info_dict["subject_key_identifier_critical"] = x509.get_extension(i).get_critical()

            elif "basicConstraints" == x509.get_extension(i).get_short_name().decode():
                info_dict["basic_constraints"] = 1
                info_dict["basic_constraints_critical"] = x509.get_extension(i).get_critical()

            elif "authorityKeyIdentifier" == x509.get_extension(i).get_short_name().decode():
                info_dict["authority_key_identifier"] = 1
                info_dict["authority_key_identifier_critical"] = x509.get_extension(i).get_critical()

            elif "crlDistributionPoints" == x509.get_extension(i).get_short_name().decode():
                info_dict["crl_distribution_points"] = 1
                info_dict["crl_distribution_points_critical"] = x509.get_extension(i).get_critical()

            elif "certificatePolices" == x509.get_extension(i).get_short_name().decode():
                info_dict["certificate_polices"] = 1
                info_dict["certificate_polices_critical"] = x509.get_extension(i).get_critical()

            elif "isExtendedValidation" == x509.get_extension(i).get_short_name().decode():
                info_dict["is_extended_validation"] = 1
                info_dict[u"is_extended_validation_critical"] = x509.get_extension(i).get_critical()

            elif "freshestCRL" == x509.get_extension(i).get_short_name().decode():
                info_dict["freshestCRL"] = 1
                info_dict["freshestCRL_critical"] = x509.get_extension(i).get_critical()

            elif "subjectAltNames" == x509.get_extension(i).get_short_name().decode():
                info_dict["subject_alt_name"] = x509.get_extension(i).__str__()
                info_dict["subjectAltNames"] = 1
                info_dict["subjectAltNames_critical"] =x509.get_extension(i).get_critical()

            elif "issuerAltNames" == x509.get_extension(i).get_short_name().decode():
                info_dict["issuer_alt_name"] = 1
                info_dict["issuer_alt_names_critical"] = x509.get_extension(i).get_critical()

            elif u'keyUsage' == x509.get_extension(i).get_short_name().decode():
                info_dict["use_key_usage"] = 1
                info_dict["key_usage_critical"] = x509.get_extension(i).get_critical()

            else:
                info_dict["not_common_name"] += 1

        info_dict["diff_not_after_timestamp"] = self.get_time_diff(info_dict["cert_validate_time_not_before"], timestamp)
        info_dict["diff_not_after_timestamp"] = self.get_time_diff(timestamp, info_dict["cert_validate_time_not_after"])
        info_dict["diff_not_before_notafter"] = self.get_time_diff(
            info_dict["cert_validate_time_not_before"],
            info_dict["cert_validate_time_not_after"]
        )

        info_dict["match_website_altname"] = self.match_altname(
            info_dict["origin_url"],
            info_dict["subject_alt_name"],
        )

        info_dict["match_issuer_o_cn"] = self.match_name(
            info_dict["cert_issuer"]["CN"],
            info_dict["cert_issuer"]["O"],
        )
        info_dict["match_issuer_subject_cn"] = self.match_name(
            info_dict["cert_issuer"]["CN"],
            info_dict["cert_subject"]["CN"],
        )
        info_dict["match_issuer_subject_c"] = self.match_name(
            info_dict["cert_issuer"]["C"],
            info_dict["cert_subject"]["C"],
        )
        info_dict["match_website_issuercn"] = self.match_name(
            info_dict["origin_url"],
            info_dict["cert_issuer"]["CN"],
        )
        info_dict["match_subject_o_cn"] = self.match_name(
            info_dict["cert_subject"]["O"],
            info_dict["cert_subject"]["CN"],
        )
        info_dict["match_issuer_o_ou"] = self.match_name(
            info_dict["cert_issuer"]["O"],
            info_dict["cert_issuer"]["OU"],
        )
        info_dict["match_subject_o_ou"] = self.match_name(
            info_dict["cert_subject"]["O"],
            info_dict["cert_subject"]["OU"],
        )
        logger.info("Certificate information dict of {} is {}", url, info_dict)
        return info_dict

    def check_prohibit_name(self, common_name):
        if common_name == "none" or common_name == "default":
            return 1
        for regex in CertificateParser.PROHIBITED_LIST["local_network"]:
            result = re.search(regex, common_name)
            if result:
                return 1
        for name in CertificateParser.PROHIBITED_LIST["wildcard"]:
            if common_name == name:
                return 1
        return 0
    def check_trusted_issuer(self, issuer):
        issuer = issuer.lower()
        lower_issuer = issuer.lower()
        logger.info("Trusted issuer: {}", issuer)
        if lower_issuer in CertificateParser.TRUSTED_LIST:
            logger.info("Direct matched issuer found in list")
            return 1
        for ele in CertificateParser.TRUSTED_LIST:
            # if there is a string in the trust list
            # that is similar to the issuer's common name
            # treat it as trusted.
            index_1 = lower_issuer.find(ele)
            index_2 = ele.find(lower_issuer)
            if index_1 != -1 and index_2 != -1:
                logger.info("Found sub match for issuer {} in Mozilla list {}", issuer, ele)
                return 1
            return 0

    def match_name(self,target, source):
        """

        Get the matching rate of target and source.
        :param target: target string to be matched
        :param source: source string to match with.

        :return: matching rate of target and source.
        :rtype: string representation of float number
        """

        match_rate = "-1"
        if target == "None" or source == "None":
            return match_rate

        source = source.strip()
        target = target.strip()
        target = target.lower()
        source = source.lower()
        match_rate = SequenceMatcher(None, target, source).ratio()

        return convert_float_to_str(match_rate)

    def match_altname(self,target, altname):
        if altname == "None" or target == "None":
            return "-1"

        target = target.lower()
        match_rate = 0
        altname = altname.split(",")

        for alt in altname:
            if ":" in alt:
                alt = alt.split(":")[1].strip
            alt = alt.lower()
            tmp_rate = SequenceMatcher(None, target, alt).ratio()
            if tmp_rate > match_rate:
                match_rate = tmp_rate
        return convert_float_to_str(match_rate)

    def get_time_diff(self,start_time, end_time):
        if isinstance(start_time, str):
            start_time = self.convert_str_time_to_seconds(start_time, DATETIME_FORMAT)
        elif isinstance(start_time, datetime.datetime):
            start_time = self.convert_str_time_to_seconds(start_time)

        if isinstance(end_time, str):
            end_time = self.convert_str_time_to_seconds(end_time,DATETIME_FORMAT)
        elif isinstance(end_time, datetime.datetime):
            end_time = self.convert_str_time_to_seconds(end_time)

        diff = end_time - start_time
        return diff.total_seconds()


    def convert_str_time_to_seconds(self, start_time, time_format):
        converted_time = time.mktime(time.strptime(start_time, time_format))
        return converted_time


    def convert_datetime_to_seconds(self, target_datetime):
        return time.mktime(target_datetime.timetuple())

    def parse_identity_components(self, identity, output_dict):
        common_name = "None"
        organization_name = "None"
        country_name = "None"  # countryName
        state_name = "None"  # stateOrProvinceName
        organization_unit = "None"  # organizationalUnitName
        locality = "None"  # localityName
        email_addr = "None"

        for ele in identity:
            if ele[0].decode() == "CN":
                common_name = ele[1].decode().upper()
                continue
            if ele[0].decode() == "O":
                organization_name = ele[1].decode().upper()
            if ele[0].decode() == "C":
                country_name = ele[1].decode().upper()
            if ele[0].decode() == "S":
                state_name = ele[1].decode().upper()
            if ele[0].decode() == "OU":
                organization_unit = ele[1].decode().upper()
            if ele[0].decode() == "emailAddress":
                email_addr = ele[1].decode().upper()
            if ele[0].decode() == "L":
                locality = ele[1].decode().upper()
                continue
        output_dict["common_name"] = common_name
        output_dict["O"] = organization_name
        output_dict["C"] = country_name
        output_dict["ST"] = state_name
        output_dict["OU"] = organization_unit
        output_dict["L"] = locality
        output_dict["email"] = email_addr


if __name__ == "__main__":
    pem_cert = """-----BEGIN CERTIFICATE-----
MIIJ2jCCCMKgAwIBAgIMUiR8hLBhmJuAljA0MA0GCSqGSIb3DQEBCwUAMFAxCzAJ
BgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMSYwJAYDVQQDEx1H
bG9iYWxTaWduIFJTQSBPViBTU0wgQ0EgMjAxODAeFw0yMzEyMjgyMDI2MDRaFw0y
NTAxMTkyMTMxMDdaMHExCzAJBgNVBAYTAkNBMRAwDgYDVQQIEwdPbnRhcmlvMRAw
DgYDVQQHEwdUb3JvbnRvMSQwIgYDVQQKExtGb3VyIFNlYXNvbnMgSG90ZWxzIExp
bWl0ZWQxGDAWBgNVBAMTD2ZvdXJzZWFzb25zLmNvbTCCAiIwDQYJKoZIhvcNAQEB
BQADggIPADCCAgoCggIBALISIRSXe/giKBu4ft661H1oJxFRugT19jpWIWpYVIy2
QyAWarTHax/uJdyBXAlTKCoJszhw6WkYGczaIw8tAr2LTDgmiKQRkzTDAfErfm1F
ACLWs5SEhmCe0+0+aNp1f/GT/3HP3bo2bBMsQKgUXoCn56S1kTYxB0EGDve5dGV6
/axzOQCx8P5jhPq5deaIjXQjC85H14ImkdOA0kebmRNijOdXeiDpki+oupJOsb+8
c4jJbyfLFMkzVsE1Q8g2GvavnVFKYPiPm6CuO6HmSVpkBZEM1rsOyfvHNFKTDAyj
HI2080tWIf0GsISHt2GbaEOidBi2GcZaybJEHDpmM8R7EVam7jL0DZlD2vTwsbrR
jOlZHmfbc0q0vLyrJ1CV4Me8vVRnC0FjV3aUzzo98dWpPYV1Husg1qCZaLrmQtpe
HgFaIXH1gDkRfIXsneb6UPvZN+M2HvPZNBPpLP2ZvXw7e3gxTqWzStcC+Ts8gBrX
cfh1N0a+uJbS8j4pCFZDtIJ/e7Oh14IJ0DuLC+dfWwVRRxbGP2//IoAXDnhxz2H0
6egQ/lMaSFGT6Dl/qGc+HKhdVlstuZZ9K+GAybhdUdvO6H0p3ac1iWt1vgNQS0Lp
hYx4cR0Uics7aR7uT5+49FtyQ7aO9RXWGLbRRxbo6qck4AxJWI9RGvobVq3r9bXd
AgMBAAGjggWRMIIFjTAOBgNVHQ8BAf8EBAMCBaAwDAYDVR0TAQH/BAIwADCBjgYI
KwYBBQUHAQEEgYEwfzBEBggrBgEFBQcwAoY4aHR0cDovL3NlY3VyZS5nbG9iYWxz
aWduLmNvbS9jYWNlcnQvZ3Nyc2FvdnNzbGNhMjAxOC5jcnQwNwYIKwYBBQUHMAGG
K2h0dHA6Ly9vY3NwLmdsb2JhbHNpZ24uY29tL2dzcnNhb3Zzc2xjYTIwMTgwVgYD
VR0gBE8wTTBBBgkrBgEEAaAyARQwNDAyBggrBgEFBQcCARYmaHR0cHM6Ly93d3cu
Z2xvYmFsc2lnbi5jb20vcmVwb3NpdG9yeS8wCAYGZ4EMAQICMD8GA1UdHwQ4MDYw
NKAyoDCGLmh0dHA6Ly9jcmwuZ2xvYmFsc2lnbi5jb20vZ3Nyc2FvdnNzbGNhMjAx
OC5jcmwwggJeBgNVHREEggJVMIICUYIPZm91cnNlYXNvbnMuY29tghNqb2JzLmZv
dXJzZWFzb25zLmNughV3d3cuMS5mb3Vyc2Vhc29ucy5jb22CFnNlY3VyZS5mb3Vy
c2Vhc29ucy5jb22CEW0uZm91cnNlYXNvbnMuY29tghVwcmVzcy5mb3Vyc2Vhc29u
cy5jb22CIXByZWZlcnJlZHBhcnRuZXJzLmZvdXJzZWFzb25zLmNvbYIacmVzaWRl
bmNlcy5mb3Vyc2Vhc29ucy5jb22CHHJlc2VydmF0aW9ucy5mb3Vyc2Vhc29ucy5j
b22CJWZzb3JpZ2luLXJlc2VydmF0aW9ucy5mb3Vyc2Vhc29ucy5jb22CH2Zzb3Jp
Z2luLXNlY3VyZS5mb3Vyc2Vhc29ucy5jb22CHGZzb3JpZ2luLXd3dy5mb3Vyc2Vh
c29ucy5jb22CG2F1dGhvci5saXZlLmZvdXJzZWFzb25zLmNvbYIUc3RheS5mb3Vy
c2Vhc29ucy5jb22CFWZvbnRzLmZvdXJzZWFzb25zLmNvbYIbZmlsbWFjYWRlbXku
Zm91cnNlYXNvbnMuY29tgiNyZXNpZGVudGlhbGJyYW5kaHViLmZvdXJzZWFzb25z
LmNvbYIhZGlnaXRhbHN0eWxlZ3VpZGUuZm91cnNlYXNvbnMuY29tghRqb2JzLmZv
dXJzZWFzb25zLmNvbYIZY2FycmllcmVzLmZvdXJzZWFzb25zLmNvbYIYbWFnYXpp
bmUuZm91cnNlYXNvbnMuY29tghN3d3cuZm91cnNlYXNvbnMuY29tMB0GA1UdJQQW
MBQGCCsGAQUFBwMBBggrBgEFBQcDAjAfBgNVHSMEGDAWgBT473/yzXhnqN5vjySN
iPGHAwKz6zAdBgNVHQ4EFgQUSYcWrCRz/bZ/BBYREh2SN5OCZGcwggGABgorBgEE
AdZ5AgQCBIIBcASCAWwBagB3AObSMWNAd4zBEEEG13G5zsHSQPaWhIb7uocyHf0e
N45QAAABjLIbCkEAAAQDAEgwRgIhAPDqQ+HFv3ctDumb8VBjQcy6vXScLuGYRjpk
xsQmduK2AiEAsqYPdOrouIUdmn0ywTk9/ZsCVGSV+AUkGXCtCHKe63oAdwCi4wrk
Re+9rZt+OO1HZ3dT14JbhJTXK14bLMS5UKRH5wAAAYyyGwo1AAAEAwBIMEYCIQCI
zvN05TBQtayT5/zlJlQ1CfizQpWf4ZxNxPZNOTEeZgIhAIQkkMo/gLeC5KAKnyD3
rGjVNE3EnBMSA+JC70Cwy4hlAHYATnWjJ1yaEMM4W2zU3z9S6x3w4I4bjWnAsfpk
sWKaOd8AAAGMshsKFAAABAMARzBFAiEA0hszpDHCc+cpqLE9bYai7zV0AXWLtXBY
AhX7XubkfboCIDZczU0CTDi+hEq2qnpj2DRgo6yJQ35Noc+84s5uMxXVMA0GCSqG
SIb3DQEBCwUAA4IBAQCLm3XRFai20Ek4X6/ljmk9qOMlaFpnELyoIS+EmRlut3Kk
IpAGlPKsZ62kvoCa6qFN5QSpFlfSL91Xr+/s4EoYoplAAD3eqW6kIzkecUSA6yaA
OWWQZ7qCibilCRgyK8sFjfosmZg1unKI7B2VnA/ysI4CP3ZcOYsc4hhwG1mQqb0o
pN0eyYedi325k6/36BisaK1/4H8xnD9DvrV0lhfHS7zTJxrQgAhQjaf5jwe/Outw
cigyvoQdEjPkY88p+VZ0vdxj1krSMGY30kuHTjs2PDdDpJUTUbchyH6b3jhQFCAb
D+4FGxxhgHBXkeW2HFlqOhqyeQv1zCfPJ+ptbcHe
-----END CERTIFICATE-----"""
    result = CertificateParser().get_info("fourseasons.com", pem_cert, "2024-04-05 23:08:45")



