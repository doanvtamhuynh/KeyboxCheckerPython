# Hello! Some part of this code is made by Senyx BUT
# Special thanks to these people!
# KimmyXYC - Certificate Checks and the base code
# Me - I ported this owowo!
# Hollowed Citra - wait theres is more than google and aosp keybox?!!1!
# 4:32AM - November 19 2024

import asyncio
import aiohttp
import re
import json
import tempfile
import time
import sys
import argparse
from colorama import Fore, Style, init
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
init(autoreset=True)

async def load_from_url():
    url = "https://android.googleapis.com/attestation/status"

    timestamp = int(time.time())
    headers = {
        "Cache-Control": "max-age=0, no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
        "Expires": "0"
    }

    params = {
        "ts": timestamp
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(url, headers=headers, params=params) as response:
            if response.status != 200:
                raise Exception(f"Error fetching data: {response.status}")
            return await response.json()


def parse_number_of_certificates(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    number_of_certificates = root.find('.//NumberOfCertificates')

    if number_of_certificates is not None:
        count = int(number_of_certificates.text.strip())
        return count
    else:
        raise Exception('No NumberOfCertificates found.')


def parse_certificates(xml_file, pem_number):
    tree = ET.parse(xml_file)
    root = tree.getroot()

    pem_certificates = root.findall('.//Certificate[@format="pem"]')

    if pem_certificates is not None:
        pem_contents = [cert.text.strip() for cert in pem_certificates[:pem_number]]
        return pem_contents
    else:
        raise Exception("No Certificate found.")


def load_public_key_from_file(file_path):
    with open(file_path, 'rb') as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )
    return public_key


def compare_keys(public_key1, public_key2):
    return public_key1.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ) == public_key2.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

async def keybox_check_cli(keybox_path):    
    try:
        pem_number = parse_number_of_certificates(keybox_path)
        pem_certificates = parse_certificates(keybox_path, pem_number)
    except Exception as e:
        print(f"{Fore.RED}Error : {e}")
        return

    try:
        certificate = x509.load_pem_x509_certificate(
            pem_certificates[0].encode(),
            default_backend()
        )
    except Exception as e:
        print(f"{Fore.RED}Error : {e}")
        return

    # Certificate Validity Verification
    serial_number = certificate.serial_number
    serial_number_string = hex(serial_number)[2:].lower()
    subject = certificate.subject
    not_valid_before = certificate.not_valid_before_utc
    not_valid_after = certificate.not_valid_after_utc
    current_date = datetime.now(timezone.utc)
    validity = not_valid_before <= current_date <= not_valid_after
    current_time_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Make terminal more beautiful
    not_valid_before_str = not_valid_before.strftime('%Y-%m-%d %H:%M:%S')
    not_valid_after_str = not_valid_after.strftime('%Y-%m-%d %H:%M:%S')
    if validity:
        validity_status = f"{Fore.GREEN}Valid. (Valid from {not_valid_before_str} to {not_valid_after_str})"
    else:
        validity_status = f"{Fore.RED}Expired. (Valid from {not_valid_before_str} to {not_valid_after_str})"

    # Keychain Authentication
    flag = True
    for i in range(pem_number - 1):
        son_certificate = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        father_certificate = x509.load_pem_x509_certificate(pem_certificates[i + 1].encode(), default_backend())

        if son_certificate.issuer != father_certificate.subject:
            flag = False
            break
        signature = son_certificate.signature
        signature_algorithm = son_certificate.signature_algorithm_oid._name
        tbs_certificate = son_certificate.tbs_certificate_bytes
        public_key = father_certificate.public_key()
        try:
            if signature_algorithm in ['sha256WithRSAEncryption', 'sha1WithRSAEncryption', 'sha384WithRSAEncryption',
                                       'sha512WithRSAEncryption']:
                hash_algorithm = {
                    'sha256WithRSAEncryption': hashes.SHA256(),
                    'sha1WithRSAEncryption': hashes.SHA1(),
                    'sha384WithRSAEncryption': hashes.SHA384(),
                    'sha512WithRSAEncryption': hashes.SHA512()
                }[signature_algorithm]
                padding_algorithm = padding.PKCS1v15()
                public_key.verify(signature, tbs_certificate, padding_algorithm, hash_algorithm)
            elif signature_algorithm in ['ecdsa-with-SHA256', 'ecdsa-with-SHA1', 'ecdsa-with-SHA384',
                                         'ecdsa-with-SHA512']:
                hash_algorithm = {
                    'ecdsa-with-SHA256': hashes.SHA256(),
                    'ecdsa-with-SHA1': hashes.SHA1(),
                    'ecdsa-with-SHA384': hashes.SHA384(),
                    'ecdsa-with-SHA512': hashes.SHA512()
                }[signature_algorithm]
                padding_algorithm = ec.ECDSA(hash_algorithm)
                public_key.verify(signature, tbs_certificate, padding_algorithm)
            else:
                raise ValueError("Unsupported signature algorithms")
        except Exception:
            flag = False
            break
    if flag:
        keychain_status = (f"{Fore.GREEN}Valid.")
    else:
        keychain_status = (f"{Fore.RED}Invalid.")

    # Root Certificate Validation
    script_dir = os.path.dirname(os.path.abspath(__file__))
    google_pem = os.path.join(script_dir, 'lib', 'pem', 'google.pem')
    aosp_ec_pem = os.path.join(script_dir, 'lib', 'pem', 'aosp_ec.pem')
    aosp_rsa_pem = os.path.join(script_dir, 'lib', 'pem', 'aosp_rsa.pem')
    knox_pem = os.path.join(script_dir, 'lib', 'pem', 'knox.pem')

    root_certificate = x509.load_pem_x509_certificate(pem_certificates[-1].encode(), default_backend())
    root_public_key = root_certificate.public_key()
    google_public_key = load_public_key_from_file(google_pem)
    aosp_ec_public_key = load_public_key_from_file(aosp_ec_pem)
    aosp_rsa_public_key = load_public_key_from_file(aosp_rsa_pem)
    knox_public_key = load_public_key_from_file(knox_pem)
    if compare_keys(root_public_key, google_public_key):
        cert_status = (f"{Fore.GREEN}Google Hardware Attestation")
    elif compare_keys(root_public_key, aosp_ec_public_key):
        cert_status = (f"{Fore.YELLOW}AOSP Software Attestation(EC)")
    elif compare_keys(root_public_key, aosp_rsa_public_key):
        cert_status = (f"{Fore.YELLOW}AOSP Software Attestation(RCA)")
    elif compare_keys(root_public_key, knox_public_key):
        cert_status = (f"{Fore.GREEN}Samsung Knox Attestation")
    else:
        cert_status = (f"{Fore.YELLOW}Unknown / Software")

    # Validation of certificate revocation
    try:
        status_json = await load_from_url()
    except Exception:
        print("Failed to fetch Google's revoked keybox list")
        with open("res/json/status.json", 'r', encoding='utf-8') as file:
            status_json = json.load(file)
            reply += "\nUsing local revoked keybox list"
    status = status_json['entries'].get(serial_number_string, None)
    if status is None:
        google_status = "null"
    else:
        google_status = (f"{status['reason']}")

    overrall_status = get_overrall_status(status, keychain_status, cert_status, google_status)

    keybox_parsed = (f"{certificate.subject}")
    keybox_string = re.search(r"2\.5\.4\.5=([0-9a-fA-F]+)", keybox_parsed) 
    if keybox_string:
        serial_number = keybox_string.group(1)
        print(f"Keybox SN : {Fore.BLUE}{serial_number}")
    else:
        print(f"Keybox SN : {Fore.YELLOW}Software or Invalid")
    print(f"Cert SN : {Fore.BLUE}{serial_number_string}")
    print(f"Status : {overrall_status}")
    print(f"Keychain : {keychain_status}")
    print(f"Validity: {validity_status}")
    print(f"Root Cert : {cert_status}")
    print(f"Check Time : {Fore.BLUE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Im dying here
def get_overrall_status(status, keychain_status, cert_status, google_status):
    if status is None:
        if keychain_status == f"{Fore.GREEN}Valid.":
            if cert_status == f"{Fore.YELLOW}Unknown / Software":
                if google_status == "null":
                    return f"{Fore.YELLOW}Valid. (Software signed)"
                else:
                    print(f"Something happen {status['reason']}")
            elif cert_status in (f"{Fore.YELLOW}AOSP Software Attestation(EC)", f"{Fore.YELLOW}AOSP Software Attestation(RCA)", f"{Fore.GREEN}Samsung Knox Attestation"):
                cert_status_map = {
                    f"{Fore.YELLOW}AOSP Software Attestation(EC)": f"{Fore.YELLOW}Valid. (AOSP Software EC)",
                    f"{Fore.YELLOW}AOSP Software Attestation(RCA)": f"{Fore.YELLOW}Valid. (AOSP Software RCA)",
                    f"{Fore.GREEN}Samsung Knox Attestation": f"{Fore.GREEN}Valid. (How did u get this? / Knox Attestation)"
                }
                return cert_status_map.get(cert_status, f"{Fore.RED}Invalid keybox.")
            else:
                return f"{Fore.RED}Invalid keybox."
        else:
            return f"{Fore.RED}Invalid Keybox."
    else:
        status_reason = google_status
        status_reason_map = {
            "KEY_COMPROMISE": f"{Fore.RED}Invalid. (Key Compromised)",
            "SOFTWARE_FLAW": f"{Fore.RED}Invalid. (Software flaw)",
            "CA_COMPROMISE": f"{Fore.RED}Invalid. (CA Compromised)",
            "SUPERSEDED": f"{Fore.RED}Invalid. (Suspended)"
        }
        return status_reason_map.get(status_reason, f"{Fore.GREEN}Valid")




if __name__ == "__main__":
    # Create an argument parser
    parser = argparse.ArgumentParser(description="Keybox Checker")
    parser.add_argument(
        "keybox_path", 
        nargs='?',
        help="Path to the keybox.xml file"
    )
    parser.add_argument(
        "-b", "--bulk",
        metavar="FOLDER_PATH",
        help="Check keybox.xml files in bulk."
    )
    
    args = parser.parse_args()

    if args.bulk:
        folder_path = args.bulk
        for filename in os.listdir(folder_path):
            if filename.endswith(".xml"):
                file_path = os.path.join(folder_path, filename)
                print("=====================================")
                print(f"Processing: {file_path}")
                asyncio.run(keybox_check_cli(file_path))

    elif args.keybox_path: # If --bulk is not used, check single file
        asyncio.run(keybox_check_cli(args.keybox_path))
    else:
        print("Error: Please provide a folder full of keybox.xml files or a single keybox.xml file.")
        sys.exit(1)
    

    if not args.keybox_path:
        print("Error: Please provide the path to the keybox file.")
        sys.exit(1)
