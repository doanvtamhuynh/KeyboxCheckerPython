# Hello! Some part of this code is made by Senyx BUT
# Special thanks to these people!
# KimmyXYC - Certificate Checks and the base code
# Me - I ported this owowo!
# Hollowed Citra - wait theres is more than google and aosp keybox?!!1!
# 4:32AM - November 19 2024

import asyncio
import aiohttp
import re
import tarfile
import requests
import json
import tempfile
import time
import os
import sys
import argparse
from colorama import Fore, Style, init
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, ec
init(autoreset=True)
current_version = "v1.4"

# ==== This code is to check update

# because the "v" is important since it look beautiful
def parse_version(version):
    return tuple(map(int, (version.lstrip('v').split("."))))

def get_latest_version():
    url = f"https://api.github.com/repos/SenyxLois/KeyboxCheckerPython/releases/latest"
    response = requests.get(url)
    if response.status_code == 200:
        latest_release = response.json()
        return latest_release["tag_name"], latest_release["tarball_url"], latest_release["body"]
    else:
        raise Exception(f"Failed to fetch latest release: {response.status_code}")

def download_and_replace_files(tarball_url):
    response = requests.get(tarball_url)
    if response.status_code == 200:
        tar_content = response.content
        with tempfile.TemporaryDirectory() as tmpdirname:
            tar_path = os.path.join(tmpdirname, 'update.tar.gz')
            with open(tar_path, 'wb') as f:
                f.write(tar_content)
            with tarfile.open(tar_path, 'r:gz') as tar_ref:
                def is_within_directory(directory, target):
                    abs_directory = os.path.abspath(directory)
                    abs_target = os.path.abspath(target)
                    prefix = os.path.commonprefix([abs_directory, abs_target])
                    return prefix == abs_directory

                def safe_extract(tar, path=".", members=None, *, numeric_owner=False):
                    for member in tar.getmembers():
                        member_path = os.path.join(path, member.name)
                        if not is_within_directory(path, member_path):
                            raise Exception("Attempted Path Traversal in Tar File")
                    tar.extractall(path, members, numeric_owner=numeric_owner)

                safe_extract(tar_ref, tmpdirname)
            extracted_dir = os.path.join(tmpdirname, os.listdir(tmpdirname)[0])
            for root, dirs, files in os.walk(extracted_dir):
                for file in files:
                    src_path = os.path.join(root, file)
                    rel_path = os.path.relpath(src_path, extracted_dir)
                    dest_path = os.path.join(os.getcwd(), rel_path)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    os.replace(src_path, dest_path)
            print("Update successful. Please restart the application.")
    else:
        print("Failed to download the update.")

def check_for_update():
    repo_url = "https://api.github.com/repos/SenyxLois/KeyboxCheckerPython/releases/latest"
    response = requests.get(repo_url)
    if response.status_code == 200:
        release_info = response.json()
        latest_version = release_info['tag_name']
        changelog = release_info['body']
        if parse_version(latest_version) > parse_version(current_version):
            print(f"New Version available: {latest_version}")
            print("Changelog :")
            print(changelog)
            update = input("Do you want to update? (y/n): ").strip().lower()
            if update == "y":
                print('Updating...')
                download_and_replace_files(release_info['tarball_url'])
            else:
                print("Update canceled.")
        else:
            time.sleep(0.02)
    else:
        print("Failed to check for updates.")

# ==== very demure lining :3

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
            print("Using local revoked list.. (DO NOT TRUST 100%)")

    status = None
    for i in range(pem_number):
        certificate = x509.load_pem_x509_certificate(pem_certificates[i].encode(), default_backend())
        serial_number = certificate.serial_number
        serial_number_string = hex(serial_number)[2:].lower()
        if status_json['entries'].get(serial_number_string, None):
            status = status_json['entries'][serial_number_string]
            break
    if not status:
        google_status = "null"
    else:
        google_status = (f"{status['reason']}")

    overrall_status = get_overrall_status(status, keychain_status, cert_status, google_status)
    oid_values = {}
    for rdn in subject:
        oid_values[rdn.oid._name] = rdn.value

    keybox_parsed = (f"{certificate.subject}")
    keybox_string = re.search(r"2\.5\.4\.5=([0-9a-fA-F]+)", keybox_parsed) 
    if keybox_string:
        serial_number = keybox_string.group(1)
        print(f"Keybox SN : {Fore.BLUE}{serial_number}")
    else:
        print(f"Keybox SN : {Fore.YELLOW}Software or Invalid")
    print(f"Cert SN : {Fore.BLUE}{serial_number_string}")
    keybox_title = oid_values.get('title', 'N/A')
    if keybox_title != 'TEE':
        print(f"Keybox Title : {Fore.BLUE}{keybox_title}")
    if 'organizationName' in oid_values:
        print(f"Keybox Organization: {Fore.BLUE}{oid_values['organizationName']}")
    if 'commonName' in oid_values:
        print(f"Keybox Name: {Fore.BLUE}{oid_values['commonName']}")
    print(f"Status : {overrall_status}")
    print(f"Keychain : {keychain_status}")
    print(f"Validity: {validity_status}")
    print(f"Root Cert : {cert_status}")
    print(f"Check Time : {Fore.BLUE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    return overrall_status

    # Im dying here
def get_overrall_status(status, keychain_status, cert_status, google_status):
    if status is None:
        if keychain_status == f"{Fore.GREEN}Valid.":
            if cert_status == f"{Fore.YELLOW}Unknown / Software":
                if google_status == "null":
                    return f"{Fore.YELLOW}Valid. (Software signed)"
                else:
                    print(f"Something happen {status['reason']}")
            elif cert_status in (f"{Fore.YELLOW}AOSP Software Attestation(EC)", f"{Fore.YELLOW}AOSP Software Attestation(RCA)", f"{Fore.GREEN}Samsung Knox Attestation", f"{Fore.GREEN}Google Hardware Attestation"):
                cert_status_map = {
                    f"{Fore.GREEN}Google Hardware Attestation": f"{Fore.GREEN}Valid. (Google Hardware Attestation)",
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
    check_for_update()
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
    parser.add_argument(
        "-v", "--version",
        action='version',
        version=f'KeyboxChecker Version : {current_version}'
    )
    
    args = parser.parse_args()

    if args.bulk:
        folder_path = args.bulk
        keybox_statuses = {}
        total_valid_keybox = 0
        total_software_keybox = 0
        total_invalid_keybox = 0

        print("Checking keyboxs folder...")
        for filename in os.listdir(folder_path):
            if filename.endswith(".xml"):
                file_path = os.path.join(folder_path, filename)
                overrall_status = asyncio.run(keybox_check_cli(file_path))
                keybox_statuses[file_path] = overrall_status
                os.system('cls' if os.name == 'nt' else 'clear')

                if overrall_status == f"{Fore.GREEN}Valid. (Google Hardware Attestation)":
                    total_valid_keybox += 1
                elif overrall_status == f"{Fore.YELLOW}Valid. (Software signed)":
                    total_software_keybox += 1
                elif overrall_status in [f"{Fore.RED}Invalid Keybox.", f"{Fore.RED}Invalid. (Key Compromised)", f"{Fore.RED}Invalid. (Software flaw)", f"{Fore.RED}Invalid. (CA Compromised)", f"{Fore.RED}Invalid. (Suspended)"]:
                    total_invalid_keybox += 1

        for keybox, overrall_status in keybox_statuses.items():
            print(f"{keybox} : {overrall_status}")

        print(f"\nValid Keyboxs : {total_valid_keybox}")
        print(f"Software Keyboxs : {total_software_keybox}")
        print(f"Invalid Keyboxs : {total_invalid_keybox}")

    elif args.keybox_path:  # If --bulk is not used, check single file
        asyncio.run(keybox_check_cli(args.keybox_path))
    else:
        print("Error: Please provide a folder full of keybox.xml files or the path to the keybox file.")  # Modified error message
        sys.exit(1)