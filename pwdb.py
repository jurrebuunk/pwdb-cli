import mariadb
import configparser
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os
from cryptography.hazmat.primitives import padding
import getpass
import pyperclip

def connect_to_db():
    config = configparser.ConfigParser()
    config.read('config.ini')
    db_host = config['database']['host']
    db_port = int(config['database']['port'])
    db_user = config['database']['user']
    db_password = config['database']['password']
    db_name = config['database']['database']
    
    try:
        conn = mariadb.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name
        )
        return conn
    except mariadb.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def generate_128bit_hash(master_password: str) -> bytes:
    md5_hash = hashlib.md5()
    md5_hash.update(master_password.encode('utf-8'))
    return md5_hash.digest()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    encrypted_password_bytes = base64.b64decode(encrypted_password)
    iv = encrypted_password_bytes[:16]  # Pak de IV uit de eerste 16 bytes
    ciphertext = encrypted_password_bytes[16:]  # Pak de ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password_bytes = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad de data
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_password = unpadder.update(decrypted_password_bytes) + unpadder.finalize()

    return decrypted_password.decode('utf-8')


def fetch_secret_password(conn, secret_name, folder_name):
    cursor = conn.cursor()
    cursor.execute("SELECT s.password FROM secrets s JOIN folders f ON s.folder_id = f.id WHERE s.name = %s AND f.name = %s;", (secret_name, folder_name))
    result = cursor.fetchone()
    
    if result:
        encrypted_password = result[0]
        master_password = getpass.getpass("Enter master password: ")
        key = generate_128bit_hash(master_password)
        return decrypt_password(encrypted_password, key)
    else:
        return f"No matching secret found for '{secret_name}' in folder '{folder_name}'"

def review_secret(args):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        result = fetch_secret_password(conn, args.secret_name, args.folder_name)
        conn.close()
        
        if args.copy:  # If the '--copy' flag is provided
            pyperclip.copy(result)  # Copy the result to clipboard
            return "Password copied to clipboard"
        else:
            return result
    else:
        return conn


def encrypt_password(password: str, key: bytes) -> str:
    iv = os.urandom(16)  # Gebruik een willekeurig IV per encryptie
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode('utf-8')) + padder.finalize()

    ciphertext = encryptor.update(padded_password) + encryptor.finalize()

    encrypted_password = iv + ciphertext  # Voeg IV toe aan begin van de versleutelde string
    encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')
    return encrypted_password_base64


def insert_secret(conn, secret_name, folder_name, username, url, encrypted_password):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_name,))
    folder = cursor.fetchone()
    if not folder:
        return f"Folder '{folder_name}' not found."
    
    folder_id = folder[0]
    cursor.execute("INSERT INTO secrets (name, folder_id, username, url, password) VALUES (%s, %s, %s, %s, %s)", (secret_name, folder_id, username, url, encrypted_password))
    conn.commit()
    return f"Secret '{secret_name}' successfully inserted."

def create_secret(args):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        key = generate_128bit_hash(getpass.getpass("Enter master password: "))
        encrypted_password = encrypt_password(args.password, key)
        
        # If URL is not provided, set it to an empty string
        url = args.url if args.url else ""
        print(f"Creating secret '{args.secret_name}'")
        # Insert the secret into the table
        result = insert_secret(conn, args.secret_name, args.folder_name, args.username, url, encrypted_password)
        conn.close()
        return result
    else:
        return conn



parser = argparse.ArgumentParser(description="Manage secrets stored in a MariaDB database.")
subparsers = parser.add_subparsers(dest="command")

review_parser = subparsers.add_parser('review', help="Review a secret password")
review_parser.add_argument('-s', '--secret-name', type=str, required=True, help="The name of the secret to retrieve")
review_parser.add_argument('-f', '--folder-name', type=str, required=True, help="The name of the folder where the secret is stored")
review_parser.add_argument('-c', '--copy', action='store_true', help="Copy the password to the clipboard")

create_parser = subparsers.add_parser('create', help="Create a new secret")
create_parser.add_argument('-s', '--secret-name', type=str, required=True, help="The name of the secret to create")
create_parser.add_argument('-f', '--folder-name', type=str, required=True, help="The name of the folder where the secret will be stored")
create_parser.add_argument('-u', '--username', type=str, required=True, help="The username associated with the secret")
create_parser.add_argument('-l', '--url', type=str, required=False, help="The URL associated with the secret")
create_parser.add_argument('-p', '--password', type=str, required=True, help="The password to store")


args = parser.parse_args()

if args.command == "review":
    result = review_secret(args)
    print(result)
elif args.command == "create":
    result = create_secret(args)
    print(result)
else:
    print("Invalid command. Use 'review' or 'create'.")
