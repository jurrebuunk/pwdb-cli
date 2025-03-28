import mariadb
import configparser
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import hashlib
import base64
import os
from cryptography.hazmat.primitives import padding

def connect_to_db():
    config = configparser.ConfigParser()
    config.read('config.ini')
    db_host = config['database']['host']
    db_port = int(config['database']['port'])
    db_user = config['database']['user']
    db_password = config['database']['password']
    db_name = config['database']['database']

    try:
        print(f"Connecting to database at {db_host}:{db_port} with user {db_user}")
        conn = mariadb.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            password=db_password,
            database=db_name
        )
        print("Connection successful")
        return conn
    except mariadb.Error as e:
        print(f"Error connecting to database: {e}")
        return f"Error: {e}"

def generate_128bit_hash(master_password: str) -> bytes:
    print(f"Generating 128-bit hash from master password")
    md5_hash = hashlib.md5()
    md5_hash.update(master_password.encode('utf-8'))
    return md5_hash.digest()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    missing_padding = len(encrypted_password) % 4
    if missing_padding:
        encrypted_password += '=' * (4 - missing_padding)

    encrypted_password_bytes = base64.b64decode(encrypted_password)
    
    iv = encrypted_password_bytes[:16]
    ciphertext = encrypted_password_bytes[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Unpad the decrypted password (remove padding)
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_password = unpadder.update(decrypted_password_bytes) + unpadder.finalize()

    return decrypted_password.decode('utf-8')

def fetch_secret_password(conn, secret_name, folder_name, master_password):
    print(f"Fetching password for secret '{secret_name}' in folder '{folder_name}'")
    cursor = conn.cursor()
    query = """
        SELECT s.password 
        FROM secrets s
        JOIN folders f ON s.folder_id = f.id
        WHERE s.name = %s AND f.name = %s;
    """
    cursor.execute(query, (secret_name, folder_name))
    result = cursor.fetchone()

    if result:
        # Ensure encrypted_password is a bytes object
        encrypted_password = result[0]
        print(f"Found encrypted password (base64): {encrypted_password}")

        # Decode the base64 string to binary data
        encrypted_password = base64.b64decode(encrypted_password)
        
        key = generate_128bit_hash(master_password)
        decrypted_password = decrypt_password(encrypted_password, key)
        return decrypted_password
    else:
        return f"No matching secret found for '{secret_name}' in folder '{folder_name}'"

def review_secret(args):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        result = fetch_secret_password(conn, args.secret_name, args.folder_name, args.master_password)
        conn.close()
        return result
    else:
        return conn

def encrypt_password(password: str, key: bytes) -> str:
    print(f"Encrypting password: {password}")
    iv = generate_128bit_hash(args.master_password)  # Use a random IV for each encryption
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad password to make it a multiple of block size (16 bytes)
    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode('utf-8')) + padder.finalize()

    ciphertext = encryptor.update(padded_password) + encryptor.finalize()

    encrypted_password = iv + ciphertext  # Concatenate IV with the ciphertext
    encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')  # Convert to base64 string
    print(f"Encrypted password (base64): {encrypted_password_base64}")
    return encrypted_password_base64  # Return as base64 string

def insert_secret(conn, secret_name, folder_name, username, url, encrypted_password):
    print(f"Inserting new secret '{secret_name}' into folder '{folder_name}'")
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_name,))
    folder = cursor.fetchone()
    if not folder:
        return f"Folder '{folder_name}' not found."
    
    folder_id = folder[0]
    print(f"Folder ID: {folder_id}")

    query = """
        INSERT INTO secrets (name, folder_id, username, url, password)
        VALUES (%s, %s, %s, %s, %s)
    """
    cursor.execute(query, (secret_name, folder_id, username, url, encrypted_password))
    conn.commit()
    print(f"Secret '{secret_name}' successfully inserted.")

def create_secret(args):
    print(f"Creating secret '{args.secret_name}'")
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        key = generate_128bit_hash(args.master_password)
        encrypted_password = encrypt_password(args.password, key)
        result = insert_secret(conn, args.secret_name, args.folder_name, args.username, args.url, encrypted_password)
        conn.close()
        return result
    else:
        return conn

parser = argparse.ArgumentParser(description="Manage secrets stored in a MariaDB database.")
subparsers = parser.add_subparsers(dest="command")

review_parser = subparsers.add_parser('review', help="Review a secret password")
review_parser.add_argument('-s', '--secret-name', type=str, required=True, help="The name of the secret to retrieve")
review_parser.add_argument('-f', '--folder-name', type=str, required=True, help="The name of the folder where the secret is stored")
review_parser.add_argument('-m', '--master-password', type=str, required=True, help="The master password to generate the decryption key")

create_parser = subparsers.add_parser('create', help="Create a new secret")
create_parser.add_argument('-s', '--secret-name', type=str, required=True, help="The name of the secret to create")
create_parser.add_argument('-f', '--folder-name', type=str, required=True, help="The name of the folder where the secret will be stored")
create_parser.add_argument('-u', '--username', type=str, required=True, help="The username associated with the secret")
create_parser.add_argument('-l', '--url', type=str, required=True, help="The URL associated with the secret")
create_parser.add_argument('-p', '--password', type=str, required=True, help="The password to store")
create_parser.add_argument('-m', '--master-password', type=str, required=True, help="The master password to generate the encryption key")

args = parser.parse_args()

if args.command == "review":
    result = review_secret(args)
    print(result)
elif args.command == "create":
    result = create_secret(args)
    print(result)
else:
    print("Invalid command. Use 'review' or 'create'.")
