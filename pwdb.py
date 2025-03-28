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

def create_folder(conn, folder_name):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_name,))
    folder = cursor.fetchone()
    if folder:
        return f"Folder '{folder_name}' already exists."
    
    cursor.execute("INSERT INTO folders (name) VALUES (%s)", (folder_name,))
    conn.commit()
    return f"Folder '{folder_name}' successfully created."

def remove_folder(conn, folder_name):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_name,))
    folder = cursor.fetchone()
    if not folder:
        return f"Folder '{folder_name}' does not exist."
    
    cursor.execute("DELETE FROM folders WHERE name = %s", (folder_name,))
    conn.commit()
    return f"Folder '{folder_name}' successfully removed."

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    encrypted_password_bytes = base64.b64decode(encrypted_password)
    iv = encrypted_password_bytes[:16]  # Extract IV from the first 16 bytes
    ciphertext = encrypted_password_bytes[16:]  # Extract the ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password_bytes = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_password = unpadder.update(decrypted_password_bytes) + unpadder.finalize()

    return decrypted_password.decode('utf-8')

def generate_128bit_hash(master_password: str) -> bytes:
    md5_hash = hashlib.md5()
    md5_hash.update(master_password.encode('utf-8'))
    return md5_hash.digest()

def decrypt_password(encrypted_password: str, key: bytes) -> str:
    encrypted_password_bytes = base64.b64decode(encrypted_password)
    iv = encrypted_password_bytes[:16]  # Extract IV from the first 16 bytes
    ciphertext = encrypted_password_bytes[16:]  # Extract the ciphertext

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password_bytes = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data
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

def add_secret(args):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        # Prompt for the password twice using getpass
        password = getpass.getpass("Enter your new password: ")
        confirm_password = getpass.getpass("Confirm your new password: ")

        if password != confirm_password:
            return "Passwords do not match. Please try again."

        key = generate_128bit_hash(getpass.getpass("Enter master password: "))
        encrypted_password = encrypt_password(password, key)
        
        # If URL is not provided, set it to an empty string
        url = args.url if args.url else ""
        print(f"Adding secret '{args.name}'")
        # Insert the secret into the table
        result = insert_secret(conn, args.name, args.folder, args.username, url, encrypted_password)
        conn.close()
        return result
    else:
        return conn
    
def remove_secret(conn, secret_name, folder_name):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_name,))
    folder = cursor.fetchone()
    if not folder:
        return f"Folder '{folder_name}' does not exist."
    
    folder_id = folder[0]
    cursor.execute("DELETE FROM secrets WHERE name = %s AND folder_id = %s", (secret_name, folder_id))
    conn.commit()
    return f"Secret '{secret_name}' successfully removed from folder '{folder_name}'."


def encrypt_password(password: str, key: bytes) -> str:
    iv = os.urandom(16)  # Use a random IV for each encryption
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode('utf-8')) + padder.finalize()

    ciphertext = encryptor.update(padded_password) + encryptor.finalize()

    encrypted_password = iv + ciphertext  # Add IV to the beginning of the encrypted string
    encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')
    return encrypted_password_base64

def search_folders(conn, query=None):
    cursor = conn.cursor()
    if query:
        # If a query is passed, search for the folder matching the query
        cursor.execute("SELECT f.name, s.name FROM folders f LEFT JOIN secrets s ON f.id = s.folder_id WHERE f.name LIKE %s ORDER BY f.name, s.name", (f"%{query}%",))
    else:
        # If no query is passed, display all folders and their secrets
        cursor.execute("SELECT f.name, s.name FROM folders f LEFT JOIN secrets s ON f.id = s.folder_id ORDER BY f.name, s.name")

    folders = {}
    for folder_name, secret_name in cursor.fetchall():
        if folder_name not in folders:
            folders[folder_name] = []
        if secret_name:
            folders[folder_name].append(secret_name)

    return folders


def search(args):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        folders = search_folders(conn, args.query)
        conn.close()
        
        if not folders:
            return "No matching folders or secrets found."
        
        output = []
        for folder, secrets in folders.items():
            output.append(f"{folder}/")  # Display folder name with a slash for folder-like appearance
            for secret in secrets:
                output.append(f"  └── {secret}")  # Use '└──' to resemble folder structure

        return "\n".join(output)
    else:
        return conn



def add(args):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        if args.type == "folder":
            result = create_folder(conn, args.name)
        elif args.type == "secret":
            result = add_secret(args)
        else:
            result = "Invalid type. Use 'folder' or 'secret'."
        conn.close()
        return result
    else:
        return conn

def remove(args):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        if args.type == "folder":
            result = remove_folder(conn, args.name)
        elif args.type == "secret":
            result = remove_secret(conn, args.name, args.folder_name)
        else:
            result = "Invalid type. Use 'folder' or 'secret'."
        conn.close()
        return result
    else:
        return conn

# Argument parser
parser = argparse.ArgumentParser(description="Manage secrets stored in a MariaDB database.")
subparsers = parser.add_subparsers(dest="command")

# Add parser for add command
add_parser = subparsers.add_parser('add', help="Add a folder or secret")
add_parser.add_argument('type', choices=['folder', 'secret'], help="The type of item to add (folder or secret)")
add_parser.add_argument('name', type=str, help="The name of the folder or secret to add")
add_parser.add_argument('-f', '--folder', type=str, required=True,help="The name of the folder where the secret will be stored (required for secret)")
add_parser.add_argument('-u', '--username', type=str, required=True, help="The username associated with the secret (required for secret)")
add_parser.add_argument('-l', '--url', type=str, help="The URL associated with the secret (optional for secret)")

# Add parser for remove command
remove_parser = subparsers.add_parser('remove', help="Remove a folder or secret")
remove_parser.add_argument('type', choices=['folder', 'secret'], help="The type of item to remove (folder or secret)")
remove_parser.add_argument('name', type=str, help="The name of the folder or secret to remove")
remove_parser.add_argument('-f', '--folder-name', type=str, required=True, help="The name of the folder where the secret is stored (required for secret)")

# Review parser
review_parser = subparsers.add_parser('review', help="Review a secret password")
review_parser.add_argument('secret_name', type=str, help="The name of the secret to retrieve")
review_parser.add_argument('-f', '--folder-name', type=str, required=True, help="The name of the folder where the secret is stored")
review_parser.add_argument('-c', '--copy', action='store_true', help="Copy the password to the clipboard")

# Add parser for search command
search_parser = subparsers.add_parser('search', help="Search for folders and their secrets")
search_parser.add_argument('query', nargs='?', type=str, help="The folder name to search for (optional)")



args = parser.parse_args()

# Execute based on command
if args.command == "add":
    result = add(args)
    print(result)
elif args.command == "remove":
    result = remove(args)
    print(result)
elif args.command == "review":
    result = review_secret(args)
    print(result)
elif args.command == "search":
    result = search(args)
    print(result)
else:
    print("Invalid command. Use 'add', 'remove', 'review', or 'search'.")
