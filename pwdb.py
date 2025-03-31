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
    script_dir = os.path.dirname(os.path.abspath(__file__))  # Bepaal script locatie
    config_path = os.path.join(script_dir, 'config.ini')  # Volledig pad naar config.ini

    config = configparser.ConfigParser()
    config.read(config_path)  # Lees config bestand
    
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
    if not folder_name.startswith("/"):
        folder_name = "/" + folder_name  # Zorg ervoor dat de folder altijd begint met "/"

    cursor = conn.cursor()
    cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_name,))
    folder = cursor.fetchone()
    if folder:
        return f"Folder '{folder_name}' already exists."
    
    cursor.execute("INSERT INTO folders (name) VALUES (%s)", (folder_name,))
    conn.commit()
    return f"Folder '{folder_name}' successfully created."

def remove_secret(conn, secret_name, folder_name):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_name,))
    folder = cursor.fetchone()
    if not folder:
        return f"Folder '{folder_name}' does not exist."

    cursor.execute("DELETE FROM secrets WHERE name = %s AND folder_id = %s", (secret_name, folder[0]))
    conn.commit()
    return f"Secret '{secret_name}' successfully removed from folder '{folder_name}'."

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

def review_secret(secret_name, folder_name, copy=False):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        result = fetch_secret_password(conn, secret_name, folder_name)
        conn.close()
        
        if copy:
            pyperclip.copy(result)
            return "Password copied to clipboard"
        else:
            return result
    else:
        return "Database connection failed."


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

def add_secret(path, username=None, url=None):
    # Split the provided path into folder and secret name
    folder_path, secret_name = os.path.split(path)
    
    if not folder_path:
        return "Error: The folder path must be specified and cannot be empty."
    
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        cursor = conn.cursor()
        
        # Check if the folder exists
        cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_path,))
        folder = cursor.fetchone()
        
        if not folder:
            conn.close()
            return f"Error: Folder '{folder_path}' does not exist."

        # Prompt for username if not provided
        if not username:
            username = input("Enter the username associated with the secret: ")

        # Prompt for the password twice using getpass
        password = getpass.getpass("Enter your new password: ")
        confirm_password = getpass.getpass("Confirm your new password: ")

        if password != confirm_password:
            conn.close()
            return "Passwords do not match. Please try again."

        key = generate_128bit_hash(getpass.getpass("Enter master password: "))
        encrypted_password = encrypt_password(password, key)

        # If URL is not provided, set it to an empty string
        url = url if url else ""
        print(f"Adding secret '{secret_name}' in folder '{folder_path}'")
        
        # Insert the secret into the table
        result = insert_secret(conn, secret_name, folder_path, username, url, encrypted_password)
        conn.close()
        return result
    else:
        return "Error: Database connection failed."    
def remove_folder(conn, folder_name):
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_name,))
    folder = cursor.fetchone()
    if not folder:
        return f"Folder '{folder_name}' does not exist."
    
    cursor.execute("DELETE FROM folders WHERE name = %s", (folder_name,))
    conn.commit()
    return f"Folder '{folder_name}' successfully removed."


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
    query = f"%{query}%" if query else "%"
    cursor.execute("SELECT f.name, s.name FROM folders f LEFT JOIN secrets s ON f.id = s.folder_id WHERE f.name LIKE %s ORDER BY f.name, s.name",
                   (query,))
    
    folders = {}
    for folder_name, secret_name in cursor.fetchall():
        folders.setdefault(folder_name, []).append(secret_name) if secret_name else folders.setdefault(folder_name, [])

    def build_tree():
        tree = {}
        for folder in sorted(folders.keys()):
            parts = folder.strip("/").split("/")
            current = tree
            for part in parts:
                current = current.setdefault(part, {})
            if folders[folder]:
                current["_secrets"] = folders[folder]
        return tree

    def print_tree(node, prefix=""):
        lines = []
        keys = sorted(k for k in node.keys() if k != "_secrets")
        for key in keys:
            lines.append(f"{prefix}├── {key}/")
            lines.extend(print_tree(node[key], prefix + "│   "))
        if "_secrets" in node:
            for secret in node["_secrets"]:
                lines.append(f"{prefix}└── {secret}")
        return lines

    return "\n".join(print_tree(build_tree()))
    

def parse_and_execute(command_str):
    tokens = command_str.split()
    if not tokens:
        print("No command entered.")
        return

    command = tokens[0]
    args = tokens[1:]

    if command == "mkdir" and len(args) == 1:
        conn = connect_to_db()
        if conn:
            print(create_folder(conn, args[0]))
            conn.close()

    elif command == "secret":
        if len(args) >= 1:
            path = args[0]
            username = None
            url = None
            for i in range(1, len(args), 2):
                if args[i] in ["-u", "--username"] and i + 1 < len(args):
                    username = args[i + 1]
                elif args[i] in ["-l", "--url"] and i + 1 < len(args):
                    url = args[i + 1]
            result = add_secret(path, username, url)
            print(result)

    elif command == "rmdir" and len(args) == 1:
        conn = connect_to_db()
        if conn:
            print(remove_folder(conn, args[0]))
            conn.close()

    elif command == "rmsecret" and len(args) == 1:
        conn = connect_to_db()
        if conn:
            print(remove_secret(conn, os.path.basename(args[0]), os.path.dirname(args[0])))
            conn.close()

    elif command == "review":
        if len(args) >= 1:
            path = args[0]
            folder_name, secret_name = os.path.split(path)
            copy = "-c" in args or "--copy" in args
            result = review_secret(secret_name, folder_name, copy)
            print(result)


    elif command == "ls":
        query = args[0] if args else None
        conn = connect_to_db()
        if conn:
            print(search_folders(conn, query))
            conn.close()

    else:
        print("Invalid command. Use 'mkdir', 'secret', 'rmdir', 'rmsecret', 'review', or 'ls'.")



parser = argparse.ArgumentParser(description="Process command input as a single string.")
parser.add_argument("command", nargs=argparse.REMAINDER, help="Full command input")

args = parser.parse_args()

if args.command:
    command_str = " ".join(args.command)
    parse_and_execute(command_str)
else:
    print("No command provided. Use 'mkdir', 'secret', 'rmdir', 'rmsecret', 'review', or 'ls'.")
