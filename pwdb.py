import MySQLdb
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
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, 'config.ini')
    
    config = configparser.ConfigParser()
    config.read(config_path)
    
    db_host = config['database']['host']
    db_port = int(config['database']['port'])
    db_user = config['database']['user']
    db_password = config['database']['password']
    db_name = config['database']['database']
    
    try:
        conn = MySQLdb.connect(
            host=db_host,
            port=db_port,
            user=db_user,
            passwd=db_password,
            db=db_name
        )
        return conn
    except MySQLdb.Error as e:
        print(f"Error connecting to database: {e}")
        return None

def create_folder(conn, folder_name):
    if not folder_name.startswith("/"):
        folder_name = "/" + folder_name

    cursor = conn.cursor()

    # Split the folder path into all possible parent folders
    parts = folder_name.strip("/").split("/")
    current_path = ""

    for part in parts:
        current_path += f"/{part}"  # Build the path step by step
        
        # Check if the folder already exists
        cursor.execute("SELECT id FROM folders WHERE name = %s", (current_path,))
        folder = cursor.fetchone()

        if not folder:  # Only insert if it does not exist
            cursor.execute("INSERT INTO folders (name) VALUES (%s)", (current_path,))
            conn.commit()

    return f"Folder '{folder_name}' successfully created with all necessary parent folders."


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
    iv = encrypted_password_bytes[:16]  
    ciphertext = encrypted_password_bytes[16:]  

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_password_bytes = decryptor.update(ciphertext) + decryptor.finalize()

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

def review_secret(path, copy):
    folder, secret = path.rsplit("/", 1)
    conn = connect_to_db()
    if conn:
        result = fetch_secret_password(conn, secret, folder)
        conn.close()
        
        if copy:
            pyperclip.copy(result)
            return "Password copied to clipboard"
        else:
            return result
    else:
        return "Error: Database connection failed."

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

import os

def add_secret(path, url=None):
    folder_path, secret_name = os.path.split(path)  # This splits the path into folder and secret

    if not folder_path:
        return "Error: The folder path must be specified and cannot be empty."
    
    # If the path ends with a slash, we remove it
    if folder_path.endswith('/'):
        folder_path = folder_path[:-1]

    conn = connect_to_db()
    if conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM folders WHERE name = %s", (folder_path,))
        folder = cursor.fetchone()
        
        if not folder:
            conn.close()
            return f"Error: Folder '{folder_path}' does not exist."

        username = secret_name  # Now we use the secret_name directly from the path

        password = getpass.getpass("Enter your new password: ")
        confirm_password = getpass.getpass("Confirm your new password: ")

        if password != confirm_password:
            conn.close()
            return "Passwords do not match. Please try again."

        key = generate_128bit_hash(getpass.getpass("Enter master password: "))
        encrypted_password = encrypt_password(password, key)

        url = url if url else ""
        
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
    iv = os.urandom(16)  
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_password = padder.update(password.encode('utf-8')) + padder.finalize()

    ciphertext = encryptor.update(padded_password) + encryptor.finalize()

    encrypted_password = iv + ciphertext  
    encrypted_password_base64 = base64.b64encode(encrypted_password).decode('utf-8')
    return encrypted_password_base64

def list_folder_contents(conn, folder_path="/"):
    cursor = conn.cursor()

    # Ensure the path starts with "/"
    if not folder_path.startswith("/"):
        folder_path = "/" + folder_path

    # If the path is "/", list all unique first-level folders
    if folder_path == "/":
        cursor.execute("SELECT name FROM folders WHERE name LIKE '/%'")
        subfolders = {row[0].split('/')[1] for row in cursor.fetchall()}
    else:
        # Fetch only first-level subfolders under the given path
        cursor.execute("SELECT name FROM folders WHERE name LIKE %s", (folder_path + "/%",))
        subfolders = {row[0][len(folder_path):].strip("/").split('/')[0] for row in cursor.fetchall()}

    # Fetch secrets inside the given folder
    cursor.execute("""
        SELECT s.name 
        FROM secrets s 
        JOIN folders f ON s.folder_id = f.id 
        WHERE f.name = %s
    """, (folder_path,))
    secrets = ["." + row[0] for row in cursor.fetchall()]

    # Format folders (only show the last part, no full path)
    formatted_folders = sorted(f"{name}/" for name in subfolders if name)

    # Combine and return results
    result = formatted_folders + sorted(secrets)
    return "\n".join(result) if result else f"No contents found in '{folder_path}'"

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
            result = add_secret(args[0])
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
            result = review_secret(args[0], "-c" in args or "--copy" in args)
            print(result)
    elif command == "ls":
        if len(args) == 1:
            conn = connect_to_db()
            if conn:
                print(list_folder_contents(conn, args[0]))
                conn.close()
        else:
            print("Usage: ls <folder_path>")

    else:
        print("Invalid command. Use 'mkdir', 'secret', etc.")

parser = argparse.ArgumentParser(description="Process command input as a single string.")
parser.add_argument("command", nargs=argparse.REMAINDER, help="Full command input")

args = parser.parse_args()

if args.command:
    parse_and_execute(" ".join(args.command))
else:
    print("No command provided.")
