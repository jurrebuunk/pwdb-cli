import mariadb
import configparser
import argparse
import hashlib

def generate_128bit_hash(master_password: str) -> str:
    md5_hash = hashlib.md5()
    md5_hash.update(master_password.encode('utf-8'))
    return md5_hash.hexdigest()

master_password = "my_master_password"
hash_value = generate_128bit_hash(master_password)
print(f"128-bit hash: {hash_value}")


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
        return f"Error: {e}"

def fetch_secret_password(conn, secret_name, folder_name):
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
        return result[0]
    else:
        return("Folder or Secret does not exist")


def review_secret(args):
    conn = connect_to_db()
    if isinstance(conn, mariadb.Connection):
        result = fetch_secret_password(conn, args.secret_name, args.folder_name)
        conn.close()
        return result
    else:
        return conn #error if fails to connect


parser = argparse.ArgumentParser(description="Manage secrets stored in a MariaDB database.")
subparsers = parser.add_subparsers(dest="command")

#review command
review_parser = subparsers.add_parser('review', help="Review a secret password")
review_parser.add_argument(
    '-s', '--secret-name', 
    type=str, 
    required=True, 
    help="The name of the secret to retrieve"
)
review_parser.add_argument(
    '-f', '--folder-name', 
    type=str, 
    required=True, 
    help="The name of the folder where the secret is stored"
)

# Parse the arguments
args = parser.parse_args()
if args.command == "review":
    result = review_secret(args)
    print(result)
else:
    print("Invalid command")
