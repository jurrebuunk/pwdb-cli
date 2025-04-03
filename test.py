import MySQLdb
import configparser
import os

def test_db_connection():
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
            user=db_user,
            password=db_password,
            database=db_name
        )

        print("Connected to database successfully!")
        conn.close()
    except pymysql.MySQLError as e:
        print(f"Error connecting to database: {e}")

test_db_connection()
