### README - Secrets Manager

This command line tool allows you to manage secrets (e.g., passwords) stored in a MariaDB database, with commands to create folders, add secrets, remove secrets, and more.

---

### Installation

1. **Install Python 3.6+**  
   Ensure you have Python 3.6 or higher installed on your system.

2. **Install Required Packages**  
   This project uses several external libraries. You can install them using `pip`. Run the following command in your terminal or command prompt:

   ```bash
   pip install mariadb cryptography pyperclip
   ```

3. **Set up the Database**  
   You need a MariaDB database with the following tables:
   - `folders` (id, name)
   - `secrets` (id, folder_id, name, username, url, password)

   You can create these tables using the following SQL commands:

   ```sql
   CREATE TABLE folders (
       id INT AUTO_INCREMENT PRIMARY KEY,
       name VARCHAR(255) UNIQUE NOT NULL
   );

   CREATE TABLE secrets (
       id INT AUTO_INCREMENT PRIMARY KEY,
       folder_id INT,
       name VARCHAR(255) NOT NULL,
       username VARCHAR(255),
       url VARCHAR(255),
       password TEXT NOT NULL,
       FOREIGN KEY (folder_id) REFERENCES folders(id)
   );
   ```

4. **Create a `config.ini` File**  
   The tool requires a `config.ini` file to connect to the MariaDB database. Create this file in the same directory as the `pwdb.py` file with the following format:

   ```ini
   [database]
   host = your_database_host
   port = 3306
   user = your_database_user
   password = your_database_password
   database = your_database_name
   ```

---

### Usage

#### Available Commands:

1. **Create a folder:**
   ```bash
   python pwdb.py mkdir /path/to/folder
   ```

2. **Add a secret:**
   ```bash
   python pwdb.py secret /path/to/folder/secret_name -u username -l url
   ```

3. **Remove a folder:**
   ```bash
   python pwdb.py rmdir /path/to/folder
   ```

4. **Remove a secret:**
   ```bash
   python pwdb.py rmsecret /path/to/folder/secret_name
   ```

5. **Review a secret:**
   ```bash
   python pwdb.py review /path/to/folder/secret_name
   ```
   Use `-c` to copy the password to the clipboard:
   ```bash
   python pwdb.py review /path/to/folder/secret_name -c
   ```

6. **List folders and secrets:**
   ```bash
   python pwdb.py ls
   ```
   Optionally, search for a specific query:
   ```bash
   python pwdb.py ls search_query
   ```

---

### Notes

- The tool uses AES encryption to store passwords securely in the database.
- The master password is required when adding or retrieving secrets.