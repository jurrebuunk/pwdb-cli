# Password Manager

A simple command-line password manager that stores and retrieves secrets securely using MariaDB and AES encryption.

## Installation
1. Install dependencies:
   ```sh
   pip install mariadb cryptography pyperclip
   ```
2. Configure the database connection in `config.ini`.

## Usage

### Add a Folder
```sh
python pwdb.py add folder "MyFolder"
```

### Add a Secret
```sh
python pwdb.py add secret "MySecret" -f "MyFolder" -u "username" -l "https://example.com"
```
You will be prompted to enter and confirm the password.

### Remove a Folder or Secret
```sh
python pwdb.py remove folder "MyFolder"
python pwdb.py remove secret "MySecret" -f "MyFolder"
```

### Retrieve a Secret
```sh
python pwdb.py review "MySecret" -f "MyFolder"
```

### Search for Folders and Secrets
```sh
python pwdb.py search  # Lists all folders and secrets
python pwdb.py search "MyFolder"  # Lists secrets within a specific folder
```

## Features and planned features

- [x] Add and remove secrets
- [x] folder structure
- [x] AES secret encryption and decryption
- [x] Copy to clipboard support
- [x] Ability to list stored secrets
- [ ] Vault mode (browse trough vault like file system)
- [ ] Linux support
- [ ] Ability to move already created secrets to a different folder
- [ ] More support for different databases
- [ ] Recycling bin

