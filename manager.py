from cryptography.fernet import Fernet


class PasswordManager:

    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}
        self.keyloaded = False

    def create_key(self, path):
        self.key = Fernet.generate_key()
        with open(path, 'wb') as f:
            f.write(self.key)
        self.keyloaded = True

    def load_key(self, path):
        with open(path, 'rb') as f:
            self.key = f.read()
        self.keyloaded = True


    def create_password_file(self, path, initial_values=None):
        self.password_file = path
        if initial_values is not None:
            for site in initial_values:
                print(initial_values[site])
                self.add_password(site, initial_values[site])

    def load_password_file(self, path):
        self.password_file = path
        with open(path, 'r') as f:
            for line in f:
                site, encrypted = line.split(":")
                self.password_dict[site] = Fernet(self.key).decrypt(encrypted.encode()).decode()

    def add_password(self, site, password):
        if site in self.password_dict:  
            print(f"Warning: A password for the site '{site}' already exists.")  
            return 
        self.password_dict[site] = password
        if self.password_file is not None:
            with open(self.password_file, 'a+') as f:
                encrypted = Fernet(self.key).encrypt(password.encode()).decode()
                f.write(f"{site}:{encrypted}\n")

    def get_password(self, site):
        return self.password_dict.get(site, "Password not found.")

    def delete_password(self, site):
        if site in self.password_dict:
            # Remove from the dictionary
            del self.password_dict[site]
            # Update the password file
            if self.password_file is not None:
                with open(self.password_file, 'r') as f:
                    lines = f.readlines()
                with open(self.password_file, 'w') as f:
                    for line in lines:
                        if not line.startswith(site + ":"):  # Skip the line with the site to delete
                            f.write(line)
        else:
            print("Site not found.")

    def validate_strength(self, password):
        # a password is strong if it has length greater than 8
        # it has special characters such as !@#$%^&*
        # it is a mix of letters, numbers
        SpecialChar = '!@#$%^&*'
        has_good_length = False
        has_special_char = False
        has_numeric_characters = False
        has_capital_letters = False
        has_small_letters = False
        if len(password) > 8: 
            has_good_length = True
        for chr in password:
            if chr in SpecialChar:
                has_special_char = True
            if chr.isupper():
                has_capital_letters = True
            if chr.islower():
                has_small_letters = True
            if chr.isdigit():
                has_numeric_characters = True
        return has_numeric_characters and has_good_length and\
              has_capital_letters and has_special_char and has_small_letters

    def get_current_key_id(self):
        if not self.key:
            return None
        key = self.session.query(Key).filter_by(key_value=self.key.decode()).first()
        return key.key_id
    
    def list_keys(self):
        keys = self.session.query(Key).filter_by(user_id=self.user.user_id).all()
        if not keys:
            print("No keys available. Please create a new key.")
        else:
            print("Available Keys:")
            for idx, key in enumerate(keys):
                print(f"{idx + 1}. Key ID: {key.key_id}")
        return keys
    
    def list_sites(self):
        passwords = self.session.query(Password).filter_by(user_id=self.user.user_id).all()
        passwords = set([password.site for password in passwords])
        if not passwords:
            print("No passwords stored yet.")
        else:
            print("Stored Sites:")
            for idx, password in enumerate(passwords):
                print(f"{idx + 1}. {password}")

