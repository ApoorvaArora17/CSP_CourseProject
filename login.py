from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from email.mime.text import MIMEText
import hashlib
import os
import random
import re
import smtplib
import ssl
import socket
import string
import tkinter as tk
from tkinter import ttk, messagebox

##File to maintain user db
USERS_FILE = "F.txt"
## Port at which honeychecker is present
HONEYCHECKER_ADDRESS = ('127.0.0.1', 9999)
N = 19  ##No. of honeywords

### HELPFUL LISTS IN GENERATING HONEYWORDS
common_passwords = ['123456', 'password', '12345678', 'dragon', 'qwerty', '696969', 'mustang', 'letmein', 'baseball', 'master', 'michael', 'football', 'shadow', 'monkey', 'abc123', 'fuckme', 'jordan', 'harley', 'ranger', 'iwantu', 'jennifer', 'hunter', 'batman', 'trustno1', 'thomas', 'tigger', 'robert', 'access', 'buster', '1234567', 'soccer', 'hockey', 'killer', 'george', 'andrew', 'charlie', 'superman', 'asshole', 'fuckyou', 'dallas', 'jessica', 'panties', 'pepper', 'austin', 'william', 'daniel', 'golfer', 'summer', 'heather', 'hammer', 'yankees', 'joshua', 'maggie', 'biteme', 'ashley', 'thunder', 'cowboy', 'silver', 'richard', 'fucker', 'orange', 'merlin', 'michelle', 'corvette', 'bigdog', 'cheese', 'matthew', '121212', 'patrick', 'martin', 'freedom', 'ginger', 'blowjob', 'nicole', 'sparky', 'yellow', 'camaro', 'secret', 'falcon', 'taylor', '111111', '131313', '123123', 'scooter', 'please', 'porsche', 'guitar', 'chelsea', 'diamond', 'nascar', 'jackson', 'cameron', '654321', 'computer', 'amanda', 'wizard', 'xxxxxxxx', 'phoenix', 'mickey', 'bailey', 'knight', 'iceman', 'tigers', 'purple', 'andrea', 'dakota', 'aaaaaa', 'player', 'sunshine', 'morgan', 'starwars', 'boomer', 'cowboys', 'edward', 'charles', 'booboo', 'coffee', 'xxxxxx', 'bulldog', 'ncc1701', 'rabbit', 'peanut', 'johnny', 'gandalf', 'spanky', 'winter', 'brandy', 'compaq', 'carlos', 'tennis', 'brandon', 'fender', 'anthony', 'blowme', 'ferrari', 'cookie', 'chicken', 'maverick', 'chicago', 'joseph', 'diablo', 'sexsex', 'hardcore', '666666', 'willie', 'welcome', 'panther', 'yamaha', 'justin', 'banana', 'driver', 'marine', 'angels', 'fishing', 'maddog', 'hooters', 'wilson', 'butthead', 'dennis', 'fucking', 'captain', 'bigdick', 'chester', 'smokey', 'xavier', 'steven', 'viking', 'snoopy', 'eagles', 'winner', 'samantha', 'miller', 'flower', 'firebird', 'butter', 'united', 'turtle', 'steelers', 'tiffany', 'zxcvbn', 'tomcat', 'bond007', 'doctor', 'gateway', 'gators', 'junior', 'thx1138', 'badboy', 'debbie', 'spider', 'melissa', 'booger', 'flyers', 'matrix', 'scooby', 'walter', 'cumshot', 'boston', 'braves', 'yankee', 'barney', 'victor', 'tucker', 'princess', 'mercedes', 'doggie', 'zzzzzz', 'gunner', 'horney', 'johnson', 'member', 'donald', 'bigdaddy', 'bronco', 'voyager', 'rangers', 'birdie', 'trouble', 'topgun', 'bigtits', 'bitches', 'qazwsx', 'lakers', 'rachel', 'slayer', 'london', 'marlboro', 'srinivas', 'internet', 'action', 'carter', 'jasper', 'monster', 'teresa', 'jeremy', '11111111', 'crystal', 'pussies', 'rocket', 'theman', 'oliver', 'prince', 'amateur', '7777777', 'muffin', 'redsox', 'testing', 'shannon', 'murphy', 'hannah', 'eagle1', 'mother', 'nathan', 'raiders', 'forever', 'angela', 'lovers', 'suckit', 'gregory', 'whatever', 'nicholas', 'helpme', 'jackie', 'monica', 'midnight', 'college', 'startrek', 'sierra', 'leather', '232323', 'beavis', 'bigcock', 'sophie', 'ladies', 'naughty', 'giants', 'blonde', 'fucked', 'golden', 'sandra', 'pookie', 'packers', 'einstein', 'dolphins', 'winston', 'warrior', '8675309', 'zxcvbnm', 'nipples', 'victoria', 'asdfgh', 'vagina', 'toyota', 'travis', 'hotdog', 'extreme', 'redskins', 'erotic', 'freddy', 'arsenal', 'access14', 'nipple', 'iloveyou', 'florida', 'legend', 'success', 'rosebud', 'jaguar', 'cooper', 'scorpio', 'mountain', 'madison', '987654', 'brazil', 'lauren', 'squirt', 'alexis', 'bonnie', 'peaches', 'jasmine', 'qwertyui', 'danielle', 'beaver', 'runner', 'swimming', 'dolphin', 'gordon', 'casper', 'stupid', 'saturn', 'gemini', 'apples', 'august', 'canada', 'blazer', 'cumming', 'hunting', 'rainbow', '112233', 'arthur', 'calvin', 'shaved', 'surfer', 'samson', 'racing', 'hentai', 'newyork', 'little', 'redwings', 'sticky', 'cocacola', 'animal', 'broncos', 'private', 'skippy', 'marvin', 'blondes', 'apollo', 'parker', 'sydney', 'voodoo', 'magnum', 'abgrtyu', '777777', 'dreams', 'maxwell', 'rush2112', 'russia', 'scorpion', 'rebecca', 'tester', 'mistress', 'phantom', 'albert']
dictionary_words = [
    "apple", "banana", "orange", "password", "qwerty", "house", "computer", "table", "keyboard", "sunshine", 
    "mountain", "river", "flower", "butterfly", "chair", "window", "cloud", "elephant", "guitar", "piano", 
    "cat", "dog", "fish", "bird", "rabbit", "snake", "lion", "tiger", "bear", "monkey", 
    "star", "moon", "planet", "galaxy", "universe", "earth"
]

names = [
    "john", "mary", "alex", "emily", "james", "sophia", "david", "olivia", "michael", "emma", 
    "jacob", "ava", "william", "isabella", "noah", "mia", "logan", "charlotte", "ethan", "harper", 
    "benjamin", "abigail", "daniel", "amelia", "samuel", "sarah", "ryan", "hannah", "nathan", "grace", 
    "andrew", "ella", "matthew", "zoey", "liam", "lily", "jayden", "chloe"
]

countries = [
    "USA", "UK", "Canada", "Australia", "Germany", "France", "Italy", "Japan", "China", "Brazil", 
    "India", "Russia", "Mexico", "Spain", "South Korea", "Argentina", "Turkey", "Indonesia", "Netherlands", 
    "Saudi Arabia", "Egypt", "South Africa", "Thailand", "Vietnam", "Philippines", "Iran", "Pakistan", 
    "Nigeria", "Bangladesh", "Ethiopia", "Colombia", "Kenya", "Ukraine", "Myanmar", "Sudan"
]

years = [str(year) for year in range(1970, 2025)]

## HELPER FUNCTION
def ensure_users_file():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as file:
            pass

def read_users():
    users = {}
    salts = {}
    with open(USERS_FILE, "r") as file:
        for line in file:
            data = line.strip().split(":")
            username = data[0]
            passwords = data[1:len(data)-1]
            salt = data[-1]
            users[username] = passwords
            salts[username] = salt
    return users, salts


def write_user(username, passwords, salt):
    with open(USERS_FILE, "a") as file:
        file.write(f"{username}:{':'.join(passwords)}:{salt}\n")


def chaff_tail(password, tail_length):
    
    tail = password[-tail_length:]
    chaffed_tail = ""
    for char in tail:
        if char.isalpha():
            if char.islower():
                chaffed_tail += random.choice(string.ascii_lowercase)
            else:
                chaffed_tail += random.choice(string.ascii_uppercase)
        elif char.isdigit():
            chaffed_tail += random.choice(string.digits)
        else:
            chaffed_tail += random.choice(string.punctuation)
    honeyword = password[:-tail_length] + chaffed_tail
    return honeyword


def replace_substrings(password):
    categories = {
        "dictionary_words": dictionary_words,
        "names": names,
        "countries": countries,
        "years": years
    }
    substrings = {}
    for category, words in categories.items():
        for word in words:
            if word.lower() in password.lower():
                if category not in substrings:
                    substrings[category] = []
                substrings[category].append(word)
    if substrings:
        # Randomly choose how many substrings to replace
        num_substrings_to_replace = random.randint(1, len(substrings))
        # Randomly choose the substrings to replace
        categories_to_replace = random.sample(list(substrings.keys()), num_substrings_to_replace)
        replaced_password = password
        for category_to_replace in categories_to_replace:
            substring_to_replace = random.choice(substrings[category_to_replace])
            # Get the indices of the original substring in the password
            matches = [m.start() for m in re.finditer(re.escape(substring_to_replace), replaced_password, flags=re.IGNORECASE)]
            for match_index in matches:
                original_substring = replaced_password[match_index:match_index+len(substring_to_replace)]
                replacement_candidates = [word for word in categories[category_to_replace] if word.lower() != substring_to_replace.lower()]
                replacement = random.choice(replacement_candidates)
                # Apply case of original substring to replacement
                replaced_chars = []
                for orig_char, new_char in zip(original_substring, replacement):
                    if orig_char.isupper():
                        replaced_chars.append(new_char.upper())
                    elif orig_char.islower():
                        replaced_chars.append(new_char.lower())
                    else:
                        replaced_chars.append(new_char)
                replacement = ''.join(replaced_chars)
                # Replace the chosen substring with the replacement
                replaced_password = replaced_password[:match_index] + replacement + replaced_password[match_index+len(substring_to_replace):]
        return replaced_password
    else:
        return password
    

def generate_honeywords(password, num_honeywords=N):
    honeywords = set()  # Using a set to ensure uniqueness
    tail_length = random.randint(1, len(password))
    while len(honeywords) < num_honeywords:
        if password in common_passwords:
            honeywords.add(random.choice(common_passwords))
        else:
            honeyword = replace_substrings(password)
            if honeyword == password:
                honeyword = chaff_tail(password, tail_length)
            else:
                honeyword = replace_substrings(password)
            honeywords.add(honeyword)
    return list(honeywords)


def shuffle_list(input_list):
    n = len(input_list)
    rand_bytes = bytearray(os.urandom(n))
    zipped = zip(rand_bytes, input_list)
    sorted_zip = sorted(zipped)
    shuffled_list = [item[1] for item in sorted_zip]
    
    return shuffled_list

def hash_pwd(text, salt):
    # Create a SHA-256 hash object
    sha256_hash = hashlib.sha256()

    # Convert the text and salt to bytes and update the hash object
    text_bytes = text.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    sha256_hash.update(text_bytes + salt_bytes)

    # Get the hexadecimal digest of the hash
    hash_digest = sha256_hash.hexdigest()

    return hash_digest

def encrypt_aes_cbc(plaintext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_plaintext = plaintext + b'\x00' * (16 - len(plaintext) % 16)
    ciphertext = iv + cipher.encrypt(padded_plaintext)
    return ciphertext

def decrypt_aes_cbc(ciphertext, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b'\x00')

def honeychecker_send(command, username, index):
    honeychecker_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    honeychecker_socket.connect(HONEYCHECKER_ADDRESS)

    honeychecker_public_key = RSA.import_key(honeychecker_socket.recv(4096))
    session_key = get_random_bytes(16)  ##AES KEY

    cipher_rsa = PKCS1_OAEP.new(honeychecker_public_key)    ##Ensure proper padding when encrypting
    encrypted_session_key = cipher_rsa.encrypt(session_key) ##Encrypt aes key to send
    honeychecker_socket.send(encrypted_session_key)         ## send encrypted key

    data = f"{command}:{username}:{index}".encode('utf-8')

    iv = get_random_bytes(16)

    ciphertext = encrypt_aes_cbc(data, session_key, iv)
    honeychecker_socket.sendall(ciphertext)

    if command == 'login':
        response = honeychecker_socket.recv(1024)
        iv = response[:16]
        response = response[16:]
        response = decrypt_aes_cbc(response, session_key, iv).decode()

        honeychecker_socket.close()
        return response
    honeychecker_socket.close()

def show_login_page():
    option_frame.pack_forget()
    login_frame.pack()
    clear_login_fields()

def show_register_page():
    option_frame.pack_forget()
    register_frame.pack()
    clear_register_fields()

def show_option_page(frame):
    frame.pack_forget()
    option_frame.pack()

def exit_program():
    root.destroy()
    #client_socket.close()


def send_malicious_attempt_email(email):
    SMTP_SERVER = "smtp.gmail.com"
    PORT = 587
    EMAIL = "arora.apoorva02@gmail.com"
    PASSWORD = ""

    context = ssl.create_default_context()

    with smtplib.SMTP(SMTP_SERVER, PORT) as server:
        server.starttls(context=context)
        server.login(EMAIL, PASSWORD)
        
        subject = "Malicious Login attempt"
        body = """\
        We have detected a malicious attempt to login to your account. For security reasons, we have temporarily disabled your account. Please change your password as soon as possible.
        """
        
        message = f"Subject: {subject}\n\n{body}"
        
        server.sendmail(EMAIL, email, message)
    # Plain text content
    

    


## Get username and password and send it to server to validate
def login():
    username = login_username_entry.get()
    password = login_password_entry.get()

    users, salts = read_users()

    if username not in users:
        messagebox.showinfo("Login Status", "Invalid Username")
        del(password)
        clear_login_fields()
        return
    
    hashed_pwd = hash_pwd(password, salts[username])
    del(password)
    try:
        index = users[username].index(hashed_pwd)
    except:
        index = 0
    ## Check index with honeychecker

    if username in users and hashed_pwd in users[username]:
        honey_response = honeychecker_send("login", username, index)
        if honey_response == "Yes":
            messagebox.showinfo("Login Status", "Login succesful")
        else:
            messagebox.showerror("Login Status", "Malicious attempt to login detected")
            send_malicious_attempt_email(username)
    else:
        messagebox.showerror("Login Status", "Invalid credentials")

    clear_login_fields()


def register():
    email = register_email_entry.get()
    password = register_password_entry.get()
    confirm_password = confirm_password_entry.get()

    if len(password) < 6:
        messagebox.showerror("Registration Status", "Password must be at least 6 characters long")
        clear_register_fields()
        return

    if password != confirm_password:
        messagebox.showerror("Registration Status", "Passwords do not match")
        clear_register_fields()
        return

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        messagebox.showerror("Registration Status", "Invalid email address")
        clear_register_fields()
        return

    users, salts = read_users()
            
    if email in users:
        messagebox.showerror("Registration Status", "Email already exists")
        clear_register_fields()
        return
    
    else:
        salt = os.urandom(16).hex()

        passwords = generate_honeywords(password)
        passwords.append(password)
        passwords = shuffle_list(passwords)
        print(passwords)
        
        index = passwords.index(password)
        honeychecker_send("register", email, index)
        hashed_passwords = [hash_pwd(pwd, salt) for pwd in passwords]

        del(passwords)
        del(password)

        write_user(email, hashed_passwords, salt)
        messagebox.showinfo("Registration Status", "Registration successful")

    clear_register_fields()


def clear_login_fields():
    login_username_entry.delete(0, 'end')
    login_password_entry.delete(0, 'end')

def clear_register_fields():
    register_email_entry.delete(0, 'end')
    register_password_entry.delete(0, 'end')
    confirm_password_entry.delete(0, 'end')


ensure_users_file()

root = tk.Tk()
root.title("Login")
root.geometry("400x300")

option_frame = ttk.Frame(root)
option_frame.pack(pady=20)

login_frame = ttk.Frame(root)
register_frame = ttk.Frame(root)

login_label = ttk.Label(login_frame, text="Login", font=('Helvetica', 18, 'bold'))
login_label.pack(pady=10)

login_username_label = ttk.Label(login_frame, text="Email:", font=('Helvetica', 12))
login_username_label.pack()
login_username_entry = ttk.Entry(login_frame)
login_username_entry.pack(pady=5)

login_password_label = ttk.Label(login_frame, text="Password:", font=('Helvetica', 12))
login_password_label.pack()
login_password_entry = ttk.Entry(login_frame, show="*")
login_password_entry.pack(pady=5)

login_button = ttk.Button(login_frame, text="Login", command=login)
login_button.pack(pady=10)

back_button_login = ttk.Button(login_frame, text="Back", command=lambda: show_option_page(login_frame))
back_button_login.pack(pady=5)

register_label = ttk.Label(register_frame, text="Register", font=('Helvetica', 18, 'bold'))
register_label.pack(pady=10)

register_email_label = ttk.Label(register_frame, text="Email:", font=('Helvetica', 12))
register_email_label.pack()
register_email_entry = ttk.Entry(register_frame)
register_email_entry.pack(pady=5)

register_password_label = ttk.Label(register_frame, text="Password:", font=('Helvetica', 12))
register_password_label.pack()
register_password_entry = ttk.Entry(register_frame, show="*")
register_password_entry.pack(pady=5)

confirm_password_label = ttk.Label(register_frame, text="Confirm Password:", font=('Helvetica', 12))
confirm_password_label.pack()
confirm_password_entry = ttk.Entry(register_frame, show="*")
confirm_password_entry.pack(pady=5)

register_button = ttk.Button(register_frame, text="Register", command=register)
register_button.pack(pady=10)

back_button_register = ttk.Button(register_frame, text="Back", command=lambda: show_option_page(register_frame))
back_button_register.pack(pady=5)

option_label = ttk.Label(option_frame, text="Select an option:", font=('Helvetica', 14))
option_label.pack(pady=10)

login_button = ttk.Button(option_frame, text="Login", command=show_login_page)
login_button.pack(pady=5)

register_button = ttk.Button(option_frame, text="Register", command=show_register_page)
register_button.pack(pady=5)

exit_button = ttk.Button(option_frame, text="Exit", command=exit_program)
exit_button.pack(pady=5)

root.mainloop()
    
