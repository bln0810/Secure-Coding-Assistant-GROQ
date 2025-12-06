# Python Vulnerabilities Test Cases

# 1. SQL Injection Vulnerability
def get_user_data(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    return execute_query(query)

# 2. Command Injection Vulnerability
def process_file(filename):
    os.system("process_file " + filename)
    return "File processed"

# 3. Path Traversal Vulnerability
def read_user_file(filepath):
    with open(filepath) as f:
        return f.read()

# 4. XSS Vulnerability in Template
def display_user_message(message):
    return f"<div>{message}</div>"

# 5. Insecure Deserialization
def load_user_preferences(data):
    return pickle.loads(data)

# 6. Hardcoded Credentials
def connect_to_database():
    return mysql.connect(host="localhost", user="admin", password="admin123")

# 7. Weak Cryptography
def encrypt_password(password):
    return md5(password.encode()).hexdigest()