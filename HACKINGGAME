from flask import Flask, request, render_template_string, session, redirect, url_for, make_response
from faker import Faker
import random
import string
import time
import os
import sys
import subprocess

app = Flask(__name__)
app.secret_key = 'supersecretkey'
fake = Faker()

# Directory and virtual environment setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
VENV_DIR = os.path.join(BASE_DIR, 'game_env')
VM_DIR = os.path.join(BASE_DIR, 'virtual_machine')

# Create necessary directories
os.makedirs(VENV_DIR, exist_ok=True)
os.makedirs(VM_DIR, exist_ok=True)

# Create virtual environment if not exists
if not os.path.exists(os.path.join(VENV_DIR, 'bin' if sys.platform != 'win32' else 'Scripts')):
    subprocess.check_call([sys.executable, '-m', 'venv', VENV_DIR])

# Activate virtual environment
activate_this = os.path.join(VENV_DIR, 'bin', 'activate_this.py' if sys.platform != 'win32' else 'Scripts\\activate_this.py')
with open(activate_this) as f:
    exec(f.read(), {'__file__': activate_this})

def generate_credentials(level):
    return {
        'username': fake.user_name(),
        'password': ''.join(random.choices(string.ascii_letters + string.digits, k=8)),
        'role': 'user',
        'level': level
    }

# Mock data
admin_credentials = {'username': 'admin', 'password': 'adminpass', 'role': 'admin'}
levels = [generate_credentials(i + 1) for i in range(20)]  # Increased levels to 20

# Simple HTML templates for the game
login_page = """
<h1>Login</h1>
<form method="post" action="/login">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Login">
</form>
"""

admin_page = """
<h1>Admin Panel</h1>
<p>Welcome, Admin!</p>
<p>Your task is to find and fix vulnerabilities.</p>
<a href="/logout">Logout</a>
"""

user_page = """
<h1>User Panel - Level {{ level }}</h1>
<p>Welcome, {{username}}!</p>
<p>{{hint}}</p>
<a href="/logout">Logout</a>
"""

# Define hints for each level
hints = {
    1: "Try basic SQL Injection with ' OR '1'='1",
    2: "Try adding ' OR '1'='1 to the password",
    3: "Look for XSS vulnerabilities in the search box.",
    4: "Try injecting a <script>alert('XSS')</script> tag.",
    5: "Find a way to inject SQL through multiple parameters.",
    6: "Try a more complex SQL Injection attack.",
    7: "Look for different vectors for XSS.",
    8: "Try DOM-based XSS attack vectors.",
    9: "Explore potential authentication bypass.",
    10: "Look for directory traversal vulnerabilities.",
    11: "Try advanced SQL Injection with union-based attack.",
    12: "Try time-based blind SQL Injection.",
    13: "Attempt to bypass advanced XSS filters.",
    14: "Exploit CSRF vulnerabilities in forms.",
    15: "Look for local file inclusion (LFI) vulnerabilities.",
    16: "Try remote file inclusion (RFI) attacks.",
    17: "Explore advanced authentication bypass techniques.",
    18: "Attempt to bypass multi-factor authentication.",
    19: "Look for remote code execution (RCE) vulnerabilities.",
    20: "Try to find zero-day vulnerabilities akin to Google security."
}

@app.route('/')
def index():
    return login_page

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if username == admin_credentials['username'] and password == admin_credentials['password']:
        session['username'] = username
        session['role'] = admin_credentials['role']
        return admin_page

    for creds in levels:
        if username == creds['username'] and password == creds['password']:
            session['username'] = username
            session['role'] = creds['role']
            session['level'] = creds['level']
            return render_template_string(user_page, username=username, level=session['level'], hint=hints[session['level']])

    return "Invalid credentials! <a href='/'>Try again</a>"

@app.route('/logout')
def logout():
    session.clear()
    return "Logged out! <a href='/'>Login again</a>"

@app.route('/next_level')
def next_level():
    if 'level' in session:
        current_level = session['level']
        if current_level < len(levels):
            session['level'] += 1
            next_creds = levels[session['level'] - 1]
            session['username'] = next_creds['username']
            return render_template_string(user_page, username=session['username'], level=session['level'], hint=hints[session['level']])
        else:
            return "Congratulations! You've completed all levels! <a href='/logout'>Logout</a>"
    return redirect(url_for('index'))

# Adding routes to demonstrate vulnerabilities
@app.route('/vulnerable_query', methods=['GET'])
def vulnerable_query():
    level = session.get('level', 0)
    if level in [1, 2, 5, 6, 11, 12]:
        username = request.args.get('username')
        query = f"SELECT * FROM users WHERE username = '{username}'"
        # Simulating SQL injection vulnerability
        if username == "admin' OR '1'='1":
            return "Welcome, admin!"
        elif level == 12 and "SLEEP" in username.upper():
            time.sleep(int(username.split('SLEEP(')[1].split(')')[0]))
            return "Time-based SQL Injection detected!"
        return f"Query executed: {query}"
    return redirect(url_for('index'))

@app.route('/vulnerable_xss', methods=['GET'])
def vulnerable_xss():
    level = session.get('level', 0)
    if level in [3, 4, 7, 8, 13]:
        search = request.args.get('search')
        response = make_response(f"Search results for: {search}")
        # Simulating XSS vulnerability
        if level == 13:
            search = search.replace("<", "&lt;").replace(">", "&gt;")
        response.set_cookie('last_search', search)
        return response
    return redirect(url_for('index'))

@app.route('/vulnerable_csrf', methods=['POST'])
def vulnerable_csrf():
    level = session.get('level', 0)
    if level in [14]:
        # Simulate CSRF vulnerability
        token = request.form.get('csrf_token')
        if token != session.get('csrf_token'):
            return "CSRF attack detected!"
        return "CSRF token valid!"
    return redirect(url_for('index'))

@app.route('/vulnerable_file_inclusion', methods=['GET'])
def vulnerable_file_inclusion():
    level = session.get('level', 0)
    if level in [15, 16]:
        file = request.args.get('file')
        if level == 15 and '..' in file:
            return "Local File Inclusion detected!"
        elif level == 16 and 'http://' in file:
            return "Remote File Inclusion detected!"
        return f"File included: {file}"
    return redirect(url_for('index'))

@app.route('/vulnerable_auth_bypass', methods=['POST'])
def vulnerable_auth_bypass():
    level = session.get('level', 0)
    if level in [17, 18]:
        username = request.form['username']
        password = request.form['password']
        if level == 17 and password == "bypass":
            return "Authentication bypassed!"
        elif level == 18 and password == "mfa-bypass":
            return "Multi-factor authentication bypassed!"
        return "Invalid credentials!"
    return redirect(url_for('index'))

@app.route('/vulnerable_rce', methods=['POST'])
def vulnerable_rce():
    level = session.get('level', 0)
    if level in [19, 20]:
        command = request.form['command']
        if level == 19 and "rm -rf /" in command:
            return "Remote Code Execution detected!"
        elif level == 20 and "curl" in command:
            return "Zero-day vulnerability detected!"
        return f"Command executed: {command}"
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
