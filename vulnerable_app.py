#!/usr/bin/env python3
from flask import Flask, request, render_template_string, redirect, url_for, make_response
import sqlite3
import os
import pickle
import subprocess

app = Flask(__name__)
app.secret_key = 'vulnerable_key_123'

# Page d'accueil vulnérable à XSS
@app.route('/')
def home():
    name = request.args.get('name', 'Guest')
    return render_template_string(f'''
        <h1>Welcome {name}!</h1>
        <a href="/login">Login</a><br>
        <a href="/search">Search</a><br>
        <a href="/profile">Profile</a><br>
        <a href="/admin">Admin Panel</a><br>
        <a href="/upload">File Upload</a><br>
        <a href="/cmd">Command Exec</a><br>
    ''')

# Page de login vulnérable à l'injection SQL
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        
        # Injection SQL intentionnelle
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        cursor.execute(query)
        
        user = cursor.fetchone()
        conn.close()
        
        if user:
            resp = make_response(redirect('/profile'))
            resp.set_cookie('user_id', str(user[0]))  # Non sécurisé
            return resp
        else:
            return "Login failed", 401
    
    return '''
        <form method="POST">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <input type="submit" value="Login">
        </form>
    '''

# Page de recherche vulnérable à XSS et LFI
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template_string(f'''
        <h1>Search Results for: {query}</h1>
        <form>
            <input type="text" name="q" value="{query}">
            <input type="submit" value="Search">
        </form>
        <!-- Try ?q=../../etc/passwd -->
    ''')

# Page de profil vulnérable à IDOR
@app.route('/profile')
def profile():
    user_id = request.cookies.get('user_id', '1')  # Default to admin (IDOR)
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id={user_id}")
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return f'''
            <h1>Profile</h1>
            <p>ID: {user[0]}</p>
            <p>Username: {user[1]}</p>
            <p>Email: {user[3]}</p>
            <p>Role: {user[4]}</p>
        '''
    return "User not found", 404

# Panel admin vulnérable à la faille de contrôle d'accès
@app.route('/admin')
def admin():
    user_id = request.cookies.get('user_id', '1')
    if user_id == '1':  # Only admin has ID 1
        return '''
            <h1>Admin Panel</h1>
            <p>Welcome Admin!</p>
            <a href="/delete_all">Delete All Users</a>
        '''
    return "Access denied", 403

# Upload de fichier vulnérable
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            filename = file.filename
            file.save(os.path.join('uploads', filename))
            return f"File {filename} uploaded successfully!"
    
    return '''
        <form method="POST" enctype="multipart/form-data">
            <input type="file" name="file">
            <input type="submit" value="Upload">
        </form>
    '''

# Exécution de commande vulnérable
@app.route('/cmd')
def cmd():
    command = request.args.get('cmd', 'whoami')
    try:
        output = subprocess.check_output(command, shell=True)
        return f"<pre>Command: {command}\nOutput:\n{output.decode()}</pre>"
    except Exception as e:
        return f"Error executing command: {str(e)}"

# Désérialisation vulnérable
@app.route('/deserialize')
def deserialize():
    data = request.args.get('data', '')
    try:
        obj = pickle.loads(bytes.fromhex(data))
        return "Object deserialized!"
    except:
        return "Invalid data"

# Route pour supprimer tous les utilisateurs (CSRF)
@app.route('/delete_all', methods=['POST'])
def delete_all():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id > 1")  # Garder l'admin
    conn.commit()
    conn.close()
    return "All users deleted!"

def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT
        )
    ''')
    
    # Ajouter un admin et un utilisateur normal
    cursor.execute("INSERT OR IGNORE INTO users VALUES (1, 'admin', 'admin123', 'admin@example.com', 'admin')")
    cursor.execute("INSERT OR IGNORE INTO users VALUES (2, 'user', 'password123', 'user@example.com', 'user')")
    
    conn.commit()
    conn.close()

if __name__ == '__main__':
    # Créer le répertoire d'upload s'il n'existe pas
    os.makedirs('uploads', exist_ok=True)
    
    # Initialiser la base de données
    init_db()
    
    # Démarrer l'application en mode debug (ce qui est aussi une vulnérabilité)
    app.run(debug=True, host='0.0.0.0')