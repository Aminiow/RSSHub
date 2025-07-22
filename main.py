from flask import Flask, request, redirect, url_for, render_template_string, session
import feedparser
import sqlite3
import threading
import time
import traceback
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a strong, random key!

DB = 'rss_app.db'
FETCH_INTERVAL = 300  # 5 minutes (in seconds)

# --- Main CSS for all pages ---
MAIN_CSS = '''
<style>
body { font-family: Arial, sans-serif; margin: 20px; background: #f0f2f5; color: #333; line-height: 1.6; }
h1, h2, h3 { color: #444; margin-top: 1.5em; margin-bottom: 0.8em; }
h1 { text-align: center; color: #2c3e50; }
table { border-collapse: collapse; width: 100%; background: white; margin-bottom: 20px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); border-radius: 8px; overflow: hidden; }
th, td { padding: 12px 15px; border: 1px solid #e0e0e0; text-align: left; }
th { background: #f8f8f8; font-weight: bold; color: #555; }
tr:nth-child(even) { background-color: #f9f9f9; }
a { color: #007bff; text-decoration: none; transition: color 0.2s ease-in-out; }
a:hover { text-decoration: underline; color: #0056b3; }
input[type=text], input[type=password], input[type=url], select {
    padding: 10px;
    margin-bottom: 15px;
    border: 1px solid #ccc;
    border-radius: 4px;
    width: calc(100% - 22px); /* Account for padding and border */
    box-sizing: border-box;
}
input[type=submit], button {
    padding: 10px 20px;
    cursor: pointer;
    background: #28a745;
    border: none;
    color: white;
    border-radius: 4px;
    font-size: 1em;
    transition: background-color 0.2s ease-in-out;
}
input[type=submit]:hover, button:hover { background: #218838; }
.message {
    padding: 12px 20px;
    margin-bottom: 20px;
    border-radius: 5px;
    font-weight: bold;
    border: 1px solid transparent;
}
.message.error { background: #f8d7da; color: #721c24; border-color: #f5c6cb; }
.message.success { background: #d4edda; color: #155724; border-color: #c3e6cb; }
.feed-group {
    margin-bottom: 30px;
    padding: 20px;
    background: white;
    border-radius: 8px;
    box-shadow: 0 4px 10px rgba(0,0,0,0.08);
}
.feed-group h2 { margin-top: 0; color: #34495e; }
.small-link { font-size: 0.85em; color: #777; margin-left: 10px; }
nav { text-align: center; margin-bottom: 25px; }
nav a { margin: 0 15px; font-weight: bold; }
form { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); margin-bottom: 20px; }
form label { display: block; margin-bottom: 5px; font-weight: bold; color: #555; }
</style>
'''

# --- Database Operations (using lambdas for conciseness) ---

# Helper to connect and execute SQL
def _execute_sql(sql, params=(), fetch_one=False, fetch_all=False, commit=False):
    try:
        with sqlite3.connect(DB) as con:
            cur = con.cursor()
            cur.execute(sql, params)
            if commit:
                con.commit()
            if fetch_one:
                return cur.fetchone()
            if fetch_all:
                return cur.fetchall()
    except sqlite3.IntegrityError as e:
        raise e # Re-raise integrity errors for specific handling (e.g., unique constraints)
    except Exception as e:
        print(f"Database error: {e}")
        traceback.print_exc()
        raise # Re-raise other exceptions for error handling

# Initialize database tables and create a default owner user
def init_db():
    try:
        with sqlite3.connect(DB) as con:
            cur = con.cursor()
            # Use executescript for multiple statements
            cur.executescript('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT UNIQUE,
                    password TEXT,
                    role TEXT
                );
                CREATE TABLE IF NOT EXISTS feeds (
                    id INTEGER PRIMARY KEY,
                    name TEXT,
                    url TEXT UNIQUE
                );
                CREATE TABLE IF NOT EXISTS items (
                    id INTEGER PRIMARY KEY,
                    feed_id INTEGER,
                    title TEXT,
                    link TEXT,
                    published TEXT,
                    UNIQUE(feed_id, link)
                );
            ''')
            con.commit() # Commit after executescript

            # Create default owner if not exists
            if not _execute_sql('SELECT * FROM users WHERE role = "owner"', fetch_one=True):
                _execute_sql('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', ('owner', 'ownerpass', 'owner'), commit=True)

    except Exception as e:
        print(f"DB initialization error: {e}")
        traceback.print_exc()

# Fetch all feeds (id, name, url)
fetch_feeds = lambda: _execute_sql('SELECT id, name, url FROM feeds', fetch_all=True)

# Insert feed
add_feed = lambda name, url: _execute_sql('INSERT INTO feeds (name, url) VALUES (?, ?)', (name, url), commit=True)

# Delete feed and its items
def delete_feed(feed_id):
    _execute_sql('DELETE FROM feeds WHERE id=?', (feed_id,), commit=True)
    _execute_sql('DELETE FROM items WHERE feed_id=?', (feed_id,), commit=True)

# Get last N items of a feed
get_last_feed_items = lambda feed_id, limit=10: _execute_sql('''
    SELECT title, link, published FROM items
    WHERE feed_id=?
    ORDER BY datetime(published) DESC
    LIMIT ?
''', (feed_id, limit), fetch_all=True)

# Insert feed item (ignore duplicates)
add_feed_item = lambda feed_id, title, link, published: _execute_sql(
    'INSERT OR IGNORE INTO items (feed_id, title, link, published) VALUES (?, ?, ?, ?)',
    (feed_id, title, link, published), commit=True
)

# Fetch user by username
get_user = lambda username: _execute_sql('SELECT id, username, password, role FROM users WHERE username=?', (username,), fetch_one=True)

# Fetch all users
fetch_users = lambda: _execute_sql('SELECT id, username, role FROM users', fetch_all=True)

# Add user (admin or owner)
add_user = lambda username, password, role: _execute_sql('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, password, role), commit=True)

# Delete user by id
delete_user = lambda user_id: _execute_sql('DELETE FROM users WHERE id=?', (user_id,), commit=True)

# --- Background Feed Fetcher ---
def fetch_feeds_loop():
    while True:
        try:
            feeds = fetch_feeds()
            for feed_id, feed_name, feed_url in feeds:
                try:
                    d = feedparser.parse(feed_url)
                    if d.bozo:
                        print(f"Warning: Feed parse error for {feed_url}: {d.bozo_exception}")
                        continue

                    for entry in d.entries:
                        published = entry.get('published', '') or entry.get('updated', '') or ''
                        add_feed_item(feed_id, entry.title, entry.link, published)
                except Exception as e:
                    print(f"Failed to fetch {feed_url}: {e}")
                    traceback.print_exc()
        except Exception as e:
            print(f"Error in fetch_feeds_loop: {e}")
            traceback.print_exc()
        time.sleep(FETCH_INTERVAL)

# --- Authentication Decorator ---
def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login'))
            if role:
                user_role = session.get('role', '')
                # Owner can do everything, other roles are restricted
                if user_role != 'owner' and user_role != role:
                    return render_template_string(f"{MAIN_CSS}<h1>Access Denied</h1><p>You do not have permission to view this page.</p><a href='{url_for('dashboard')}'>Back to Dashboard</a>"), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Global Error Handler ---
@app.errorhandler(Exception)
def handle_all_errors(e):
    print(f"Unhandled Exception: {e}")
    traceback.print_exc()
    page = f'''
    {MAIN_CSS}
    <div style="text-align: center; padding: 50px;">
        <h1>Oops! Something went wrong.</h1>
        <p>An unexpected error occurred. Please try again later.</p>
        <p>Error details: {e}</p>
        <a href="{url_for('index')}" style="display: inline-block; margin-top: 20px; padding: 10px 20px; background-color: #dc3545; color: white; border-radius: 5px;">Back to Home</a>
    </div>
    '''
    return render_template_string(page), 500

# --- Routes ---

@app.route('/')
def index():
    all_feeds = fetch_feeds()
    grouped_items = []
    try:
        for feed_id, feed_name, feed_url in all_feeds:
            items = get_last_feed_items(feed_id)
            grouped_items.append({'feed_name': feed_name, 'feed_url': feed_url, 'feed_items': items})
    except Exception as e:
        print(f"Error fetching grouped items for index page: {e}")
        grouped_items = [] # Ensure grouped_items is empty on error

    page = '''
    ''' + MAIN_CSS + '''
    <body>
      <h1>RSS Feed Items</h1>
      <nav>
        <a href="{{ url_for('dashboard') }}">Admin Dashboard</a>
      </nav>

      {% if grouped_items %}
        {% for feed in grouped_items %}
          <div class="feed-group">
            <h2>{{ feed.feed_name }} <small class="small-link">(<a href="{{ feed.feed_url }}" target="_blank">Feed Link</a>)</small></h2>
            <table>
                <tr><th>Title</th><th>Published</th></tr>
                {% if feed.feed_items %}
                    {% for title, link, published in feed.feed_items %}
                    <tr>
                        <td><a href="{{ link }}" target="_blank">{{ title }}</a></td>
                        <td>{{ published }}</td>
                    </tr>
                    {% endfor %}
                {% else %}
                    <tr><td colspan="2">No items found for this feed.</td></tr>
                {% endif %}
            </table>
          </div>
        {% endfor %}
      {% else %}
        <p style="text-align: center;">No feeds added yet. Please add some from the <a href="{{ url_for('dashboard') }}">Admin Dashboard</a>.</p>
      {% endif %}
    </body>
    '''
    return render_template_string(page, grouped_items=grouped_items)

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        user = get_user(username)
        if user and user[2] == password: # user[2] is the password
            session['logged_in'] = True
            session['username'] = user[1] # user[1] is the username
            session['role'] = user[3] # user[3] is the role
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
    page = '''
    ''' + MAIN_CSS + '''
    <body>
      <div style="max-width: 400px; margin: 50px auto; padding: 30px; background: white; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
        <h1 style="text-align: center; margin-top: 0;">Admin Login</h1>
        <form method="post">
          <label for="username">Username:</label>
          <input type="text" id="username" name="username" required><br>
          <label for="password">Password:</label>
          <input type="password" id="password" name="password" required><br>
          <input type="submit" value="Login">
        </form>
        {% if error %}
          <p class="message error">{{ error }}</p>
        {% endif %}
        <p style="text-align: center; margin-top: 20px;"><a href="{{ url_for('index') }}">Back to Feeds</a></p>
      </div>
    </body>
    '''
    return render_template_string(page, error=error)

@app.route('/logout')
@login_required()
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required()
def dashboard():
    message = ''
    message_type = 'success' # Default message type
    
    if request.method == 'POST':
        # Add feed logic
        name = request.form.get('name', '').strip()
        url = request.form.get('url', '').strip()
        if name and url:
            try:
                # Validate RSS feed URL before adding
                d = feedparser.parse(url)
                if d.bozo:
                    message = f'Invalid RSS feed URL: {d.bozo_exception}'
                    message_type = 'error'
                elif not d.entries:
                    message = 'No entries found in RSS feed. Please check the URL.'
                    message_type = 'error'
                else:
                    add_feed(name, url)
                    message = 'Feed added successfully!'
                    message_type = 'success'
            except sqlite3.IntegrityError:
                message = 'Feed URL already exists. Please use a unique URL.'
                message_type = 'error'
            except Exception as e:
                print(f"Error adding feed: {e}")
                message = 'Failed to add feed due to an unexpected error.'
                message_type = 'error'
        else:
            message = 'Both Feed Name and RSS Feed URL are required.'
            message_type = 'error'
    
    # Remove feed logic (GET request)
    remove_id = request.args.get('remove')
    if remove_id:
        try:
            delete_feed(int(remove_id))
            message = 'Feed removed successfully!'
            message_type = 'success'
        except Exception as e:
            print(f"Error removing feed: {e}")
            message = 'Failed to remove feed due to an unexpected error.'
            message_type = 'error'

    feeds = fetch_feeds() # Re-fetch feeds after any modifications

    page = '''
    ''' + MAIN_CSS + '''
    <body>
      <div style="max-width: 900px; margin: 20px auto; padding: 30px; background: white; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
        <h1 style="text-align: center; margin-top: 0;">Admin Dashboard</h1>
        <nav>
          <a href="{{ url_for('index') }}">Back to Feeds</a> | 
          <a href="{{ url_for('logout') }}">Logout</a>
          {% if session.get('role') == 'owner' %}
          | <a href="{{ url_for('manage_users') }}">Manage Admins</a>
          {% endif %}
        </nav>

        {% if message %}
          <div class="message {{ message_type }}">{{ message }}</div>
        {% endif %}

        <h2>Current Feeds</h2>
        <table>
            <tr><th>ID</th><th>Name</th><th>URL</th><th>Actions</th></tr>
            {% if feeds %}
                {% for id, name, url in feeds %}
                <tr>
                    <td>{{ id }}</td>
                    <td>{{ name }}</td>
                    <td><a href="{{ url }}" target="_blank">{{ url }}</a></td>
                    <td><a href="{{ url_for('dashboard', remove=id) }}" onclick="return confirm('Are you sure you want to remove this feed and all its items?');">Remove</a></td>
                </tr>
                {% endfor %}
            {% else %}
                <tr><td colspan="4">No feeds added yet.</td></tr>
            {% endif %}
        </table>

        <h2>Add New Feed</h2>
        <form method="post">
          <label for="feed_name">Feed Name:</label>
          <input type="text" id="feed_name" name="name" placeholder="e.g., My Favorite Blog" required><br>
          <label for="feed_url">RSS Feed URL:</label>
          <input type="url" id="feed_url" name="url" placeholder="e.g., https://example.com/rss.xml" size="60" required><br>
          <input type="submit" value="Add Feed">
        </form>
      </div>
    </body>
    '''
    return render_template_string(page, feeds=feeds, message=message, message_type=message_type)

@app.route('/manage_users', methods=['GET', 'POST'])
@login_required(role='owner')
def manage_users():
    message = ''
    message_type = 'success'

    if request.method == 'POST':
        # Add user logic
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        role = request.form.get('role', '').strip()
        if username and password and role in ('owner', 'admin'):
            try:
                add_user(username, password, role)
                message = f'User "{username}" added successfully with role "{role}"!'
                message_type = 'success'
            except sqlite3.IntegrityError:
                message = f'Username "{username}" already exists. Please choose a different username.'
                message_type = 'error'
            except Exception as e:
                print(f"Error adding user: {e}")
                message = 'Failed to add user due to an unexpected error.'
                message_type = 'error'
        else:
            message = 'All fields are required, and role must be either "admin" or "owner".'
            message_type = 'error'
    
    # Remove user logic (GET request)
    remove_id = request.args.get('remove')
    if remove_id:
        try:
            user_to_remove = _execute_sql('SELECT id, username, role FROM users WHERE id=?', (remove_id,), fetch_one=True)
            if user_to_remove and user_to_remove[2] == 'owner': # user_to_remove[2] is the role
                message = 'Cannot remove the owner account for security reasons.'
                message_type = 'error'
            elif user_to_remove and str(user_to_remove[0]) == str(session.get('user_id')): # Prevent self-deletion
                 message = 'You cannot remove your own account.'
                 message_type = 'error'
            else:
                delete_user(int(remove_id))
                message = f'User "{user_to_remove[1]}" removed successfully!'
                message_type = 'success'
        except Exception as e:
            print(f"Error removing user: {e}")
            message = 'Failed to remove user due to an unexpected error.'
            message_type = 'error'

    users = fetch_users() # Re-fetch users after any modifications

    page = '''
    ''' + MAIN_CSS + '''
    <body>
      <div style="max-width: 800px; margin: 20px auto; padding: 30px; background: white; border-radius: 8px; box-shadow: 0 4px 10px rgba(0,0,0,0.1);">
        <h1 style="text-align: center; margin-top: 0;">Manage Admin Accounts</h1>
        <nav>
          <a href="{{ url_for('dashboard') }}">Back to Dashboard</a> | 
          <a href="{{ url_for('logout') }}">Logout</a>
        </nav>

        {% if message %}
          <div class="message {{ message_type }}">{{ message }}</div>
        {% endif %}

        <h2>Current Admin Users</h2>
        <table>
          <tr><th>ID</th><th>Username</th><th>Role</th><th>Actions</th></tr>
          {% if users %}
            {% for id, username, role in users %}
            <tr>
              <td>{{ id }}</td>
              <td>{{ username }}</td>
              <td>{{ role }}</td>
              <td>
                {% if role != 'owner' and id != session.get('user_id') %}
                <a href="{{ url_for('manage_users', remove=id) }}" onclick="return confirm('Are you sure you want to remove user \\'{{ username }}\\'?');">Remove</a>
                {% else %}
                &mdash;
                {% endif %}
              </td>
            </tr>
            {% endfor %}
          {% else %}
            <tr><td colspan="4">No admin users found.</td></tr>
          {% endif %}
        </table>

        <h2>Add New Admin User</h2>
        <form method="post">
          <label for="new_username">Username:</label>
          <input type="text" id="new_username" name="username" required><br>
          <label for="new_password">Password:</label>
          <input type="password" id="new_password" name="password" required><br>
          <label for="new_role">Role:</label>
          <select id="new_role" name="role" required>
            <option value="admin">Admin</option>
            <option value="owner">Owner</option>
          </select><br>
          <input type="submit" value="Add User">
        </form>
      </div>
    </body>
    '''
    return render_template_string(page, users=users, message=message, message_type=message_type)

# --- Application Entry Point ---
if __name__ == '__main__':
    init_db()
    # Start the background feed fetching thread
    threading.Thread(target=fetch_feeds_loop, daemon=True).start()
    # Run the Flask application
    app.run(debug=True, host='0.0.0.0', port=5000)
