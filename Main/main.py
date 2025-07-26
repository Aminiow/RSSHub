from flask import Flask, request, redirect, url_for, render_template, session
import feedparser
import sqlite3
import threading
import time
import traceback
from functools import wraps

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a strong, random key!

DB = 'RSSHub.db'
FETCH_INTERVAL = 300  # 5 minutes (in seconds)

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
                    return render_template('error.html', error_message="Access Denied: You do not have permission to view this page."), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Global Error Handler ---
@app.errorhandler(Exception)
def handle_all_errors(e):
    print(f"Unhandled Exception: {e}")
    traceback.print_exc()
    return render_template('error.html', error_message=f"An unexpected error occurred: {e}"), 500

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

    return render_template('index.html', grouped_items=grouped_items)

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
            session['user_id'] = user[0] # Store user ID for self-deletion check
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid credentials. Please try again.'
    return render_template('login.html', error=error)

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

    return render_template('dashboard.html', feeds=feeds, message=message, message_type=message_type)

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

    return render_template('manage_users.html', users=users, message=message, message_type=message_type)

# --- Application Entry Point ---
if __name__ == '__main__':
    init_db()
    # Start the background feed fetching thread
    threading.Thread(target=fetch_feeds_loop, daemon=True).start()
    # Run the Flask application
    app.run(debug=True, host='0.0.0.0', port=5000)
