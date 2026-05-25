from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import pickle
import re
from urllib.parse import urlparse
import pandas as pd
import numpy as np
from tld import get_tld
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishing_detector.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

# Load the trained model
try:
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    model = None

# ============================================================
# Database Models
# ============================================================

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scans = db.relationship('ScanHistory', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(2048), nullable=False)
    prediction = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    benign_prob = db.Column(db.Float, nullable=False)
    defacement_prob = db.Column(db.Float, nullable=False)
    phishing_prob = db.Column(db.Float, nullable=False)
    malware_prob = db.Column(db.Float, nullable=False)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ============================================================
# Feature Extraction Functions
# ============================================================

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.'
        '(0x[0-9a-fA-F]{1,2})\\/)'
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return 1 if match else 0

def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    return 1 if match else 0

def count_dot(url):
    return url.count('.')

def count_www(url):
    return url.count('www')

def count_atrate(url):
    return url.count('@')

def no_of_dir(url):
    urldir = urlparse(url).path
    return urldir.count('/')

def no_of_embed(url):
    urldir = urlparse(url).path
    return urldir.count('//')

def shortening_service(url):
    match = re.search(
        'bit\\.ly|goo\\.gl|shorte\\.st|go2l\\.ink|x\\.co|ow\\.ly|t\\.co|tinyurl|tr\\.im|is\\.gd|cli\\.gs|'
        'yfrog\\.com|migre\\.me|ff\\.im|tiny\\.cc|url4\\.eu|twit\\.ac|su\\.pr|twurl\\.nl|snipurl\\.com|'
        'short\\.to|BudURL\\.com|ping\\.fm|post\\.ly|Just\\.as|bkite\\.com|snipr\\.com|fic\\.kr|loopt\\.us|'
        'doiop\\.com|short\\.ie|kl\\.am|wp\\.me|rubyurl\\.com|om\\.ly|to\\.ly|bit\\.do|t\\.co|lnkd\\.in|'
        'db\\.tt|qr\\.ae|adf\\.ly|goo\\.gl|bitly\\.com|cur\\.lv|tinyurl\\.com|ow\\.ly|bit\\.ly|ity\\.im|'
        'q\\.gs|is\\.gd|po\\.st|bc\\.vc|twitthis\\.com|u\\.to|j\\.mp|buzurl\\.com|cutt\\.us|u\\.bb|'
        'yourls\\.org|x\\.co|prettylinkpro\\.com|scrnch\\.me|filoops\\.info|vzturl\\.com|qr\\.net|'
        '1url\\.com|tweez\\.me|v\\.gd|tr\\.im|link\\.zip\\.net', url)
    return 1 if match else 0

def count_https(url):
    return url.count('https')

def count_http(url):
    return url.count('http')

def count_per(url):
    return url.count('%')

def count_ques(url):
    return url.count('?')

def count_hyphen(url):
    return url.count('-')

def count_equal(url):
    return url.count('=')

def url_length(url):
    return len(str(url))

def hostname_length(url):
    return len(urlparse(url).netloc)

def suspicious_words(url):
    match = re.search(
        'PayPal|login|signin|bank|account|update|free|lucky|service|bonus|ebayisapi|webscr',
        url)
    return 1 if match else 0

def digit_count(url):
    return sum(1 for i in url if i.isnumeric())

def letter_count(url):
    return sum(1 for i in url if i.isalpha())

def fd_length(url):
    urlpath = urlparse(url).path
    try:
        return len(urlpath.split('/')[1])
    except:
        return 0

def tld_length(tld):
    try:
        return len(tld)
    except:
        return -1

def extract_features(url):
    try:
        tld = get_tld(url, fail_silently=True)
        tld_len = tld_length(tld)
    except:
        tld = None
        tld_len = -1

    features = {
        'use_of_ip': having_ip_address(url),
        'abnormal_url': abnormal_url(url),
        'count.': count_dot(url),
        'count-www': count_www(url),
        'count@': count_atrate(url),
        'count_dir': no_of_dir(url),
        'count_embed_domian': no_of_embed(url),
        'short_url': shortening_service(url),
        'count-https': count_https(url),
        'count-http': count_http(url),
        'count%': count_per(url),
        'count?': count_ques(url),
        'count-': count_hyphen(url),
        'count=': count_equal(url),
        'url_length': url_length(url),
        'hostname_length': hostname_length(url),
        'sus_url': suspicious_words(url),
        'fd_length': fd_length(url),
        'tld_length': tld_len,
        'count-digits': digit_count(url),
        'count-letters': letter_count(url)
    }
    return pd.DataFrame([features])


def predict_url(url):
    if model is None:
        return None

    features_df = extract_features(url)
    prediction = model.predict(features_df)[0]
    label_map = {0: 'benign', 1: 'defacement', 2: 'phishing', 3: 'malware'}
    probabilities = model.predict_proba(features_df)[0]

    result = {
        'url': url,
        'prediction': label_map[prediction],
        'confidence': float(probabilities[prediction]) * 100,
        'probabilities': {
            'benign': float(probabilities[0]) * 100,
            'defacement': float(probabilities[1]) * 100,
            'phishing': float(probabilities[2]) * 100,
            'malware': float(probabilities[3]) * 100
        }
    }
    return result


# ============================================================
# Routes
# ============================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        # Validation
        if not username or not email or not password:
            flash('All fields are required.', 'danger')
            return render_template('register.html')

        if len(username) < 3:
            flash('Username must be at least 3 characters.', 'danger')
            return render_template('register.html')

        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'danger')
            return render_template('register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return render_template('register.html')

        # Create user
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        remember = request.form.get('remember', False)

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            login_user(user, remember=bool(remember))
            next_page = request.args.get('next')
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(next_page if next_page else url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    # Stats
    total_scans = ScanHistory.query.filter_by(user_id=current_user.id).count()
    malicious_scans = ScanHistory.query.filter(
        ScanHistory.user_id == current_user.id,
        ScanHistory.prediction != 'benign'
    ).count()
    safe_scans = ScanHistory.query.filter_by(
        user_id=current_user.id,
        prediction='benign'
    ).count()
    recent_scans = ScanHistory.query.filter_by(
        user_id=current_user.id
    ).order_by(ScanHistory.scanned_at.desc()).limit(5).all()

    return render_template(
        'dashboard.html',
        total_scans=total_scans,
        malicious_scans=malicious_scans,
        safe_scans=safe_scans,
        recent_scans=recent_scans
    )


@app.route('/scan', methods=['POST'])
@login_required
def scan():
    url = request.form.get('url', '').strip()

    if not url:
        return jsonify({'error': 'URL is required'}), 400


    try:
        result = predict_url(url)

        if result is None:
            return jsonify({'error': 'Model not available'}), 500

        # Save to history
        scan_record = ScanHistory(
            url=url,
            prediction=result['prediction'],
            confidence=result['confidence'],
            benign_prob=result['probabilities']['benign'],
            defacement_prob=result['probabilities']['defacement'],
            phishing_prob=result['probabilities']['phishing'],
            malware_prob=result['probabilities']['malware'],
            user_id=current_user.id
        )
        db.session.add(scan_record)
        db.session.commit()

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history')
@login_required
def history():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    filter_type = request.args.get('filter', 'all')

    query = ScanHistory.query.filter_by(user_id=current_user.id)

    if filter_type != 'all':
        query = query.filter_by(prediction=filter_type)

    scans = query.order_by(
        ScanHistory.scanned_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)

    return render_template('history.html', scans=scans, filter_type=filter_type)


@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = ScanHistory.query.get_or_404(scan_id)
    if scan.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    db.session.delete(scan)
    db.session.commit()
    return jsonify({'success': True})


@app.route('/api/stats')
@login_required
def api_stats():
    scans = ScanHistory.query.filter_by(user_id=current_user.id).all()
    stats = {
        'benign': sum(1 for s in scans if s.prediction == 'benign'),
        'defacement': sum(1 for s in scans if s.prediction == 'defacement'),
        'phishing': sum(1 for s in scans if s.prediction == 'phishing'),
        'malware': sum(1 for s in scans if s.prediction == 'malware'),
    }
    return jsonify(stats)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)