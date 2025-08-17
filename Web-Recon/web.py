#!/usr/bin/env python3
"""
Rapid Recon Web Application - Complete Working Implementation
"""
import warnings
warnings.filterwarnings("ignore", message="pkg_resources is deprecated")

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash, send_from_directory
import os
import json
import uuid
from datetime import datetime
import threading
import time
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import concurrent.futures
import traceback
import socket

# Import existing modules
from modules.input_handler import detect_input_type
from modules.whois_lookup import perform_whois_lookup
from modules.dns_lookup import get_dns_records
from modules.port_scan import scan_ports
from modules.http_info import fetch_http_info
from modules.tech_stack import detect_tech_stack
from modules.geoip_lookup import get_geoip_info
from modules.report_generator import ReportGenerator
from modules.export_manager import ExportManager
from modules.subdomain_finder import find_subdomains
from modules.shodan_search import perform_shodan_search
from modules.cve_lookup import check_cves

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'rapid-recon-secret-key-2024')

# Configuration
SCAN_RESULTS_DIR = 'web_data/scans'
USERS_FILE = 'web_data/users.json'
HISTORY_FILE = 'web_data/history.json'
EXPORT_DIR = 'output'
MAX_CONCURRENT_MODULES = 3  # Number of modules to run concurrently
SCAN_TIMEOUT = 300  # 5 minutes timeout for scans

# Ensure directories exist
os.makedirs(SCAN_RESULTS_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)
os.makedirs('web_data', exist_ok=True)

# Scan progress tracking with thread locks
scan_progress_data = {}
scan_locks = {}

def init_data_files():
    """Initialize data files if they don't exist"""
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'w') as f:
            json.dump({}, f)
    
    if not os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, 'w') as f:
            json.dump([], f)

def login_required(f):
    """Decorator to require login for certain routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    """Home page with dashboard"""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    history = load_history()
    recent_scans = [h for h in history if h.get('user') == session['user_id']][-5:]
    
    return render_template('index.html', recent_scans=recent_scans)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        users = load_users()
        if username in users and check_password_hash(users[username]['password'], password):
            session['user_id'] = username
            session['username'] = username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registration page"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form.get('email', '')
        
        users = load_users()
        
        if username in users:
            flash('Username already exists', 'danger')
        else:
            users[username] = {
                'password': generate_password_hash(password),
                'email': email,
                'created_at': datetime.now().isoformat(),
                'role': 'user'
            }
            save_users(users)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Logout route"""
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    """User profile page"""
    users = load_users()
    user_data = users.get(session['user_id'], {})
    
    if 'created_at' in user_data:
        try:
            created_date = datetime.fromisoformat(user_data['created_at'])
            user_data['formatted_date'] = created_date.strftime('%B %d, %Y')
        except:
            user_data['formatted_date'] = user_data['created_at']
    
    return render_template('profile.html', user=user_data)

@app.route('/dashboard')
@login_required
def dashboard():
    """Dashboard page"""
    history = load_history()
    user_history = [h for h in history if h.get('user') == session['user_id']]
    recent_scans = user_history[-10:]
    
    total_scans = len(user_history)
    successful_scans = len([h for h in user_history if h.get('status') == 'completed'])
    
    return render_template('dashboard.html', 
                         recent_scans=recent_scans,
                         total_scans=total_scans,
                         successful_scans=successful_scans)

@app.route('/scan', methods=['GET', 'POST'])
@login_required
def scan():
    """Scan page"""
    if request.method == 'POST':
        target = request.form['target']
        modules = request.form.getlist('modules')
        
        if not target:
            flash('Please provide a target', 'danger')
            return redirect(url_for('scan'))
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())
        user_id = session.get('user_id', 'anonymous')
        
        # Initialize scan progress data
        scan_progress_data[scan_id] = {
            'status': 'initializing',
            'progress': 0,
            'current_module': None,
            'modules': modules,
            'completed_modules': [],
            'logs': [],
            'start_time': datetime.now().isoformat(),
            'user_id': user_id,
            'target': target
        }
        
        # Create a lock for this scan
        scan_locks[scan_id] = threading.Lock()
        
        # Start scan in background thread
        thread = threading.Thread(
            target=run_scan_async,
            args=(scan_id, target, modules, user_id),
            daemon=True
        )
        thread.start()
        
        return redirect(url_for('get_scan_progress', scan_id=scan_id))
    
    return render_template('scan.html')

@app.route('/scan/progress/<scan_id>')
@login_required
def get_scan_progress(scan_id):
    """Scan progress page"""
    if scan_id not in scan_progress_data:
        flash('Scan not found or expired', 'danger')
        return redirect(url_for('history'))
    
    # Verify user owns this scan
    if scan_progress_data[scan_id].get('user_id') != session.get('user_id'):
        flash('Unauthorized access to scan', 'danger')
        return redirect(url_for('history'))
    
    return render_template('scan_progress.html', scan_id=scan_id)

@app.route('/api/scan/status/<scan_id>')
@login_required
def scan_status(scan_id):
    """API endpoint for scan status"""
    if scan_id not in scan_progress_data:
        return jsonify({
            'status': 'error',
            'message': 'Scan not found'
        }), 404
    
    # Verify user owns this scan
    if scan_progress_data[scan_id].get('user_id') != session.get('user_id'):
        return jsonify({
            'status': 'error',
            'message': 'Unauthorized'
        }), 403
    
    # Create a copy of the data to return
    with scan_locks.get(scan_id, threading.Lock()):
        status_data = scan_progress_data[scan_id].copy()
    
    return jsonify(status_data)

@app.route('/results/<scan_id>')
@login_required
def results(scan_id):
    """Scan results page"""
    scan_file = os.path.join(SCAN_RESULTS_DIR, f"{scan_id}.json")
    
    if not os.path.exists(scan_file):
        flash('Scan not found', 'danger')
        return redirect(url_for('history'))
    
    # Verify user owns this scan
    with open(scan_file, 'r') as f:
        scan_data = json.load(f)
    
    if scan_data.get('user_id') != session.get('user_id'):
        flash('Unauthorized access to scan results', 'danger')
        return redirect(url_for('history'))
    
    # Generate report data if not already present
    if 'analysis' not in scan_data:
        report_generator = ReportGenerator()
        report_data = report_generator._prepare_report_data(scan_data['target'], scan_data['results'])
        scan_data['analysis'] = report_data['analysis']
        
        # Save the updated data
        with open(scan_file, 'w') as f:
            json.dump(scan_data, f, indent=2)
    
    return render_template('results.html', scan_data=scan_data)

@app.route('/history')
@login_required
def history():
    """History page"""
    history_data = [h for h in load_history() if h.get('user') == session['user_id']]
    return render_template('history.html', history=history_data)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Settings page"""
    if request.method == 'POST':
        new_email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        
        users = load_users()
        user_data = users.get(session['user_id'])
        
        if not user_data:
            flash('User not found', 'danger')
            return redirect(url_for('settings'))
        
        # Validate current password if changing password
        if new_password:
            if not check_password_hash(user_data['password'], current_password):
                flash('Current password is incorrect', 'danger')
                return redirect(url_for('settings'))
            
            user_data['password'] = generate_password_hash(new_password)
            flash('Password updated successfully', 'success')
        
        # Update email if changed
        if new_email and new_email != user_data.get('email', ''):
            user_data['email'] = new_email
            flash('Email updated successfully', 'success')
        
        save_users(users)
        return redirect(url_for('settings'))
    
    # Load current user data
    users = load_users()
    user_data = users.get(session['user_id'], {})
    return render_template('settings.html', user=user_data)

@app.route('/about')
@login_required
def about():
    """About page"""
    return render_template('about.html')

@app.route('/export/<scan_id>/<format>')
@login_required
def export_results(scan_id, format):
    """Export scan results in specified format"""
    scan_file = os.path.join(SCAN_RESULTS_DIR, f"{scan_id}.json")
    
    if not os.path.exists(scan_file):
        flash('Scan not found', 'danger')
        return redirect(url_for('history'))
    
    with open(scan_file, 'r') as f:
        scan_data = json.load(f)
    
    # Verify user owns this scan
    if scan_data.get('user_id') != session.get('user_id'):
        flash('Unauthorized to export this scan', 'danger')
        return redirect(url_for('history'))
    
    export_manager = ExportManager()
    
    try:
        if format == 'json':
            filepath = export_manager._export_json(scan_data, f"scan_{scan_id}")
            return redirect(url_for('download_file', filename=os.path.basename(filepath)))
        elif format == 'pdf':
            filepath = export_manager._export_pdf(scan_data, f"scan_{scan_id}")
            return redirect(url_for('download_file', filename=os.path.basename(filepath)))
        elif format == 'html':
            filepath = export_manager._export_html(scan_data, f"scan_{scan_id}")
            return redirect(url_for('download_file', filename=os.path.basename(filepath)))
        else:
            flash('Invalid format requested', 'danger')
            return redirect(url_for('results', scan_id=scan_id))
    except Exception as e:
        flash(f'Error generating report: {str(e)}', 'danger')
        return redirect(url_for('results', scan_id=scan_id))

@app.route('/email_report/<scan_id>', methods=['POST'])
@login_required
def email_report(scan_id):
    """Email scan report to user"""
    scan_file = os.path.join(SCAN_RESULTS_DIR, f"{scan_id}.json")
    
    if not os.path.exists(scan_file):
        flash('Scan not found', 'danger')
        return redirect(url_for('history'))
    
    with open(scan_file, 'r') as f:
        scan_data = json.load(f)
    
    # Verify user owns this scan
    if scan_data.get('user_id') != session.get('user_id'):
        flash('Unauthorized to email this scan', 'danger')
        return redirect(url_for('history'))
    
    email = request.form.get('email')
    if not email:
        flash('Please provide an email address', 'danger')
        return redirect(url_for('results', scan_id=scan_id))
    
    export_manager = ExportManager()
    
    # Get SMTP settings from environment or config
    smtp_server = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', '587'))
    sender_email = os.environ.get('SENDER_EMAIL')
    sender_password = os.environ.get('SENDER_PASSWORD')
    
    if not all([sender_email, sender_password]):
        flash('Email configuration not set up', 'danger')
        return redirect(url_for('results', scan_id=scan_id))
    
    try:
        success = export_manager.send_email_report(
            scan_data, 
            recipient=email,
            sender=sender_email,
            password=sender_password,
            smtp_server=smtp_server,
            smtp_port=smtp_port
        )
        
        if success:
            flash('Report sent successfully!', 'success')
        else:
            flash('Failed to send report', 'danger')
    except Exception as e:
        flash(f'Error sending email: {str(e)}', 'danger')
    
    return redirect(url_for('results', scan_id=scan_id))

@app.route('/download/<filename>')
@login_required
def download_file(filename):
    """Download exported file"""
    safe_filename = os.path.basename(filename)
    return send_from_directory(EXPORT_DIR, safe_filename, as_attachment=True)

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

@app.route('/api/scan/cancel/<scan_id>', methods=['POST'])
@login_required
def cancel_scan(scan_id):
    """Cancel a running scan"""
    if scan_id not in scan_progress_data:
        return jsonify({'status': 'error', 'message': 'Scan not found'}), 404
    
    # Check if user owns this scan
    if scan_progress_data[scan_id].get('user_id') != session.get('user_id'):
        return jsonify({'status': 'error', 'message': 'Unauthorized'}), 403
    
    # Mark scan as cancelled
    with scan_locks[scan_id]:
        scan_progress_data[scan_id].update({
            'status': 'cancelled',
            'logs': scan_progress_data[scan_id]['logs'] + [{
                'message': 'Scan cancelled by user',
                'type': 'warning',
                'timestamp': datetime.now().isoformat()
            }],
            'end_time': datetime.now().isoformat()
        })
    
    return jsonify({'status': 'success'})

def load_users():
    """Load users from file"""
    try:
        with open(USERS_FILE, 'r') as f:
            users = json.load(f)
            for username, data in users.items():
                data['username'] = username
            return users
    except:
        return {}

def save_users(users):
    """Save users to file"""
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=2)

def load_history():
    """Load scan history"""
    try:
        with open(HISTORY_FILE, 'r') as f:
            history = json.load(f)
            for item in history:
                try:
                    dt = datetime.fromisoformat(item['timestamp'])
                    item['formatted_date'] = dt.strftime('%Y-%m-%d %H:%M')
                except:
                    item['formatted_date'] = item['timestamp']
            return history
    except:
        return []

def save_history(history):
    """Save scan history"""
    with open(HISTORY_FILE, 'w') as f:
        json.dump(history, f, indent=2)

def run_scan_async(scan_id, target, modules, user_id):
    """Background thread function to run the scan"""
    try:
        # Update status to running
        with scan_locks[scan_id]:
            scan_progress_data[scan_id].update({
                'status': 'running',
                'progress': 0,
                'logs': [{
                    'message': f'Starting scan for target: {target}',
                    'type': 'info',
                    'timestamp': datetime.now().isoformat()
                }]
            })
        
        # Detect input type
        input_type, cleaned_input, ip_address = detect_input_type(target)
        
        if input_type == "unknown":
            with scan_locks[scan_id]:
                scan_progress_data[scan_id].update({
                    'status': 'error',
                    'logs': [{
                        'message': 'Invalid target provided',
                        'type': 'error',
                        'timestamp': datetime.now().isoformat()
                    }]
                })
            return
        
        # Initialize results
        results = {
            'scan_id': scan_id,
            'target': target,
            'cleaned_input': cleaned_input,
            'ip_address': ip_address,
            'input_type': input_type,
            'timestamp': datetime.now().isoformat(),
            'modules': modules,
            'results': {},
            'user_id': user_id
        }
        
        # Define module execution functions
        module_functions = {
            'whois': {
                'name': 'WHOIS Lookup',
                'function': lambda: perform_whois_lookup(cleaned_input, ip_address)
            },
            'dns': {
                'name': 'DNS Lookup',
                'function': lambda: get_dns_records(cleaned_input)
            },
            'geoip': {
                'name': 'GeoIP Lookup',
                'function': lambda: get_geoip_info(ip_address) if ip_address else None
            },
            'http': {
                'name': 'HTTP Headers',
                'function': lambda: fetch_http_info(target)
            },
            'ports': {
                'name': 'Port Scan',
                'function': lambda: scan_ports(ip_address) if ip_address else None
            },
            'tech': {
                'name': 'Tech Stack',
                'function': lambda: detect_tech_stack(target)
            },
            'subdomains': {
                'name': 'Subdomain Finder',
                'function': lambda: find_subdomains(target)
            },
            'shodan': {
                'name': 'Shodan Search',
                'function': lambda: perform_shodan_search(ip_address) if ip_address else None
            },
            'cve': {
                'name': 'CVE Lookup',
                'function': lambda: check_cves(target)
            }
        }
        
        # Run selected modules with thread pool
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_MODULES) as executor:
            futures = {}
            
            for module in modules:
                if module in module_functions:
                    module_info = module_functions[module]
                    
                    # Update status before starting module
                    with scan_locks[scan_id]:
                        scan_progress_data[scan_id]['current_module'] = module_info['name']
                        scan_progress_data[scan_id]['logs'].append({
                            'message': f'Starting {module_info["name"]}',
                            'type': 'info',
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # Submit module to thread pool
                    futures[executor.submit(module_info['function'])] = module
        
            # Process results as they complete
            for future in concurrent.futures.as_completed(futures):
                module = futures[future]
                module_info = module_functions[module]
                
                try:
                    result = future.result()
                    results['results'][module] = result
                    
                    with scan_locks[scan_id]:
                        scan_progress_data[scan_id]['completed_modules'].append(module)
                        scan_progress_data[scan_id]['logs'].append({
                            'message': f'{module_info["name"]} completed successfully',
                            'type': 'success',
                            'timestamp': datetime.now().isoformat()
                        })
                        
                        # Update progress
                        progress = int((len(scan_progress_data[scan_id]['completed_modules']) / 
                                     len(modules)) * 100)
                        scan_progress_data[scan_id]['progress'] = progress
                
                except Exception as e:
                    error_msg = f'{module_info["name"]} failed: {str(e)}'
                    results['results'][module] = {'error': str(e)}
                    
                    with scan_locks[scan_id]:
                        scan_progress_data[scan_id]['logs'].append({
                            'message': error_msg,
                            'type': 'error',
                            'timestamp': datetime.now().isoformat()
                        })
                        traceback.print_exc()
        
        # Generate report analysis
        report_generator = ReportGenerator()
        report_data = report_generator._prepare_report_data(target, results['results'])
        results['analysis'] = report_data['analysis']
        
        # Save results
        scan_file = os.path.join(SCAN_RESULTS_DIR, f"{scan_id}.json")
        with open(scan_file, 'w') as f:
            json.dump(results, f, indent=2)
        
        # Update history
        history = load_history()
        history.append({
            'scan_id': scan_id,
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'status': 'completed',
            'modules': modules,
            'user': user_id,
            'duration': (datetime.now() - datetime.fromisoformat(
                scan_progress_data[scan_id]['start_time'])).total_seconds()
        })
        save_history(history)
        
        # Mark scan as completed
        with scan_locks[scan_id]:
            scan_progress_data[scan_id].update({
                'status': 'completed',
                'progress': 100,
                'current_module': None,
                'end_time': datetime.now().isoformat(),
                'logs': scan_progress_data[scan_id]['logs'] + [{
                    'message': 'Scan completed successfully',
                    'type': 'success',
                    'timestamp': datetime.now().isoformat()
                }]
            })
    
    except Exception as e:
        error_msg = f'Scan failed: {str(e)}'
        traceback.print_exc()
        
        with scan_locks[scan_id]:
            scan_progress_data[scan_id].update({
                'status': 'error',
                'logs': scan_progress_data[scan_id]['logs'] + [{
                    'message': error_msg,
                    'type': 'error',
                    'timestamp': datetime.now().isoformat()
                }],
                'end_time': datetime.now().isoformat()
            })

@app.route('/toggle_theme', methods=['POST'])
def toggle_theme():
    current = session.get('theme', 'light')
    session['theme'] = 'dark' if current == 'light' else 'light'
    return redirect(request.referrer or url_for('dashboard'))

@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html'), 500

if __name__ == '__main__':
    init_data_files()
    app.run(debug=True, host='0.0.0.0', port=5000)