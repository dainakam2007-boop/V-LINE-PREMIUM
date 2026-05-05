#!/usr/bin/env python3
"""
V-LINE - Site E-Commerce Complet
Application fichier unique — version corrigée et robuste
"""

from flask import (Flask, render_template, request, redirect,
                   url_for, session, flash, jsonify, abort)
from werkzeug.security import generate_password_hash, check_password_hash
from jinja2 import DictLoader
from functools import wraps
import sqlite3, re, secrets, time
from datetime import timedelta

# ============================================================
# CONFIGURATION
# ============================================================
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)

DB_PATH = 'vline.db'
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300
login_attempts = {}
PER_PAGE = 12

# ============================================================
# BASE DE DONNÉES
# ============================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'client',
            first_name TEXT, last_name TEXT,
            phone TEXT, address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, description TEXT,
            icon TEXT DEFAULT '📦',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL, description TEXT,
            price REAL NOT NULL, stock INTEGER DEFAULT 0,
            category_id INTEGER, image_url TEXT DEFAULT '',
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (category_id) REFERENCES categories(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS product_sizes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL, size TEXT NOT NULL,
            stock INTEGER DEFAULT 0,
            FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS cart (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
            size_id INTEGER, quantity INTEGER DEFAULT 1,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (size_id) REFERENCES product_sizes(id)
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, total_amount REAL NOT NULL,
            status TEXT DEFAULT 'en_attente',
            shipping_address TEXT, payment_method TEXT DEFAULT 'carte',
            order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP, notes TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
            size TEXT, quantity INTEGER NOT NULL, unit_price REAL NOT NULL,
            FOREIGN KEY (order_id) REFERENCES orders(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        CREATE TABLE IF NOT EXISTS wishlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL, product_id INTEGER NOT NULL,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, product_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (product_id) REFERENCES products(id)
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER NOT NULL, user_id INTEGER NOT NULL,
            rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
            comment TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (product_id) REFERENCES products(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    c.execute("SELECT id FROM users WHERE role='admin' LIMIT 1")
    if not c.fetchone():
        pw = generate_password_hash('Admin@VLine2024!')
        c.execute(
            "INSERT INTO users (username,email,password,role,first_name,last_name) VALUES (?,?,?,?,?,?)",
            ('admin', 'admin@vline.com', pw, 'admin', 'Super', 'Admin')
        )
    c.execute("SELECT COUNT(*) FROM categories")
    if c.fetchone()[0] == 0:
        cats = [
            ('Vêtements Homme', 'Mode masculine', '👔'),
            ('Vêtements Femme', 'Mode féminine', '👗'),
            ('Chaussures', 'Toutes chaussures', '👟'),
            ('Accessoires', 'Sacs, ceintures, bijoux', '👜'),
            ('Sport & Fitness', 'Articles sportifs', '🏋️'),
            ('Électronique', 'High-tech et gadgets', '📱'),
        ]
        c.executemany("INSERT INTO categories (name,description,icon) VALUES (?,?,?)", cats)
    conn.commit()
    conn.close()

# ============================================================
# SÉCURITÉ
# ============================================================
def sanitize_input(value):
    if value is None:
        return ''
    return re.sub(r'[<>\'"%;()&+]', '', str(value)).strip()

def check_brute_force(ip):
    now = time.time()
    if ip in login_attempts:
        attempts, first_time = login_attempts[ip]
        if now - first_time > LOCKOUT_DURATION:
            login_attempts[ip] = (0, now)
            return False
        if attempts >= MAX_LOGIN_ATTEMPTS:
            return True
    return False

def record_failed_login(ip):
    now = time.time()
    if ip in login_attempts:
        a, t = login_attempts[ip]
        login_attempts[ip] = (a + 1, t)
    else:
        login_attempts[ip] = (1, now)

def clear_login_attempts(ip):
    login_attempts.pop(ip, None)

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Veuillez vous connecter.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ============================================================
# CONTEXT PROCESSORS
# ============================================================
@app.context_processor
def utility_processor():
    def get_cart_count():
        if 'user_id' not in session:
            return 0
        try:
            conn = get_db()
            row = conn.execute(
                "SELECT COALESCE(SUM(quantity),0) FROM cart WHERE user_id=?",
                (session['user_id'],)
            ).fetchone()
            conn.close()
            return int(row[0])
        except Exception:
            return 0

    def get_all_categories():
        try:
            conn = get_db()
            cats = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
            conn.close()
            return cats
        except Exception:
            return []

    return dict(get_cart_count=get_cart_count, get_all_categories=get_all_categories)

# ============================================================
# TEMPLATES
# ============================================================
BASE_TEMPLATE = '''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{% block title %}V-LINE{% endblock %} | V-LINE</title>
<link href="https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Nunito:wght@300;400;600;700;800&display=swap" rel="stylesheet">
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" rel="stylesheet">
<style>
:root {
  --royal:#1a3a9c;--royal-dark:#0f2470;--royal-deep:#091852;
  --royal-light:#2d52c4;--royal-pale:#e8eeff;--royal-mid:#3d6be8;
  --gold:#f0b323;--white:#ffffff;--off-white:#f7f9ff;
  --gray-light:#e5eaf5;--gray-mid:#8a9cc0;--gray-dark:#2c3a5e;
  --danger:#e03e3e;--success:#1d9c5a;--warning:#f0a500;
  --radius:12px;--radius-sm:6px;
  --shadow:0 4px 24px rgba(26,58,156,.13);--shadow-lg:0 8px 40px rgba(26,58,156,.22);
  --transition:.22s cubic-bezier(.4,0,.2,1);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{scroll-behavior:smooth}
body{font-family:'Nunito',sans-serif;background:var(--off-white);color:var(--gray-dark);min-height:100vh;display:flex;flex-direction:column}
::-webkit-scrollbar{width:7px}::-webkit-scrollbar-track{background:var(--royal-pale)}::-webkit-scrollbar-thumb{background:var(--royal-light);border-radius:10px}
.topbar{background:var(--royal-deep);color:rgba(255,255,255,.75);font-size:.8rem;padding:6px 0}
.topbar-inner{max-width:1280px;margin:0 auto;padding:0 20px;display:flex;justify-content:space-between;align-items:center}
.topbar a{color:rgba(255,255,255,.7);text-decoration:none;margin-left:16px;transition:color var(--transition)}
.topbar a:hover{color:var(--gold)}
.header{background:var(--royal);box-shadow:0 2px 20px rgba(0,0,0,.25);position:sticky;top:0;z-index:1000}
.header-inner{max-width:1280px;margin:0 auto;padding:0 20px;height:70px;display:flex;align-items:center;gap:24px}
.logo{font-family:'Bebas Neue',sans-serif;font-size:2.2rem;color:var(--white);text-decoration:none;letter-spacing:3px;display:flex;align-items:center;gap:8px;flex-shrink:0}
.logo span{color:var(--gold)}.logo-dot{width:8px;height:8px;background:var(--gold);border-radius:50%;display:inline-block}
.search-bar{flex:1;display:flex;max-width:560px}
.search-bar input{flex:1;padding:11px 18px;border:none;border-radius:var(--radius) 0 0 var(--radius);font-size:.95rem;font-family:'Nunito',sans-serif;outline:none;background:white}
.search-bar button{padding:0 20px;background:var(--gold);border:none;border-radius:0 var(--radius) var(--radius) 0;cursor:pointer;font-size:1rem;transition:background var(--transition)}
.search-bar button:hover{background:#d9a000}
.header-nav{display:flex;align-items:center;gap:6px;margin-left:auto}
.nav-btn{display:flex;flex-direction:column;align-items:center;gap:2px;color:rgba(255,255,255,.88);text-decoration:none;padding:8px 12px;border-radius:var(--radius-sm);font-size:.75rem;transition:all var(--transition);position:relative;white-space:nowrap}
.nav-btn i{font-size:1.25rem}.nav-btn:hover{background:rgba(255,255,255,.15);color:white}
.nav-btn .badge{position:absolute;top:4px;right:6px;background:var(--danger);color:white;font-size:.65rem;font-weight:800;width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center}
.cat-nav{background:var(--royal-dark);border-top:1px solid rgba(255,255,255,.08)}
.cat-nav-inner{max-width:1280px;margin:0 auto;padding:0 20px;display:flex;gap:4px;overflow-x:auto;scrollbar-width:none}
.cat-nav-inner::-webkit-scrollbar{display:none}
.cat-link{color:rgba(255,255,255,.82);text-decoration:none;padding:10px 16px;font-size:.85rem;font-weight:600;white-space:nowrap;display:flex;align-items:center;gap:6px;border-bottom:2px solid transparent;transition:all var(--transition)}
.cat-link:hover,.cat-link.active{color:var(--gold);border-bottom-color:var(--gold)}
.alerts{max-width:1280px;margin:16px auto 0;padding:0 20px}
.alert{padding:12px 18px;border-radius:var(--radius-sm);margin-bottom:10px;font-weight:600;display:flex;align-items:center;gap:10px;animation:slideDown .3s ease}
@keyframes slideDown{from{transform:translateY(-10px);opacity:0}to{transform:translateY(0);opacity:1}}
.alert-success{background:#d1f5e4;color:#0d6e40;border-left:4px solid var(--success)}
.alert-danger{background:#fde8e8;color:#b02020;border-left:4px solid var(--danger)}
.alert-warning{background:#fff4d6;color:#8a6000;border-left:4px solid var(--warning)}
.alert-info{background:var(--royal-pale);color:var(--royal);border-left:4px solid var(--royal-light)}
main{flex:1}
.container{max-width:1280px;margin:0 auto;padding:0 20px}
.hero{background:linear-gradient(135deg,var(--royal-deep) 0%,var(--royal) 50%,var(--royal-mid) 100%);color:white;padding:64px 20px;text-align:center;position:relative;overflow:hidden}
.hero::before{content:'';position:absolute;top:-50%;left:-20%;width:60%;height:200%;background:rgba(255,255,255,.03);border-radius:50%;transform:rotate(-15deg)}
.hero::after{content:'';position:absolute;bottom:-60%;right:-10%;width:50%;height:200%;background:rgba(255,255,255,.04);border-radius:50%}
.hero-content{position:relative;z-index:1}
.hero h1{font-family:'Bebas Neue',sans-serif;font-size:4rem;letter-spacing:6px;margin-bottom:12px}
.hero h1 em{color:var(--gold);font-style:normal}
.hero p{font-size:1.2rem;opacity:.85;margin-bottom:28px}
.hero-btns{display:flex;gap:14px;justify-content:center;flex-wrap:wrap}
.btn{display:inline-flex;align-items:center;gap:8px;padding:12px 28px;border-radius:var(--radius);font-weight:700;font-size:.95rem;text-decoration:none;cursor:pointer;border:none;transition:all var(--transition);font-family:'Nunito',sans-serif}
.btn-primary{background:var(--gold);color:var(--royal-deep)}.btn-primary:hover{background:#d9a000;transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.2)}
.btn-outline{background:transparent;color:white;border:2px solid rgba(255,255,255,.6)}.btn-outline:hover{background:rgba(255,255,255,.15);border-color:white}
.btn-royal{background:var(--royal);color:white}.btn-royal:hover{background:var(--royal-dark);transform:translateY(-2px);box-shadow:var(--shadow)}
.btn-danger{background:var(--danger);color:white}.btn-danger:hover{background:#c03030}
.btn-success{background:var(--success);color:white}.btn-success:hover{background:#177a47}
.btn-gray{background:var(--gray-light);color:var(--gray-dark)}.btn-gray:hover{background:#d0d8ec}
.btn-sm{padding:7px 16px;font-size:.83rem}.btn-xs{padding:5px 12px;font-size:.78rem}
.btn-block{width:100%;justify-content:center}
.stats-bar{background:white;border-bottom:1px solid var(--gray-light);padding:18px 20px}
.stats-inner{max-width:1280px;margin:0 auto;display:flex;gap:40px;justify-content:center;flex-wrap:wrap}
.stat-item{display:flex;align-items:center;gap:12px;color:var(--gray-dark);font-size:.9rem}
.stat-item i{color:var(--royal);font-size:1.3rem}.stat-item strong{color:var(--royal-dark);font-size:1.05rem}
.section{padding:48px 0}
.section-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:28px}
.section-title{font-family:'Bebas Neue',sans-serif;font-size:1.9rem;color:var(--royal-dark);letter-spacing:2px;display:flex;align-items:center;gap:10px}
.section-title::before{content:'';width:5px;height:28px;background:var(--gold);border-radius:3px;display:inline-block}
.product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:20px}
.product-card{background:white;border-radius:var(--radius);overflow:hidden;box-shadow:0 2px 12px rgba(26,58,156,.08);transition:all var(--transition);position:relative}
.product-card:hover{transform:translateY(-5px);box-shadow:var(--shadow-lg)}
.product-img{width:100%;aspect-ratio:1;object-fit:cover;background:linear-gradient(135deg,var(--royal-pale),#dde5ff);display:flex;align-items:center;justify-content:center;font-size:4rem;color:var(--royal-light)}
.product-img img{width:100%;height:100%;object-fit:cover}
.product-badge{position:absolute;top:10px;left:10px;background:var(--danger);color:white;font-size:.72rem;font-weight:800;padding:3px 9px;border-radius:20px}
.product-wish{position:absolute;top:10px;right:10px;background:white;border:none;width:34px;height:34px;border-radius:50%;cursor:pointer;display:flex;align-items:center;justify-content:center;box-shadow:0 2px 8px rgba(0,0,0,.12);color:var(--gray-mid);transition:all var(--transition);font-size:.9rem}
.product-wish:hover,.product-wish.active{color:var(--danger)}
.product-info{padding:14px}
.product-cat{font-size:.73rem;color:var(--royal-mid);font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:5px}
.product-name{font-weight:700;font-size:.95rem;color:var(--gray-dark);margin-bottom:8px;line-height:1.3;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.product-price{font-size:1.15rem;font-weight:800;color:var(--royal);margin-bottom:4px}
.product-stock{font-size:.76rem;color:var(--gray-mid);margin-bottom:10px}
.product-stock.low{color:var(--warning)}.product-stock.out{color:var(--danger)}
.product-stars{color:var(--gold);font-size:.82rem;margin-bottom:10px}
.product-actions{display:flex;gap:6px}
.cat-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:16px}
.cat-card{background:white;border-radius:var(--radius);padding:24px 16px;text-align:center;text-decoration:none;color:var(--gray-dark);box-shadow:0 2px 10px rgba(26,58,156,.07);transition:all var(--transition);border:2px solid transparent}
.cat-card:hover{border-color:var(--royal-light);transform:translateY(-3px);box-shadow:var(--shadow)}
.cat-card .icon{font-size:2.2rem;margin-bottom:10px;display:block}.cat-card span{font-weight:700;font-size:.88rem}
.form-wrapper{max-width:500px;margin:40px auto;background:white;border-radius:var(--radius);box-shadow:var(--shadow-lg);overflow:hidden}
.form-header{background:linear-gradient(135deg,var(--royal),var(--royal-mid));padding:32px;text-align:center;color:white}
.form-header h2{font-family:'Bebas Neue',sans-serif;font-size:2rem;letter-spacing:3px;margin-bottom:6px}
.form-header p{opacity:.8;font-size:.9rem}
.form-body{padding:32px}
.form-group{margin-bottom:20px}
.form-group label{display:block;font-weight:700;margin-bottom:7px;color:var(--gray-dark);font-size:.88rem}
.form-control{width:100%;padding:11px 15px;border:2px solid var(--gray-light);border-radius:var(--radius-sm);font-size:.95rem;font-family:'Nunito',sans-serif;outline:none;transition:border-color var(--transition);background:white}
.form-control:focus{border-color:var(--royal-light)}.form-control.error{border-color:var(--danger)}
select.form-control{cursor:pointer}textarea.form-control{resize:vertical;min-height:100px}
.form-row{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.form-hint{font-size:.78rem;color:var(--gray-mid);margin-top:4px}
.admin-layout{display:flex;min-height:calc(100vh - 140px)}
.admin-sidebar{width:260px;background:var(--royal-deep);color:white;flex-shrink:0;position:sticky;top:70px;height:calc(100vh - 70px);overflow-y:auto}
.admin-sidebar-header{padding:24px;border-bottom:1px solid rgba(255,255,255,.1)}
.admin-sidebar-header h3{font-family:'Bebas Neue',sans-serif;font-size:1.3rem;letter-spacing:2px;color:var(--gold)}
.admin-sidebar-header p{font-size:.8rem;opacity:.6;margin-top:2px}
.sidebar-nav{padding:16px 0}
.sidebar-section{padding:8px 20px 4px;font-size:.7rem;font-weight:800;text-transform:uppercase;letter-spacing:1.5px;color:rgba(255,255,255,.35);margin-top:8px}
.sidebar-link{display:flex;align-items:center;gap:12px;padding:11px 20px;color:rgba(255,255,255,.75);text-decoration:none;font-size:.9rem;font-weight:600;transition:all var(--transition);border-left:3px solid transparent}
.sidebar-link:hover,.sidebar-link.active{color:white;background:rgba(255,255,255,.08);border-left-color:var(--gold)}
.sidebar-link i{width:18px;text-align:center}
.admin-main{flex:1;padding:32px;overflow:hidden}
.admin-page-title{font-family:'Bebas Neue',sans-serif;font-size:2rem;letter-spacing:3px;color:var(--royal-dark);margin-bottom:24px;display:flex;align-items:center;gap:12px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:18px;margin-bottom:32px}
.stat-card{background:white;border-radius:var(--radius);padding:22px;box-shadow:var(--shadow);display:flex;align-items:center;gap:16px;border-left:4px solid var(--royal)}
.stat-card.gold{border-left-color:var(--gold)}.stat-card.green{border-left-color:var(--success)}.stat-card.red{border-left-color:var(--danger)}
.stat-icon{width:50px;height:50px;border-radius:10px;background:var(--royal-pale);display:flex;align-items:center;justify-content:center;font-size:1.4rem;color:var(--royal);flex-shrink:0}
.stat-card.gold .stat-icon{background:#fff8e1;color:var(--gold)}.stat-card.green .stat-icon{background:#e6f7ef;color:var(--success)}.stat-card.red .stat-icon{background:#fde8e8;color:var(--danger)}
.stat-text .num{font-size:1.7rem;font-weight:800;color:var(--royal-dark);line-height:1}.stat-text .lbl{font-size:.82rem;color:var(--gray-mid);margin-top:3px}
.table-wrapper{background:white;border-radius:var(--radius);box-shadow:var(--shadow);overflow:hidden}
.table-header{padding:18px 22px;border-bottom:1px solid var(--gray-light);display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.table-title{font-weight:800;font-size:1rem;color:var(--royal-dark)}
table{width:100%;border-collapse:collapse}
thead th{background:var(--royal-pale);color:var(--royal-dark);font-weight:800;font-size:.82rem;text-transform:uppercase;letter-spacing:.5px;padding:12px 16px;text-align:left}
tbody tr{border-bottom:1px solid var(--gray-light);transition:background var(--transition)}
tbody tr:last-child{border-bottom:none}tbody tr:hover{background:var(--royal-pale)}
td{padding:12px 16px;font-size:.9rem;vertical-align:middle}
.td-actions{display:flex;gap:6px;align-items:center}
.badge-status{display:inline-flex;align-items:center;gap:5px;padding:4px 10px;border-radius:20px;font-size:.76rem;font-weight:700}
.badge-admin{background:#fff0d6;color:#8a5000}.badge-client{background:var(--royal-pale);color:var(--royal)}
.badge-active{background:#e6f7ef;color:var(--success)}.badge-inactive{background:#fde8e8;color:var(--danger)}
.badge-pending{background:#fff8e1;color:#8a6000}.badge-shipped{background:#e0f0ff;color:#1060a0}
.badge-delivered{background:#e6f7ef;color:var(--success)}.badge-cancelled{background:#fde8e8;color:var(--danger)}
.product-detail{display:grid;grid-template-columns:1fr 1fr;gap:40px;padding:40px 0}
.product-detail-img{background:linear-gradient(135deg,var(--royal-pale),#dde5ff);border-radius:var(--radius);aspect-ratio:1;display:flex;align-items:center;justify-content:center;font-size:8rem;color:var(--royal-light);overflow:hidden}
.product-detail-img img{width:100%;height:100%;object-fit:cover}
.product-detail-info{padding:10px 0}
.product-detail-cat{font-size:.8rem;font-weight:700;text-transform:uppercase;color:var(--royal-mid);letter-spacing:1px;margin-bottom:10px}
.product-detail-name{font-size:1.8rem;font-weight:800;color:var(--royal-dark);line-height:1.2;margin-bottom:14px}
.product-detail-price{font-size:2.2rem;font-weight:800;color:var(--royal);margin-bottom:18px}
.product-detail-desc{color:var(--gray-mid);line-height:1.7;margin-bottom:22px;font-size:.95rem}
.size-selector{margin-bottom:20px}.size-selector label{font-weight:700;margin-bottom:10px;display:block}
.size-options{display:flex;gap:8px;flex-wrap:wrap}
.size-btn{padding:8px 16px;border:2px solid var(--gray-light);border-radius:var(--radius-sm);cursor:pointer;font-weight:700;font-size:.9rem;background:white;transition:all var(--transition);font-family:'Nunito',sans-serif}
.size-btn:hover{border-color:var(--royal-light);color:var(--royal)}.size-btn.selected{border-color:var(--royal);background:var(--royal);color:white}.size-btn.out{opacity:.4;cursor:not-allowed;text-decoration:line-through}
.qty-selector{display:flex;align-items:center;gap:12px;margin-bottom:22px}.qty-selector label{font-weight:700}
.qty-input{display:flex;align-items:center;border:2px solid var(--gray-light);border-radius:var(--radius-sm);overflow:hidden}
.qty-btn{padding:8px 14px;background:var(--royal-pale);border:none;cursor:pointer;font-size:1.1rem;font-weight:800;color:var(--royal);transition:background var(--transition)}.qty-btn:hover{background:var(--gray-light)}
.qty-num{padding:8px 18px;font-weight:800;font-size:1rem;min-width:50px;text-align:center}
.cart-layout{display:grid;grid-template-columns:1fr 340px;gap:24px;padding:32px 0}
.cart-items{display:flex;flex-direction:column;gap:14px}
.cart-item{background:white;border-radius:var(--radius);padding:18px;box-shadow:var(--shadow);display:flex;gap:16px;align-items:center}
.cart-item-img{width:80px;height:80px;border-radius:var(--radius-sm);background:var(--royal-pale);display:flex;align-items:center;justify-content:center;font-size:2rem;flex-shrink:0;overflow:hidden}
.cart-item-img img{width:100%;height:100%;object-fit:cover}
.cart-item-info{flex:1}.cart-item-name{font-weight:700;margin-bottom:4px}.cart-item-meta{font-size:.82rem;color:var(--gray-mid);margin-bottom:8px}.cart-item-price{font-weight:800;color:var(--royal);font-size:1.05rem}
.cart-summary{background:white;border-radius:var(--radius);padding:24px;box-shadow:var(--shadow);position:sticky;top:90px;height:fit-content}
.cart-summary h3{font-weight:800;margin-bottom:18px;color:var(--royal-dark)}
.summary-line{display:flex;justify-content:space-between;padding:9px 0;border-bottom:1px solid var(--gray-light);font-size:.92rem}
.summary-total{display:flex;justify-content:space-between;padding:14px 0 18px;font-weight:800;font-size:1.15rem;color:var(--royal-dark)}
footer{background:var(--royal-deep);color:rgba(255,255,255,.75);margin-top:auto}
.footer-top{padding:48px 20px 32px;max-width:1280px;margin:0 auto;display:grid;grid-template-columns:2fr 1fr 1fr 1fr;gap:40px}
.footer-brand .logo{margin-bottom:14px;display:inline-block}.footer-brand p{font-size:.88rem;line-height:1.7;max-width:300px}
.footer-col h4{font-family:'Bebas Neue',sans-serif;font-size:1.1rem;letter-spacing:2px;color:white;margin-bottom:14px}
.footer-col ul{list-style:none}.footer-col li{margin-bottom:8px}
.footer-col a{color:rgba(255,255,255,.65);text-decoration:none;font-size:.88rem;transition:color var(--transition)}.footer-col a:hover{color:var(--gold)}
.footer-bottom{border-top:1px solid rgba(255,255,255,.08);padding:16px 20px;text-align:center;font-size:.82rem;color:rgba(255,255,255,.4)}
.social-links{display:flex;gap:10px;margin-top:14px}
.social-link{width:36px;height:36px;background:rgba(255,255,255,.1);border-radius:50%;display:flex;align-items:center;justify-content:center;color:rgba(255,255,255,.7);text-decoration:none;transition:all var(--transition);font-size:.9rem}.social-link:hover{background:var(--royal-mid);color:white}
.profile-header{background:linear-gradient(135deg,var(--royal),var(--royal-mid));color:white;padding:40px;border-radius:var(--radius);margin-bottom:24px;display:flex;align-items:center;gap:24px}
.profile-avatar{width:80px;height:80px;border-radius:50%;background:rgba(255,255,255,.2);display:flex;align-items:center;justify-content:center;font-size:2rem;flex-shrink:0}
.profile-name{font-size:1.6rem;font-weight:800;margin-bottom:4px}.profile-role{opacity:.75;font-size:.9rem}
.pagination{display:flex;gap:6px;justify-content:center;padding:24px 0;flex-wrap:wrap}
.page-btn{padding:8px 14px;border-radius:var(--radius-sm);border:2px solid var(--gray-light);background:white;color:var(--royal);font-weight:700;font-size:.88rem;cursor:pointer;text-decoration:none;transition:all var(--transition)}
.page-btn:hover,.page-btn.active{background:var(--royal);border-color:var(--royal);color:white}
.empty-state{text-align:center;padding:64px 20px;color:var(--gray-mid)}
.empty-state i{font-size:3.5rem;margin-bottom:16px;display:block}.empty-state h3{font-size:1.3rem;margin-bottom:8px;color:var(--gray-dark)}
@media(max-width:1024px){.footer-top{grid-template-columns:1fr 1fr}.product-detail{grid-template-columns:1fr}.cart-layout{grid-template-columns:1fr}}
@media(max-width:768px){.admin-layout{flex-direction:column}.admin-sidebar{width:100%;position:static;height:auto}.hero h1{font-size:2.5rem}.search-bar{display:none}.footer-top{grid-template-columns:1fr}.form-row{grid-template-columns:1fr}.header-inner{gap:12px}}
@media(max-width:480px){.header-inner{padding:0 12px}.hero{padding:40px 16px}.stats-inner{gap:20px}}
.text-center{text-align:center}.text-right{text-align:right}
.mt-2{margin-top:8px}.mt-4{margin-top:16px}.mt-6{margin-top:24px}
.mb-2{margin-bottom:8px}.mb-4{margin-bottom:16px}.mb-6{margin-bottom:24px}
.flex{display:flex}.items-center{align-items:center}.justify-between{justify-content:space-between}
.gap-2{gap:8px}.gap-4{gap:16px}.font-bold{font-weight:700}
.divider{border:none;border-top:1px solid var(--gray-light);margin:20px 0}
.w-full{width:100%}
</style>
</head>
<body>
<div class="topbar">
  <div class="topbar-inner">
    <span><i class="fas fa-map-marker-alt"></i> Livraison mondiale disponible</span>
    <div>
      <a href="#"><i class="fas fa-headset"></i> Support 24/7</a>
      <a href="#"><i class="fas fa-shield-alt"></i> Achat sécurisé</a>
      {% if not session.get('user_id') %}
      <a href="{{ url_for('login') }}"><i class="fas fa-sign-in-alt"></i> Connexion</a>
      <a href="{{ url_for('register') }}"><i class="fas fa-user-plus"></i> Inscription</a>
      {% endif %}
    </div>
  </div>
</div>
<header class="header">
  <div class="header-inner">
    <a href="{{ url_for('index') }}" class="logo">V<span>-</span>LINE <span class="logo-dot"></span></a>
    <form class="search-bar" action="{{ url_for('products') }}" method="GET">
      <input type="text" name="q" placeholder="Rechercher des produits..." value="{{ request.args.get('q','') }}">
      <button type="submit"><i class="fas fa-search"></i></button>
    </form>
    <nav class="header-nav">
      {% if session.get('user_id') %}
        {% if session.get('role') == 'admin' %}
        <a href="{{ url_for('admin_dashboard') }}" class="nav-btn"><i class="fas fa-tachometer-alt"></i><span>Admin</span></a>
        {% endif %}
        <a href="{{ url_for('wishlist_view') }}" class="nav-btn"><i class="fas fa-heart"></i><span>Favoris</span></a>
        <a href="{{ url_for('cart') }}" class="nav-btn">
          <i class="fas fa-shopping-cart"></i><span>Panier</span>
          {% set cart_count = get_cart_count() %}
          {% if cart_count > 0 %}<span class="badge">{{ cart_count }}</span>{% endif %}
        </a>
        <a href="{{ url_for('profile') }}" class="nav-btn"><i class="fas fa-user-circle"></i><span>{{ session.get('username','')[:10] }}</span></a>
        <a href="{{ url_for('logout') }}" class="nav-btn"><i class="fas fa-sign-out-alt"></i><span>Sortir</span></a>
      {% else %}
        <a href="{{ url_for('login') }}" class="nav-btn"><i class="fas fa-sign-in-alt"></i><span>Connexion</span></a>
        <a href="{{ url_for('register') }}" class="nav-btn"><i class="fas fa-user-plus"></i><span>S\'inscrire</span></a>
      {% endif %}
    </nav>
  </div>
  <div class="cat-nav">
    <div class="cat-nav-inner">
      <a href="{{ url_for('products') }}" class="cat-link"><i class="fas fa-th"></i> Tout</a>
      {% for cat in get_all_categories() %}
      <a href="{{ url_for('products', category=cat['id']) }}" class="cat-link">{{ cat['icon'] }} {{ cat['name'] }}</a>
      {% endfor %}
    </div>
  </div>
</header>
<div class="alerts">
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, message in messages %}
    <div class="alert alert-{{ category }}">
      {% if category == 'success' %}<i class="fas fa-check-circle"></i>
      {% elif category == 'danger' %}<i class="fas fa-exclamation-circle"></i>
      {% elif category == 'warning' %}<i class="fas fa-exclamation-triangle"></i>
      {% else %}<i class="fas fa-info-circle"></i>{% endif %}
      {{ message }}
    </div>
    {% endfor %}
  {% endwith %}
</div>
<main>{% block content %}{% endblock %}</main>
<footer>
  <div class="footer-top">
    <div class="footer-brand">
      <a href="{{ url_for('index') }}" class="logo">V<span>-</span>LINE</a>
      <p>V-LINE est votre destination shopping de confiance. Des milliers de produits de qualité livrés partout dans le monde.</p>
      <div class="social-links">
        <a href="#" class="social-link"><i class="fab fa-facebook-f"></i></a>
        <a href="#" class="social-link"><i class="fab fa-instagram"></i></a>
        <a href="#" class="social-link"><i class="fab fa-twitter"></i></a>
        <a href="#" class="social-link"><i class="fab fa-youtube"></i></a>
      </div>
    </div>
    <div class="footer-col">
      <h4>Navigation</h4>
      <ul>
        <li><a href="{{ url_for('index') }}">Accueil</a></li>
        <li><a href="{{ url_for('products') }}">Produits</a></li>
        <li><a href="{{ url_for('cart') }}">Panier</a></li>
        <li><a href="{{ url_for('orders') }}">Mes commandes</a></li>
      </ul>
    </div>
    <div class="footer-col">
      <h4>Support</h4>
      <ul>
        <li><a href="#">Centre d'aide</a></li>
        <li><a href="#">Livraison</a></li>
        <li><a href="#">Retours</a></li>
        <li><a href="#">Contactez-nous</a></li>
      </ul>
    </div>
    <div class="footer-col">
      <h4>Légal</h4>
      <ul>
        <li><a href="#">CGV</a></li>
        <li><a href="#">Confidentialité</a></li>
        <li><a href="#">Cookies</a></li>
        <li><a href="#">Mentions légales</a></li>
      </ul>
    </div>
  </div>
  <div class="footer-bottom">&copy; 2024 V-LINE. Tous droits réservés. | Paiements sécurisés <i class="fas fa-lock"></i></div>
</footer>
<script>
setTimeout(()=>{document.querySelectorAll('.alert').forEach(a=>a.style.opacity='0');setTimeout(()=>document.querySelectorAll('.alert').forEach(a=>a.remove()),500)},4000);
</script>
{% block scripts %}{% endblock %}
</body>
</html>'''

# ---- PAGES TEMPLATES ----

INDEX_TEMPLATE = '''{% extends "base" %}
{% block title %}Accueil{% endblock %}
{% block content %}
<section class="hero">
  <div class="hero-content">
    <h1>Bienvenue sur <em>V-LINE</em></h1>
    <p>Découvrez des milliers de produits de qualité à prix imbattables</p>
    <div class="hero-btns">
      <a href="{{ url_for('products') }}" class="btn btn-primary"><i class="fas fa-shopping-bag"></i> Acheter maintenant</a>
      <a href="{{ url_for('register') }}" class="btn btn-outline"><i class="fas fa-user-plus"></i> S'inscrire gratuitement</a>
    </div>
  </div>
</section>
<div class="stats-bar">
  <div class="stats-inner">
    <div class="stat-item"><i class="fas fa-truck"></i><div><strong>Livraison rapide</strong><br>Partout dans le monde</div></div>
    <div class="stat-item"><i class="fas fa-shield-alt"></i><div><strong>Paiement sécurisé</strong><br>Transactions cryptées</div></div>
    <div class="stat-item"><i class="fas fa-undo"></i><div><strong>Retours faciles</strong><br>30 jours pour changer d'avis</div></div>
    <div class="stat-item"><i class="fas fa-headset"></i><div><strong>Support 24/7</strong><br>Toujours disponible</div></div>
  </div>
</div>
<div class="container">
  <section class="section">
    <div class="section-header">
      <h2 class="section-title">Catégories</h2>
      <a href="{{ url_for('products') }}" class="btn btn-sm btn-royal">Voir tout <i class="fas fa-arrow-right"></i></a>
    </div>
    <div class="cat-grid">
      {% for cat in categories %}
      <a href="{{ url_for('products', category=cat['id']) }}" class="cat-card">
        <span class="icon">{{ cat['icon'] }}</span>
        <span>{{ cat['name'] }}</span>
      </a>
      {% endfor %}
    </div>
  </section>
  <section class="section">
    <div class="section-header">
      <h2 class="section-title">Nouveautés</h2>
      <a href="{{ url_for('products') }}" class="btn btn-sm btn-royal">Tous les produits <i class="fas fa-arrow-right"></i></a>
    </div>
    {% if products %}
    <div class="product-grid">
      {% for p in products %}
      <div class="product-card">
        {% if p['stock'] <= 5 and p['stock'] > 0 %}<span class="product-badge">Stock limité</span>{% endif %}
        <button class="product-wish {% if p['id'] in wishlist_ids %}active{% endif %}"
                onclick="toggleWish({{ p['id'] }},this)"><i class="fas fa-heart"></i></button>
        <a href="{{ url_for('product_detail', pid=p['id']) }}" style="text-decoration:none">
          <div class="product-img">
            {% if p['image_url'] %}<img src="{{ p['image_url'] }}" alt="{{ p['name'] }}" onerror="this.style.display='none'">{% else %}🛍️{% endif %}
          </div>
          <div class="product-info">
            <div class="product-cat">{{ p['cat_name'] or 'Général' }}</div>
            <div class="product-name">{{ p['name'] }}</div>
            <div class="product-stars">★★★★☆ <small style="color:var(--gray-mid)">({{ p['review_count'] or 0 }})</small></div>
            <div class="product-price">{{ "%.2f"|format(p['price']) }} €</div>
            <div class="product-stock {% if p['stock']==0 %}out{% elif p['stock']<=5 %}low{% endif %}">
              {% if p['stock']==0 %}Rupture{% elif p['stock']<=5 %}Plus que {{ p['stock'] }} dispo{% else %}En stock ({{ p['stock'] }}){% endif %}
            </div>
          </div>
        </a>
        <div style="padding:0 14px 14px">
          <div class="product-actions">
            <a href="{{ url_for('product_detail', pid=p['id']) }}" class="btn btn-sm btn-royal" style="flex:1;justify-content:center"><i class="fas fa-eye"></i> Voir</a>
            {% if p['stock'] > 0 %}
            <form action="{{ url_for('add_to_cart') }}" method="POST" style="flex:1">
              <input type="hidden" name="product_id" value="{{ p['id'] }}">
              <input type="hidden" name="quantity" value="1">
              <button type="submit" class="btn btn-sm btn-primary w-full"><i class="fas fa-cart-plus"></i> Panier</button>
            </form>
            {% endif %}
          </div>
        </div>
      </div>
      {% endfor %}
    </div>
    {% else %}
    <div class="empty-state"><i class="fas fa-box-open" style="color:var(--royal-light)"></i><h3>Aucun produit disponible</h3><p>Revenez bientôt !</p></div>
    {% endif %}
  </section>
</div>
<script>
function toggleWish(pid,btn){
  fetch('/wishlist/toggle/'+pid,{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'}})
    .then(r=>r.json()).then(d=>{d.status==='added'?btn.classList.add('active'):btn.classList.remove('active')})
    .catch(()=>window.location='/login');
}
</script>
{% endblock %}'''

PRODUCTS_TEMPLATE = '''{% extends "base" %}
{% block title %}Produits{% endblock %}
{% block content %}
<div class="container">
<div style="display:grid;grid-template-columns:240px 1fr;gap:24px;padding:32px 0">
  <aside>
    <div class="table-wrapper" style="padding:20px">
      <h3 style="font-weight:800;color:var(--royal-dark);margin-bottom:16px"><i class="fas fa-filter"></i> Filtres</h3>
      <form method="GET">
        <div class="form-group">
          <label>Recherche</label>
          <input type="text" name="q" class="form-control" placeholder="Nom produit..." value="{{ q }}">
        </div>
        <div class="form-group">
          <label>Catégorie</label>
          <select name="category" class="form-control">
            <option value="">Toutes</option>
            {% for cat in categories %}
            <option value="{{ cat['id'] }}" {% if category_filter==cat['id']|string %}selected{% endif %}>{{ cat['icon'] }} {{ cat['name'] }}</option>
            {% endfor %}
          </select>
        </div>
        <div class="form-group">
          <label>Prix min (€)</label>
          <input type="number" name="pmin" class="form-control" value="{{ pmin }}" min="0" step="0.01">
        </div>
        <div class="form-group">
          <label>Prix max (€)</label>
          <input type="number" name="pmax" class="form-control" value="{{ pmax }}" min="0" step="0.01">
        </div>
        <div class="form-group">
          <label>Trier par</label>
          <select name="sort" class="form-control">
            <option value="newest" {% if sort=='newest' %}selected{% endif %}>Nouveautés</option>
            <option value="price_asc" {% if sort=='price_asc' %}selected{% endif %}>Prix croissant</option>
            <option value="price_desc" {% if sort=='price_desc' %}selected{% endif %}>Prix décroissant</option>
            <option value="name" {% if sort=='name' %}selected{% endif %}>Nom A-Z</option>
          </select>
        </div>
        <button type="submit" class="btn btn-royal btn-block">Appliquer</button>
        <a href="{{ url_for('products') }}" class="btn btn-block mt-2 btn-gray">Réinitialiser</a>
      </form>
    </div>
  </aside>
  <div>
    <div class="section-header">
      <h2 class="section-title">Produits <small style="font-size:.9rem;font-family:Nunito;font-weight:600;color:var(--gray-mid)">({{ total }} résultats)</small></h2>
    </div>
    {% if products %}
    <div class="product-grid">
      {% for p in products %}
      <div class="product-card">
        {% if p['stock']<=5 and p['stock']>0 %}<span class="product-badge">Limité</span>{% endif %}
        <button class="product-wish {% if p['id'] in wishlist_ids %}active{% endif %}" onclick="toggleWish({{ p['id'] }},this)"><i class="fas fa-heart"></i></button>
        <a href="{{ url_for('product_detail', pid=p['id']) }}" style="text-decoration:none">
          <div class="product-img">{% if p['image_url'] %}<img src="{{ p['image_url'] }}" alt="{{ p['name'] }}" onerror="this.style.display='none'">{% else %}🛍️{% endif %}</div>
          <div class="product-info">
            <div class="product-cat">{{ p['cat_name'] or 'Général' }}</div>
            <div class="product-name">{{ p['name'] }}</div>
            <div class="product-stars">★★★★☆</div>
            <div class="product-price">{{ "%.2f"|format(p['price']) }} €</div>
            <div class="product-stock {% if p['stock']==0 %}out{% elif p['stock']<=5 %}low{% endif %}">
              {% if p['stock']==0 %}Rupture{% elif p['stock']<=5 %}Seulement {{ p['stock'] }} restant(s){% else %}En stock{% endif %}
            </div>
          </div>
        </a>
        <div style="padding:0 14px 14px">
          {% if p['stock']>0 %}
          <form action="{{ url_for('add_to_cart') }}" method="POST">
            <input type="hidden" name="product_id" value="{{ p['id'] }}">
            <input type="hidden" name="quantity" value="1">
            <button type="submit" class="btn btn-primary btn-sm btn-block"><i class="fas fa-cart-plus"></i> Ajouter au panier</button>
          </form>
          {% else %}
          <button class="btn btn-sm btn-block" disabled style="background:var(--gray-light);color:var(--gray-mid)">Indisponible</button>
          {% endif %}
        </div>
      </div>
      {% endfor %}
    </div>
    {% if total_pages > 1 %}
    <div class="pagination">
      {% for i in range(1, total_pages+1) %}
      <a href="{{ url_for('products', q=q, category=category_filter, pmin=pmin, pmax=pmax, sort=sort, page=i) }}"
         class="page-btn {% if i==page %}active{% endif %}">{{ i }}</a>
      {% endfor %}
    </div>
    {% endif %}
    {% else %}
    <div class="empty-state"><i class="fas fa-search" style="color:var(--royal-light)"></i><h3>Aucun produit trouvé</h3><p>Modifiez vos critères de recherche.</p></div>
    {% endif %}
  </div>
</div>
</div>
<script>
function toggleWish(pid,btn){
  fetch('/wishlist/toggle/'+pid,{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'}})
    .then(r=>r.json()).then(d=>{d.status==='added'?btn.classList.add('active'):btn.classList.remove('active')})
    .catch(()=>window.location='/login');
}
</script>
{% endblock %}'''

PRODUCT_DETAIL_TEMPLATE = '''{% extends "base" %}
{% block title %}{{ product['name'] }}{% endblock %}
{% block content %}
<div class="container">
<div class="product-detail">
  <div class="product-detail-img">
    {% if product['image_url'] %}<img src="{{ product['image_url'] }}" alt="{{ product['name'] }}" onerror="this.style.display='none'">{% else %}🛍️{% endif %}
  </div>
  <div class="product-detail-info">
    <div class="product-detail-cat">{{ product['cat_name'] or 'Général' }}</div>
    <h1 class="product-detail-name">{{ product['name'] }}</h1>
    <div class="product-stars" style="font-size:1.1rem;margin-bottom:14px">★★★★☆ <small style="color:var(--gray-mid)">({{ reviews|length }} avis)</small></div>
    <div class="product-detail-price">{{ "%.2f"|format(product['price']) }} €</div>
    <p class="product-detail-desc">{{ product['description'] or 'Aucune description disponible.' }}</p>
    {% if sizes %}
    <div class="size-selector">
      <label>Choisir une taille :</label>
      <div class="size-options">
        {% for s in sizes %}
        <button class="size-btn {% if s['stock']==0 %}out{% endif %}" onclick="selectSize(this,{{ s['id'] }})" {% if s['stock']==0 %}disabled{% endif %}>{{ s['size'] }}{% if s['stock']==0 %} ✗{% endif %}</button>
        {% endfor %}
      </div>
    </div>
    {% endif %}
    {% if product['stock'] > 0 %}
    <div class="qty-selector">
      <label>Quantité :</label>
      <div class="qty-input">
        <button class="qty-btn" onclick="changeQty(-1)">−</button>
        <span class="qty-num" id="qty-display">1</span>
        <button class="qty-btn" onclick="changeQty(1)">+</button>
      </div>
      <span style="font-size:.82rem;color:var(--gray-mid)">Max: {{ product['stock'] }}</span>
    </div>
    <form action="{{ url_for('add_to_cart') }}" method="POST" id="add-cart-form">
      <input type="hidden" name="product_id" value="{{ product['id'] }}">
      <input type="hidden" name="quantity" id="qty-input" value="1">
      <input type="hidden" name="size_id" id="size-id-input" value="">
      <div style="display:flex;gap:12px">
        <button type="submit" class="btn btn-primary" style="flex:1"><i class="fas fa-cart-plus"></i> Ajouter au panier</button>
        <button type="button" onclick="toggleWish({{ product['id'] }},this)" class="btn" style="background:white;color:var(--royal);border:2px solid var(--royal)"><i class="fas fa-heart"></i></button>
      </div>
    </form>
    {% else %}
    <div style="background:#fde8e8;color:var(--danger);padding:14px;border-radius:var(--radius-sm);font-weight:700;margin-bottom:16px"><i class="fas fa-times-circle"></i> Produit actuellement en rupture de stock</div>
    {% endif %}
    <hr class="divider">
    <div style="display:flex;gap:24px;font-size:.85rem;color:var(--gray-mid)">
      <span><i class="fas fa-truck"></i> Livraison sous 3-5 jours</span>
      <span><i class="fas fa-undo"></i> Retour 30 jours</span>
      <span><i class="fas fa-shield-alt"></i> Achat garanti</span>
    </div>
  </div>
</div>
<section class="section">
  <h2 class="section-title">Avis clients</h2>
  {% if session.get('user_id') %}
  <div class="table-wrapper" style="padding:20px;margin-bottom:20px">
    <h4 style="margin-bottom:14px;font-weight:700">Laisser un avis</h4>
    <form action="{{ url_for('add_review', pid=product['id']) }}" method="POST">
      <div class="form-row">
        <div class="form-group">
          <label>Note</label>
          <select name="rating" class="form-control" required>
            <option value="5">★★★★★ Excellent</option>
            <option value="4">★★★★☆ Bien</option>
            <option value="3">★★★☆☆ Moyen</option>
            <option value="2">★★☆☆☆ Insuffisant</option>
            <option value="1">★☆☆☆☆ Mauvais</option>
          </select>
        </div>
        <div class="form-group">
          <label>Commentaire</label>
          <input type="text" name="comment" class="form-control" placeholder="Votre avis..." maxlength="500">
        </div>
      </div>
      <button type="submit" class="btn btn-royal btn-sm"><i class="fas fa-paper-plane"></i> Publier</button>
    </form>
  </div>
  {% endif %}
  {% if reviews %}
    {% for r in reviews %}
    <div style="background:white;border-radius:var(--radius-sm);padding:16px;margin-bottom:10px;box-shadow:0 1px 6px rgba(0,0,0,.05)">
      <div style="display:flex;justify-content:space-between;margin-bottom:6px">
        <strong>{{ r['username'] }}</strong>
        <span style="color:var(--gold)">{{ '★' * r['rating'] }}{{ '☆' * (5 - r['rating']) }}</span>
      </div>
      <p style="color:var(--gray-mid);font-size:.9rem">{{ r['comment'] or 'Aucun commentaire.' }}</p>
      <small style="color:var(--gray-mid)">{{ r['created_at'][:10] }}</small>
    </div>
    {% endfor %}
  {% else %}
  <div class="empty-state" style="padding:32px"><i class="fas fa-star" style="color:var(--gold)"></i><h3>Aucun avis pour le moment</h3></div>
  {% endif %}
</section>
</div>
<script>
let qty=1,maxQty={{ product['stock'] }};
function changeQty(d){qty=Math.max(1,Math.min(maxQty,qty+d));document.getElementById('qty-display').textContent=qty;document.getElementById('qty-input').value=qty;}
function selectSize(btn,id){document.querySelectorAll('.size-btn').forEach(b=>b.classList.remove('selected'));btn.classList.add('selected');document.getElementById('size-id-input').value=id;}
function toggleWish(pid,btn){fetch('/wishlist/toggle/'+pid,{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'}}).then(r=>r.json()).then(d=>{btn.style.color=d.status==='added'?'var(--danger)':''}).catch(()=>window.location='/login');}
</script>
{% endblock %}'''

LOGIN_TEMPLATE = '''{% extends "base" %}
{% block title %}Connexion{% endblock %}
{% block content %}
<div class="form-wrapper">
  <div class="form-header">
    <h2><i class="fas fa-sign-in-alt"></i> CONNEXION</h2>
    <p>Accédez à votre compte V-LINE</p>
  </div>
  <div class="form-body">
    <form method="POST">
      <div class="form-group">
        <label><i class="fas fa-user"></i> Nom d'utilisateur</label>
        <input type="text" name="username" class="form-control" placeholder="Votre identifiant" required autofocus>
      </div>
      <div class="form-group">
        <label><i class="fas fa-lock"></i> Mot de passe</label>
        <input type="password" name="password" class="form-control" placeholder="Votre mot de passe" required>
      </div>
      <button type="submit" class="btn btn-royal btn-block" style="margin-bottom:16px">
        <i class="fas fa-sign-in-alt"></i> Se connecter
      </button>
      <p class="text-center" style="color:var(--gray-mid);font-size:.9rem">
        Pas encore de compte ? <a href="{{ url_for('register') }}" style="color:var(--royal);font-weight:700">S'inscrire</a>
      </p>
    </form>
  </div>
</div>
{% endblock %}'''

REGISTER_TEMPLATE = '''{% extends "base" %}
{% block title %}Inscription{% endblock %}
{% block content %}
<div class="form-wrapper" style="max-width:600px">
  <div class="form-header">
    <h2><i class="fas fa-user-plus"></i> INSCRIPTION</h2>
    <p>Créez votre compte V-LINE gratuitement</p>
  </div>
  <div class="form-body">
    <form method="POST">
      <div class="form-row">
        <div class="form-group">
          <label>Prénom</label>
          <input type="text" name="first_name" class="form-control" placeholder="Prénom">
        </div>
        <div class="form-group">
          <label>Nom</label>
          <input type="text" name="last_name" class="form-control" placeholder="Nom">
        </div>
      </div>
      <div class="form-group">
        <label>Nom d'utilisateur *</label>
        <input type="text" name="username" class="form-control" placeholder="Identifiant unique" required>
      </div>
      <div class="form-group">
        <label>Email *</label>
        <input type="email" name="email" class="form-control" placeholder="votre@email.com" required>
      </div>
      <div class="form-group">
        <label>Téléphone</label>
        <input type="text" name="phone" class="form-control" placeholder="+33 6 00 00 00 00">
      </div>
      <div class="form-group">
        <label>Mot de passe *</label>
        <input type="password" name="password" class="form-control" placeholder="Min. 6 caractères" required minlength="6">
      </div>
      <div class="form-group">
        <label>Confirmer le mot de passe *</label>
        <input type="password" name="password2" class="form-control" placeholder="Répétez le mot de passe" required>
      </div>
      <button type="submit" class="btn btn-royal btn-block" style="margin-bottom:16px">
        <i class="fas fa-user-plus"></i> Créer mon compte
      </button>
      <p class="text-center" style="color:var(--gray-mid);font-size:.9rem">
        Déjà un compte ? <a href="{{ url_for('login') }}" style="color:var(--royal);font-weight:700">Se connecter</a>
      </p>
    </form>
  </div>
</div>
{% endblock %}'''

PROFILE_TEMPLATE = '''{% extends "base" %}
{% block title %}Mon Profil{% endblock %}
{% block content %}
<div class="container" style="padding:32px 20px">
  <div class="profile-header">
    <div class="profile-avatar"><i class="fas fa-user"></i></div>
    <div>
      <div class="profile-name">{{ user['first_name'] or '' }} {{ user['last_name'] or user['username'] }}</div>
      <div class="profile-role">{{ '⭐ Administrateur' if user['role']=='admin' else '👤 Client' }} — Membre depuis {{ user['created_at'][:10] }}</div>
    </div>
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
    <div class="table-wrapper" style="padding:24px">
      <h3 style="font-weight:800;margin-bottom:20px;color:var(--royal-dark)"><i class="fas fa-edit"></i> Modifier mes informations</h3>
      <form method="POST">
        <div class="form-row">
          <div class="form-group"><label>Prénom</label><input type="text" name="first_name" class="form-control" value="{{ user['first_name'] or '' }}"></div>
          <div class="form-group"><label>Nom</label><input type="text" name="last_name" class="form-control" value="{{ user['last_name'] or '' }}"></div>
        </div>
        <div class="form-group"><label>Email</label><input type="email" name="email" class="form-control" value="{{ user['email'] }}" required></div>
        <div class="form-group"><label>Téléphone</label><input type="text" name="phone" class="form-control" value="{{ user['phone'] or '' }}"></div>
        <div class="form-group"><label>Adresse de livraison</label><textarea name="address" class="form-control" rows="3">{{ user['address'] or '' }}</textarea></div>
        <hr class="divider">
        <div class="form-group"><label>Nouveau mot de passe (laisser vide pour ne pas changer)</label><input type="password" name="new_password" class="form-control" placeholder="Nouveau mot de passe" minlength="6"></div>
        <button type="submit" class="btn btn-royal btn-block"><i class="fas fa-save"></i> Sauvegarder</button>
      </form>
    </div>
    <div>
      <div class="table-wrapper" style="padding:20px;margin-bottom:16px">
        <h4 style="font-weight:800;margin-bottom:12px">📊 Mes statistiques</h4>
        <div style="display:flex;flex-direction:column;gap:10px">
          <div class="summary-line"><span>Commandes</span><strong>{{ stats['orders'] }}</strong></div>
          <div class="summary-line"><span>Articles en panier</span><strong>{{ stats['cart'] }}</strong></div>
          <div class="summary-line"><span>Produits favoris</span><strong>{{ stats['wishlist'] }}</strong></div>
        </div>
      </div>
      <div style="display:flex;flex-direction:column;gap:10px">
        <a href="{{ url_for('orders') }}" class="btn btn-royal"><i class="fas fa-box"></i> Mes commandes</a>
        <a href="{{ url_for('wishlist_view') }}" class="btn btn-outline" style="color:var(--royal);border-color:var(--royal)"><i class="fas fa-heart"></i> Mes favoris</a>
      </div>
    </div>
  </div>
</div>
{% endblock %}'''

CART_TEMPLATE = '''{% extends "base" %}
{% block title %}Mon Panier{% endblock %}
{% block content %}
<div class="container">
  <h2 class="section-title" style="padding:24px 0 16px">Mon Panier</h2>
  {% if items %}
  <div class="cart-layout">
    <div class="cart-items">
      {% for item in items %}
      <div class="cart-item">
        <div class="cart-item-img">{% if item['image_url'] %}<img src="{{ item['image_url'] }}" onerror="this.style.display='none'">{% else %}🛍️{% endif %}</div>
        <div class="cart-item-info">
          <div class="cart-item-name">{{ item['name'] }}</div>
          <div class="cart-item-meta">{% if item['size'] %}Taille: <strong>{{ item['size'] }}</strong> | {% endif %}Quantité: <strong>{{ item['quantity'] }}</strong></div>
          <div class="cart-item-price">{{ "%.2f"|format(item['unit_price'] * item['quantity']) }} €</div>
        </div>
        <div style="display:flex;flex-direction:column;gap:6px">
          <form action="{{ url_for('update_cart', cid=item['cart_id']) }}" method="POST" style="display:flex;gap:4px">
            <input type="number" name="quantity" value="{{ item['quantity'] }}" min="1" max="{{ item['stock'] }}" class="form-control" style="width:60px;padding:6px;text-align:center">
            <button type="submit" class="btn btn-sm btn-royal" title="Mettre à jour"><i class="fas fa-sync"></i></button>
          </form>
          <a href="{{ url_for('remove_cart', cid=item['cart_id']) }}" class="btn btn-sm btn-danger" onclick="return confirm('Retirer cet article ?')"><i class="fas fa-trash"></i> Retirer</a>
        </div>
      </div>
      {% endfor %}
    </div>
    <div class="cart-summary">
      <h3>Résumé de commande</h3>
      <div class="summary-line"><span>Sous-total</span><span>{{ "%.2f"|format(subtotal) }} €</span></div>
      <div class="summary-line"><span>Livraison</span><span style="color:var(--success)">Gratuite</span></div>
      <div class="summary-line"><span>TVA (20%)</span><span>{{ "%.2f"|format(subtotal * 0.2) }} €</span></div>
      <div class="summary-total"><span>Total TTC</span><span>{{ "%.2f"|format(subtotal * 1.2) }} €</span></div>
      <a href="{{ url_for('checkout') }}" class="btn btn-primary btn-block" style="margin-bottom:10px"><i class="fas fa-credit-card"></i> Passer la commande</a>
      <a href="{{ url_for('products') }}" class="btn btn-block btn-gray"><i class="fas fa-arrow-left"></i> Continuer mes achats</a>
      <hr class="divider">
      <div style="font-size:.8rem;color:var(--gray-mid);text-align:center"><i class="fas fa-shield-alt"></i> Paiement 100% sécurisé</div>
    </div>
  </div>
  {% else %}
  <div class="empty-state" style="padding:80px">
    <i class="fas fa-shopping-cart" style="color:var(--royal-light)"></i>
    <h3>Votre panier est vide</h3>
    <a href="{{ url_for('products') }}" class="btn btn-royal mt-4"><i class="fas fa-shopping-bag"></i> Parcourir les produits</a>
  </div>
  {% endif %}
</div>
{% endblock %}'''

CHECKOUT_TEMPLATE = '''{% extends "base" %}
{% block title %}Commander{% endblock %}
{% block content %}
<div class="container" style="padding:40px 20px">
  <h2 class="section-title" style="margin-bottom:24px">Finaliser ma commande</h2>
  <div style="display:grid;grid-template-columns:1fr 380px;gap:24px">
    <div class="table-wrapper" style="padding:24px">
      <h3 style="font-weight:800;margin-bottom:18px;color:var(--royal-dark)"><i class="fas fa-map-marker-alt"></i> Adresse de livraison</h3>
      <form action="{{ url_for('place_order') }}" method="POST" id="order-form">
        <div class="form-group">
          <label>Adresse complète *</label>
          <textarea name="shipping_address" class="form-control" required rows="3" placeholder="Numéro, rue, ville, code postal, pays...">{{ session.get('address','') }}</textarea>
        </div>
        <div class="form-group">
          <label>Mode de paiement</label>
          <select name="payment_method" class="form-control">
            <option value="carte">💳 Carte bancaire</option>
            <option value="paypal">🔵 PayPal</option>
            <option value="virement">🏦 Virement bancaire</option>
          </select>
        </div>
        <div class="form-group">
          <label>Notes (optionnel)</label>
          <textarea name="notes" class="form-control" rows="2" placeholder="Instructions spéciales..."></textarea>
        </div>
      </form>
    </div>
    <div class="cart-summary">
      <h3>Récapitulatif</h3>
      {% for item in items %}
      <div class="summary-line"><span>{{ item['name'] }} x{{ item['quantity'] }}</span><span>{{ "%.2f"|format(item['unit_price']*item['quantity']) }} €</span></div>
      {% endfor %}
      <hr class="divider">
      <div class="summary-line"><span>Sous-total</span><span>{{ "%.2f"|format(subtotal) }} €</span></div>
      <div class="summary-line"><span>Livraison</span><span style="color:var(--success)">Gratuite</span></div>
      <div class="summary-line"><span>TVA (20%)</span><span>{{ "%.2f"|format(subtotal*0.2) }} €</span></div>
      <div class="summary-total"><span>Total TTC</span><span>{{ "%.2f"|format(subtotal*1.2) }} €</span></div>
      <button form="order-form" type="submit" class="btn btn-primary btn-block"><i class="fas fa-check-circle"></i> Confirmer la commande</button>
    </div>
  </div>
</div>
{% endblock %}'''

ORDERS_TEMPLATE = '''{% extends "base" %}
{% block title %}Mes Commandes{% endblock %}
{% block content %}
<div class="container" style="padding:32px 20px">
  <h2 class="section-title" style="margin-bottom:24px">Mes Commandes</h2>
  {% if orders %}
  <div class="table-wrapper">
    <table>
      <thead><tr><th>#</th><th>Date</th><th>Articles</th><th>Total</th><th>Statut</th><th>Action</th></tr></thead>
      <tbody>
        {% for o in orders %}
        <tr>
          <td><strong>#{{ o['id'] }}</strong></td>
          <td>{{ o['order_date'][:10] }}</td>
          <td>{{ o['item_count'] }} article(s)</td>
          <td><strong>{{ "%.2f"|format(o['total_amount']) }} €</strong></td>
          <td>
            <span class="badge-status {% if o['status']=='en_attente' %}badge-pending{% elif o['status']=='expediee' %}badge-shipped{% elif o['status']=='livree' %}badge-delivered{% else %}badge-cancelled{% endif %}">
              {% if o['status']=='en_attente' %}⏳ En attente{% elif o['status']=='expediee' %}🚚 Expédiée{% elif o['status']=='livree' %}✅ Livrée{% elif o['status']=='annulee' %}❌ Annulée{% else %}{{ o['status'] }}{% endif %}
            </span>
          </td>
          <td><a href="{{ url_for('order_detail', oid=o['id']) }}" class="btn btn-xs btn-royal"><i class="fas fa-eye"></i> Détails</a></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  {% else %}
  <div class="empty-state" style="padding:64px">
    <i class="fas fa-shopping-bag" style="color:var(--royal-light)"></i>
    <h3>Aucune commande</h3>
    <a href="{{ url_for('products') }}" class="btn btn-royal mt-4"><i class="fas fa-shopping-bag"></i> Acheter maintenant</a>
  </div>
  {% endif %}
</div>
{% endblock %}'''

ORDER_DETAIL_TEMPLATE = '''{% extends "base" %}
{% block title %}Commande #{{ order['id'] }}{% endblock %}
{% block content %}
<div class="container" style="padding:32px 20px">
  <div style="display:flex;align-items:center;gap:16px;margin-bottom:24px">
    <a href="{{ url_for('orders') }}" class="btn btn-sm btn-gray"><i class="fas fa-arrow-left"></i></a>
    <h2 class="section-title">Commande #{{ order['id'] }}</h2>
    <span class="badge-status {% if order['status']=='en_attente' %}badge-pending{% elif order['status']=='expediee' %}badge-shipped{% elif order['status']=='livree' %}badge-delivered{% else %}badge-cancelled{% endif %}">{{ order['status'] }}</span>
  </div>
  <div style="display:grid;grid-template-columns:1fr 320px;gap:20px">
    <div class="table-wrapper">
      <div class="table-header"><span class="table-title">Articles commandés</span></div>
      <table>
        <thead><tr><th>Produit</th><th>Taille</th><th>Qté</th><th>Prix unit.</th><th>Sous-total</th></tr></thead>
        <tbody>
          {% for item in items %}
          <tr>
            <td><strong>{{ item['name'] }}</strong></td>
            <td>{{ item['size'] or '-' }}</td>
            <td>{{ item['quantity'] }}</td>
            <td>{{ "%.2f"|format(item['unit_price']) }} €</td>
            <td><strong>{{ "%.2f"|format(item['unit_price']*item['quantity']) }} €</strong></td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <div class="cart-summary">
      <h3>Détails</h3>
      <div class="summary-line"><span>Date</span><span>{{ order['order_date'][:10] }}</span></div>
      <div class="summary-line"><span>Paiement</span><span>{{ order['payment_method'] or 'N/A' }}</span></div>
      <div class="summary-line"><span>Adresse</span><span style="text-align:right;font-size:.82rem">{{ order['shipping_address'] or 'N/A' }}</span></div>
      <div class="summary-total"><span>Total TTC</span><span>{{ "%.2f"|format(order['total_amount']) }} €</span></div>
      {% if order['notes'] %}
      <div style="font-size:.85rem;color:var(--gray-mid);margin-top:8px"><strong>Note :</strong> {{ order['notes'] }}</div>
      {% endif %}
    </div>
  </div>
</div>
{% endblock %}'''

WISHLIST_TEMPLATE = '''{% extends "base" %}
{% block title %}Mes Favoris{% endblock %}
{% block content %}
<div class="container" style="padding:32px 20px">
  <h2 class="section-title" style="margin-bottom:24px">Mes Favoris</h2>
  {% if products %}
  <div class="product-grid">
    {% for p in products %}
    <div class="product-card">
      <button class="product-wish active" onclick="toggleWish({{ p['id'] }},this)"><i class="fas fa-heart"></i></button>
      <a href="{{ url_for('product_detail', pid=p['id']) }}" style="text-decoration:none">
        <div class="product-img">{% if p['image_url'] %}<img src="{{ p['image_url'] }}" onerror="this.style.display='none'">{% else %}🛍️{% endif %}</div>
        <div class="product-info">
          <div class="product-cat">{{ p['cat_name'] or 'Général' }}</div>
          <div class="product-name">{{ p['name'] }}</div>
          <div class="product-price">{{ "%.2f"|format(p['price']) }} €</div>
          <div class="product-stock {% if p['stock']==0 %}out{% endif %}">{% if p['stock']==0 %}Rupture de stock{% else %}En stock{% endif %}</div>
        </div>
      </a>
      <div style="padding:0 14px 14px">
        {% if p['stock']>0 %}
        <form action="{{ url_for('add_to_cart') }}" method="POST">
          <input type="hidden" name="product_id" value="{{ p['id'] }}">
          <input type="hidden" name="quantity" value="1">
          <button type="submit" class="btn btn-primary btn-sm btn-block"><i class="fas fa-cart-plus"></i> Ajouter au panier</button>
        </form>
        {% else %}
        <button class="btn btn-sm btn-block" disabled style="background:var(--gray-light);color:var(--gray-mid)">Indisponible</button>
        {% endif %}
      </div>
    </div>
    {% endfor %}
  </div>
  {% else %}
  <div class="empty-state" style="padding:64px">
    <i class="fas fa-heart" style="color:var(--royal-light)"></i>
    <h3>Aucun favori</h3>
    <p>Ajoutez des produits à vos favoris en cliquant sur le cœur.</p>
    <a href="{{ url_for('products') }}" class="btn btn-royal mt-4"><i class="fas fa-shopping-bag"></i> Découvrir les produits</a>
  </div>
  {% endif %}
</div>
<script>
function toggleWish(pid,btn){
  fetch('/wishlist/toggle/'+pid,{method:'POST',headers:{'X-Requested-With':'XMLHttpRequest'}})
    .then(r=>r.json()).then(d=>{
      if(d.status==='removed'){btn.closest('.product-card').style.opacity='0';setTimeout(()=>btn.closest('.product-card').remove(),300);}
    }).catch(()=>window.location='/login');
}
</script>
{% endblock %}'''

# ---- ADMIN TEMPLATES ----

ADMIN_BASE = '''{% extends "base" %}
{% block content %}
<div class="admin-layout">
  <aside class="admin-sidebar">
    <div class="admin-sidebar-header">
      <h3>⚙️ ADMIN PANEL</h3>
      <p>{{ session.get('username') }}</p>
    </div>
    <nav class="sidebar-nav">
      <div class="sidebar-section">Tableau de bord</div>
      <a href="{{ url_for('admin_dashboard') }}" class="sidebar-link {% if request.endpoint=='admin_dashboard' %}active{% endif %}"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
      <div class="sidebar-section">Catalogue</div>
      <a href="{{ url_for('admin_products') }}" class="sidebar-link {% if 'admin_product' in request.endpoint %}active{% endif %}"><i class="fas fa-box"></i> Produits</a>
      <a href="{{ url_for('admin_categories') }}" class="sidebar-link {% if 'admin_categor' in request.endpoint %}active{% endif %}"><i class="fas fa-tags"></i> Catégories</a>
      <div class="sidebar-section">Clients & Ventes</div>
      <a href="{{ url_for('admin_users') }}" class="sidebar-link {% if 'admin_user' in request.endpoint %}active{% endif %}"><i class="fas fa-users"></i> Utilisateurs</a>
      <a href="{{ url_for('admin_orders') }}" class="sidebar-link {% if 'admin_order' in request.endpoint %}active{% endif %}"><i class="fas fa-shopping-bag"></i> Commandes</a>
      <div class="sidebar-section">Site</div>
      <a href="{{ url_for('index') }}" class="sidebar-link"><i class="fas fa-globe"></i> Voir le site</a>
      <a href="{{ url_for('logout') }}" class="sidebar-link"><i class="fas fa-sign-out-alt"></i> Déconnexion</a>
    </nav>
  </aside>
  <div class="admin-main">
    {% block admin_content %}{% endblock %}
  </div>
</div>
{% endblock %}'''

ADMIN_DASHBOARD_TEMPLATE = '''{% extends "admin_base" %}
{% block admin_content %}
<h1 class="admin-page-title"><i class="fas fa-tachometer-alt"></i> Dashboard</h1>
<div class="stats-grid">
  <div class="stat-card gold"><div class="stat-icon"><i class="fas fa-box"></i></div><div class="stat-text"><div class="num">{{ stats['products'] }}</div><div class="lbl">Produits actifs</div></div></div>
  <div class="stat-card green"><div class="stat-icon"><i class="fas fa-shopping-bag"></i></div><div class="stat-text"><div class="num">{{ stats['orders'] }}</div><div class="lbl">Commandes</div></div></div>
  <div class="stat-card"><div class="stat-icon"><i class="fas fa-users"></i></div><div class="stat-text"><div class="num">{{ stats['users'] }}</div><div class="lbl">Utilisateurs</div></div></div>
  <div class="stat-card red"><div class="stat-icon"><i class="fas fa-euro-sign"></i></div><div class="stat-text"><div class="num">{{ "%.0f"|format(stats['revenue'] or 0) }}€</div><div class="lbl">Chiffre d'affaires</div></div></div>
</div>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:20px">
  <div class="table-wrapper">
    <div class="table-header"><span class="table-title">Dernières commandes</span><a href="{{ url_for('admin_orders') }}" class="btn btn-xs btn-royal">Voir tout</a></div>
    <table>
      <thead><tr><th>#</th><th>Client</th><th>Total</th><th>Statut</th></tr></thead>
      <tbody>
        {% for o in recent_orders %}
        <tr>
          <td>#{{ o['id'] }}</td>
          <td>{{ o['username'] }}</td>
          <td>{{ "%.2f"|format(o['total_amount']) }} €</td>
          <td><span class="badge-status {% if o['status']=='en_attente' %}badge-pending{% elif o['status']=='expediee' %}badge-shipped{% elif o['status']=='livree' %}badge-delivered{% else %}badge-cancelled{% endif %}">{{ o['status'] }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="table-wrapper">
    <div class="table-header"><span class="table-title">Stock faible</span><a href="{{ url_for('admin_products') }}" class="btn btn-xs btn-royal">Gérer</a></div>
    <table>
      <thead><tr><th>Produit</th><th>Stock</th></tr></thead>
      <tbody>
        {% for p in low_stock %}
        <tr>
          <td>{{ p['name'] }}</td>
          <td><span style="color:{% if p['stock']==0 %}var(--danger){% else %}var(--warning){% endif %};font-weight:700">{{ p['stock'] }}</span></td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
</div>
{% endblock %}'''

ADMIN_PRODUCTS_TEMPLATE = '''{% extends "admin_base" %}
{% block admin_content %}
<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px">
  <h1 class="admin-page-title" style="margin-bottom:0"><i class="fas fa-box"></i> Produits</h1>
  <a href="{{ url_for('admin_add_product') }}" class="btn btn-primary"><i class="fas fa-plus"></i> Nouveau produit</a>
</div>
<div class="table-wrapper">
  <div class="table-header">
    <span class="table-title">{{ products|length }} produit(s)</span>
    <form method="GET" style="display:flex;gap:8px">
      <input type="text" name="q" class="form-control" style="width:200px" placeholder="Rechercher..." value="{{ q }}">
      <button type="submit" class="btn btn-sm btn-royal"><i class="fas fa-search"></i></button>
    </form>
  </div>
  <table>
    <thead><tr><th>ID</th><th>Nom</th><th>Catégorie</th><th>Prix</th><th>Stock</th><th>Statut</th><th>Actions</th></tr></thead>
    <tbody>
      {% for p in products %}
      <tr>
        <td>#{{ p['id'] }}</td>
        <td><strong>{{ p['name'] }}</strong></td>
        <td>{{ p['cat_name'] or '-' }}</td>
        <td>{{ "%.2f"|format(p['price']) }} €</td>
        <td><span style="color:{% if p['stock']==0 %}var(--danger){% elif p['stock']<=5 %}var(--warning){% else %}var(--success){% endif %};font-weight:700">{{ p['stock'] }}</span></td>
        <td><span class="badge-status {% if p['is_active'] %}badge-active{% else %}badge-inactive{% endif %}">{% if p['is_active'] %}Actif{% else %}Inactif{% endif %}</span></td>
        <td class="td-actions">
          <a href="{{ url_for('admin_edit_product', pid=p['id']) }}" class="btn btn-xs btn-royal"><i class="fas fa-edit"></i></a>
          <form action="{{ url_for('admin_delete_product', pid=p['id']) }}" method="POST" style="display:inline" onsubmit="return confirm('Supprimer ce produit ?')">
            <button type="submit" class="btn btn-xs btn-danger"><i class="fas fa-trash"></i></button>
          </form>
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}'''

ADMIN_PRODUCT_FORM_TEMPLATE = '''{% extends "admin_base" %}
{% block admin_content %}
<div style="display:flex;align-items:center;gap:16px;margin-bottom:24px">
  <a href="{{ url_for('admin_products') }}" class="btn btn-sm btn-gray"><i class="fas fa-arrow-left"></i></a>
  <h1 class="admin-page-title" style="margin-bottom:0"><i class="fas fa-{% if product %}edit{% else %}plus{% endif %}"></i> {% if product %}Modifier{% else %}Ajouter{% endif %} un produit</h1>
</div>
<div class="table-wrapper" style="padding:28px;max-width:700px">
  <form method="POST">
    <div class="form-group"><label>Nom du produit *</label><input type="text" name="name" class="form-control" required value="{{ product['name'] if product else '' }}"></div>
    <div class="form-group"><label>Description</label><textarea name="description" class="form-control" rows="4">{{ product['description'] if product else '' }}</textarea></div>
    <div class="form-row">
      <div class="form-group"><label>Prix (€) *</label><input type="number" name="price" class="form-control" required step="0.01" min="0" value="{{ product['price'] if product else '' }}"></div>
      <div class="form-group"><label>Stock *</label><input type="number" name="stock" class="form-control" required min="0" value="{{ product['stock'] if product else 0 }}"></div>
    </div>
    <div class="form-group">
      <label>Catégorie</label>
      <select name="category_id" class="form-control">
        <option value="">-- Aucune --</option>
        {% for cat in categories %}
        <option value="{{ cat['id'] }}" {% if product and product['category_id']==cat['id'] %}selected{% endif %}>{{ cat['icon'] }} {{ cat['name'] }}</option>
        {% endfor %}
      </select>
    </div>
    <div class="form-group"><label>URL de l'image</label><input type="url" name="image_url" class="form-control" placeholder="https://..." value="{{ product['image_url'] if product else '' }}"></div>
    <div class="form-group">
      <label>Statut</label>
      <select name="is_active" class="form-control">
        <option value="1" {% if not product or product['is_active'] %}selected{% endif %}>✅ Actif</option>
        <option value="0" {% if product and not product['is_active'] %}selected{% endif %}>❌ Inactif</option>
      </select>
    </div>
    <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-save"></i> Sauvegarder</button>
  </form>
</div>
{% endblock %}'''

ADMIN_USERS_TEMPLATE = '''{% extends "admin_base" %}
{% block admin_content %}
<h1 class="admin-page-title"><i class="fas fa-users"></i> Utilisateurs</h1>
<div class="table-wrapper">
  <div class="table-header"><span class="table-title">{{ users|length }} utilisateur(s)</span></div>
  <table>
    <thead><tr><th>ID</th><th>Utilisateur</th><th>Email</th><th>Rôle</th><th>Inscrit le</th><th>Statut</th><th>Action</th></tr></thead>
    <tbody>
      {% for u in users %}
      <tr>
        <td>#{{ u['id'] }}</td>
        <td><strong>{{ u['username'] }}</strong><br><small style="color:var(--gray-mid)">{{ u['first_name'] or '' }} {{ u['last_name'] or '' }}</small></td>
        <td>{{ u['email'] }}</td>
        <td><span class="badge-status {% if u['role']=='admin' %}badge-admin{% else %}badge-client{% endif %}">{{ u['role'] }}</span></td>
        <td>{{ u['created_at'][:10] }}</td>
        <td><span class="badge-status {% if u['is_active'] %}badge-active{% else %}badge-inactive{% endif %}">{% if u['is_active'] %}Actif{% else %}Inactif{% endif %}</span></td>
        <td>
          {% if u['id'] != session.get('user_id') %}
          <form action="{{ url_for('admin_toggle_user', uid=u['id']) }}" method="POST" style="display:inline">
            <button type="submit" class="btn btn-xs {% if u['is_active'] %}btn-danger{% else %}btn-success{% endif %}">{% if u['is_active'] %}Désactiver{% else %}Activer{% endif %}</button>
          </form>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}'''

ADMIN_ORDERS_TEMPLATE = '''{% extends "admin_base" %}
{% block admin_content %}
<h1 class="admin-page-title"><i class="fas fa-shopping-bag"></i> Commandes</h1>
<div class="table-wrapper">
  <table>
    <thead><tr><th>#</th><th>Client</th><th>Date</th><th>Total</th><th>Paiement</th><th>Statut</th><th>Action</th></tr></thead>
    <tbody>
      {% for o in orders %}
      <tr>
        <td><strong>#{{ o['id'] }}</strong></td>
        <td>{{ o['username'] }}</td>
        <td>{{ o['order_date'][:10] }}</td>
        <td><strong>{{ "%.2f"|format(o['total_amount']) }} €</strong></td>
        <td>{{ o['payment_method'] or '-' }}</td>
        <td>
          <form action="{{ url_for('admin_update_order_status', oid=o['id']) }}" method="POST" style="display:flex;gap:6px">
            <select name="status" class="form-control" style="width:140px;padding:5px 8px;font-size:.82rem">
              <option value="en_attente" {% if o['status']=='en_attente' %}selected{% endif %}>⏳ En attente</option>
              <option value="expediee" {% if o['status']=='expediee' %}selected{% endif %}>🚚 Expédiée</option>
              <option value="livree" {% if o['status']=='livree' %}selected{% endif %}>✅ Livrée</option>
              <option value="annulee" {% if o['status']=='annulee' %}selected{% endif %}>❌ Annulée</option>
            </select>
            <button type="submit" class="btn btn-xs btn-royal"><i class="fas fa-save"></i></button>
          </form>
        </td>
        <td><a href="{{ url_for('order_detail', oid=o['id']) }}" class="btn btn-xs btn-royal"><i class="fas fa-eye"></i></a></td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>
{% endblock %}'''

ADMIN_CATEGORIES_TEMPLATE = '''{% extends "admin_base" %}
{% block admin_content %}
<h1 class="admin-page-title"><i class="fas fa-tags"></i> Catégories</h1>
<div style="display:grid;grid-template-columns:1fr 1fr;gap:24px">
  <div class="table-wrapper">
    <div class="table-header"><span class="table-title">Liste des catégories</span></div>
    <table>
      <thead><tr><th>Icône</th><th>Nom</th><th>Description</th><th>Action</th></tr></thead>
      <tbody>
        {% for cat in categories %}
        <tr>
          <td style="font-size:1.5rem">{{ cat['icon'] }}</td>
          <td><strong>{{ cat['name'] }}</strong></td>
          <td style="color:var(--gray-mid);font-size:.85rem">{{ cat['description'] or '-' }}</td>
          <td>
            <form action="{{ url_for('admin_delete_category', cid=cat['id']) }}" method="POST" onsubmit="return confirm('Supprimer cette catégorie ?')">
              <button type="submit" class="btn btn-xs btn-danger"><i class="fas fa-trash"></i></button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
  </div>
  <div class="table-wrapper" style="padding:24px">
    <h3 style="font-weight:800;margin-bottom:20px;color:var(--royal-dark)">Ajouter une catégorie</h3>
    <form method="POST" action="{{ url_for('admin_add_category') }}">
      <div class="form-group"><label>Nom *</label><input type="text" name="name" class="form-control" required placeholder="Nom de la catégorie"></div>
      <div class="form-group"><label>Description</label><input type="text" name="description" class="form-control" placeholder="Description courte"></div>
      <div class="form-group"><label>Icône (emoji)</label><input type="text" name="icon" class="form-control" placeholder="📦" value="📦" maxlength="4"></div>
      <button type="submit" class="btn btn-primary btn-block"><i class="fas fa-plus"></i> Ajouter</button>
    </form>
  </div>
</div>
{% endblock %}'''

ERROR_404_TEMPLATE = '''{% extends "base" %}
{% block title %}Page introuvable{% endblock %}
{% block content %}
<div class="empty-state" style="padding:100px 20px">
  <i class="fas fa-search" style="color:var(--royal-light);font-size:5rem"></i>
  <h3 style="font-size:2rem">404 — Page introuvable</h3>
  <p>La page que vous cherchez n'existe pas.</p>
  <a href="{{ url_for('index') }}" class="btn btn-royal mt-4"><i class="fas fa-home"></i> Retour à l'accueil</a>
</div>
{% endblock %}'''

ERROR_403_TEMPLATE = '''{% extends "base" %}
{% block title %}Accès refusé{% endblock %}
{% block content %}
<div class="empty-state" style="padding:100px 20px">
  <i class="fas fa-lock" style="color:var(--danger);font-size:5rem"></i>
  <h3 style="font-size:2rem">403 — Accès refusé</h3>
  <p>Vous n'avez pas les permissions pour accéder à cette page.</p>
  <a href="{{ url_for('index') }}" class="btn btn-royal mt-4"><i class="fas fa-home"></i> Retour à l'accueil</a>
</div>
{% endblock %}'''

# ============================================================
# CHARGEUR DE TEMPLATES (DOIT ÊTRE DÉFINI AVANT LES ROUTES)
# ============================================================
app.jinja_loader = DictLoader({
    'base':                    BASE_TEMPLATE,
    'admin_base':              ADMIN_BASE,
    'index':                   INDEX_TEMPLATE,
    'products':                PRODUCTS_TEMPLATE,
    'product_detail':          PRODUCT_DETAIL_TEMPLATE,
    'login':                   LOGIN_TEMPLATE,
    'register':                REGISTER_TEMPLATE,
    'profile':                 PROFILE_TEMPLATE,
    'cart':                    CART_TEMPLATE,
    'checkout':                CHECKOUT_TEMPLATE,
    'orders':                  ORDERS_TEMPLATE,
    'order_detail':            ORDER_DETAIL_TEMPLATE,
    'wishlist':                WISHLIST_TEMPLATE,
    'admin_dashboard':         ADMIN_DASHBOARD_TEMPLATE,
    'admin_products':          ADMIN_PRODUCTS_TEMPLATE,
    'admin_product_form':      ADMIN_PRODUCT_FORM_TEMPLATE,
    'admin_users':             ADMIN_USERS_TEMPLATE,
    'admin_orders':            ADMIN_ORDERS_TEMPLATE,
    'admin_categories':        ADMIN_CATEGORIES_TEMPLATE,
    '404':                     ERROR_404_TEMPLATE,
    '403':                     ERROR_403_TEMPLATE,
})

# ============================================================
# ROUTES — PAGES PUBLIQUES
# ============================================================
@app.route('/')
def index():
    conn = get_db()
    products = conn.execute('''
        SELECT p.*, c.name as cat_name,
               (SELECT COUNT(*) FROM reviews r WHERE r.product_id=p.id) as review_count
        FROM products p LEFT JOIN categories c ON p.category_id=c.id
        WHERE p.is_active=1 ORDER BY p.created_at DESC LIMIT 8
    ''').fetchall()
    categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    wishlist_ids = set()
    if session.get('user_id'):
        rows = conn.execute("SELECT product_id FROM wishlist WHERE user_id=?", (session['user_id'],)).fetchall()
        wishlist_ids = {r['product_id'] for r in rows}
    conn.close()
    return render_template('index', products=products, categories=categories, wishlist_ids=wishlist_ids)


@app.route('/products')
def products():
    q              = sanitize_input(request.args.get('q', ''))
    category_filter= request.args.get('category', '')
    pmin           = request.args.get('pmin', '')
    pmax           = request.args.get('pmax', '')
    sort           = request.args.get('sort', 'newest')
    page           = max(1, int(request.args.get('page', 1)))

    conn = get_db()
    where, params = ["p.is_active=1"], []
    if q:
        where.append("(p.name LIKE ? OR p.description LIKE ?)")
        params += [f'%{q}%', f'%{q}%']
    if category_filter:
        where.append("p.category_id=?"); params.append(category_filter)
    if pmin:
        where.append("p.price>=?"); params.append(float(pmin))
    if pmax:
        where.append("p.price<=?"); params.append(float(pmax))

    order = {'price_asc':'p.price ASC','price_desc':'p.price DESC','name':'p.name ASC'}.get(sort, 'p.created_at DESC')
    base_q = f"FROM products p LEFT JOIN categories c ON p.category_id=c.id WHERE {' AND '.join(where)}"

    total = conn.execute(f"SELECT COUNT(*) {base_q}", params).fetchone()[0]
    total_pages = max(1, (total + PER_PAGE - 1) // PER_PAGE)
    page = min(page, total_pages)
    offset = (page - 1) * PER_PAGE

    products_list = conn.execute(
        f"SELECT p.*, c.name as cat_name {base_q} ORDER BY {order} LIMIT ? OFFSET ?",
        params + [PER_PAGE, offset]
    ).fetchall()

    categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    wishlist_ids = set()
    if session.get('user_id'):
        rows = conn.execute("SELECT product_id FROM wishlist WHERE user_id=?", (session['user_id'],)).fetchall()
        wishlist_ids = {r['product_id'] for r in rows}
    conn.close()

    return render_template('products', products=products_list, categories=categories,
                           wishlist_ids=wishlist_ids, q=q, category_filter=category_filter,
                           pmin=pmin, pmax=pmax, sort=sort, page=page,
                           total=total, total_pages=total_pages)


@app.route('/product/<int:pid>')
def product_detail(pid):
    conn = get_db()
    product = conn.execute('''
        SELECT p.*, c.name as cat_name FROM products p
        LEFT JOIN categories c ON p.category_id=c.id
        WHERE p.id=? AND p.is_active=1
    ''', (pid,)).fetchone()
    if not product:
        abort(404)
    sizes   = conn.execute("SELECT * FROM product_sizes WHERE product_id=? ORDER BY size", (pid,)).fetchall()
    reviews = conn.execute('''
        SELECT r.*, u.username FROM reviews r
        JOIN users u ON r.user_id=u.id
        WHERE r.product_id=? ORDER BY r.created_at DESC
    ''', (pid,)).fetchall()
    conn.close()
    return render_template('product_detail', product=product, sizes=sizes, reviews=reviews)


@app.route('/product/<int:pid>/review', methods=['POST'])
@login_required
def add_review(pid):
    rating  = int(request.form.get('rating', 5))
    comment = sanitize_input(request.form.get('comment', ''))
    conn = get_db()
    try:
        conn.execute("INSERT INTO reviews (product_id,user_id,rating,comment) VALUES (?,?,?,?)",
                     (pid, session['user_id'], rating, comment))
        conn.commit()
        flash('Avis publié !', 'success')
    except Exception:
        flash('Vous avez déjà laissé un avis pour ce produit.', 'warning')
    conn.close()
    return redirect(url_for('product_detail', pid=pid))

# ============================================================
# AUTH
# ============================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        ip = request.remote_addr
        if check_brute_force(ip):
            flash('Trop de tentatives. Réessayez dans 5 minutes.', 'danger')
            return render_template('login')
        username = sanitize_input(request.form.get('username', ''))
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE (username=? OR email=?) AND is_active=1",
            (username, username)
        ).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            clear_login_attempts(ip)
            session.permanent = True
            session['user_id']  = user['id']
            session['username'] = user['username']
            session['role']     = user['role']
            session['address']  = user['address'] or ''
            flash(f'Bienvenue, {user["username"]} !', 'success')
            return redirect(request.args.get('next') or url_for('index'))
        else:
            record_failed_login(ip)
            flash('Identifiants incorrects.', 'danger')
    return render_template('login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if session.get('user_id'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        username   = sanitize_input(request.form.get('username', ''))
        email      = request.form.get('email', '').strip()
        password   = request.form.get('password', '')
        password2  = request.form.get('password2', '')
        first_name = sanitize_input(request.form.get('first_name', ''))
        last_name  = sanitize_input(request.form.get('last_name', ''))
        phone      = sanitize_input(request.form.get('phone', ''))

        if not username or not email or not password:
            flash('Tous les champs obligatoires doivent être remplis.', 'danger')
            return render_template('register')
        if password != password2:
            flash('Les mots de passe ne correspondent pas.', 'danger')
            return render_template('register')
        if len(password) < 6:
            flash('Le mot de passe doit contenir au moins 6 caractères.', 'danger')
            return render_template('register')

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username,email,password,first_name,last_name,phone) VALUES (?,?,?,?,?,?)",
                (username, email, generate_password_hash(password), first_name, last_name, phone)
            )
            conn.commit()
            flash('Compte créé avec succès ! Connectez-vous.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Ce nom d\'utilisateur ou cet email est déjà utilisé.', 'danger')
        finally:
            conn.close()
    return render_template('register')


@app.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('index'))

# ============================================================
# PROFIL
# ============================================================
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    if request.method == 'POST':
        email      = request.form.get('email', '').strip()
        first_name = sanitize_input(request.form.get('first_name', ''))
        last_name  = sanitize_input(request.form.get('last_name', ''))
        phone      = sanitize_input(request.form.get('phone', ''))
        address    = sanitize_input(request.form.get('address', ''))
        new_pw     = request.form.get('new_password', '')
        try:
            if new_pw:
                conn.execute(
                    "UPDATE users SET email=?,first_name=?,last_name=?,phone=?,address=?,password=? WHERE id=?",
                    (email, first_name, last_name, phone, address, generate_password_hash(new_pw), session['user_id'])
                )
            else:
                conn.execute(
                    "UPDATE users SET email=?,first_name=?,last_name=?,phone=?,address=? WHERE id=?",
                    (email, first_name, last_name, phone, address, session['user_id'])
                )
            conn.commit()
            session['address'] = address
            flash('Profil mis à jour !', 'success')
        except sqlite3.IntegrityError:
            flash('Cet email est déjà utilisé.', 'danger')
        user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()

    stats = {
        'orders':   conn.execute("SELECT COUNT(*) FROM orders WHERE user_id=?", (session['user_id'],)).fetchone()[0],
        'cart':     conn.execute("SELECT COALESCE(SUM(quantity),0) FROM cart WHERE user_id=?", (session['user_id'],)).fetchone()[0],
        'wishlist': conn.execute("SELECT COUNT(*) FROM wishlist WHERE user_id=?", (session['user_id'],)).fetchone()[0],
    }
    conn.close()
    return render_template('profile', user=user, stats=stats)

# ============================================================
# PANIER
# ============================================================
@app.route('/cart')
@login_required
def cart():
    conn = get_db()
    items = conn.execute('''
        SELECT c.id as cart_id, c.quantity, p.name, p.price as unit_price,
               p.stock, p.image_url, ps.size
        FROM cart c
        JOIN products p ON c.product_id=p.id
        LEFT JOIN product_sizes ps ON c.size_id=ps.id
        WHERE c.user_id=?
    ''', (session['user_id'],)).fetchall()
    conn.close()
    subtotal = sum(i['unit_price'] * i['quantity'] for i in items)
    return render_template('cart', items=items, subtotal=subtotal)


@app.route('/cart/add', methods=['POST'])
@login_required
def add_to_cart():
    product_id = int(request.form.get('product_id', 0))
    quantity   = max(1, int(request.form.get('quantity', 1)))
    size_id    = request.form.get('size_id') or None

    conn = get_db()
    product = conn.execute("SELECT * FROM products WHERE id=? AND is_active=1", (product_id,)).fetchone()
    if not product or product['stock'] < quantity:
        flash('Produit indisponible ou stock insuffisant.', 'danger')
        conn.close()
        return redirect(request.referrer or url_for('products'))

    existing = conn.execute(
        "SELECT id, quantity FROM cart WHERE user_id=? AND product_id=? AND COALESCE(size_id,0)=COALESCE(?,0)",
        (session['user_id'], product_id, size_id)
    ).fetchone()
    if existing:
        new_qty = existing['quantity'] + quantity
        conn.execute("UPDATE cart SET quantity=? WHERE id=?", (min(new_qty, product['stock']), existing['id']))
    else:
        conn.execute("INSERT INTO cart (user_id,product_id,size_id,quantity) VALUES (?,?,?,?)",
                     (session['user_id'], product_id, size_id, quantity))
    conn.commit()
    conn.close()
    flash('Produit ajouté au panier !', 'success')
    return redirect(request.referrer or url_for('cart'))


@app.route('/cart/update/<int:cid>', methods=['POST'])
@login_required
def update_cart(cid):
    quantity = max(1, int(request.form.get('quantity', 1)))
    conn = get_db()
    conn.execute("UPDATE cart SET quantity=? WHERE id=? AND user_id=?",
                 (quantity, cid, session['user_id']))
    conn.commit()
    conn.close()
    return redirect(url_for('cart'))


@app.route('/cart/remove/<int:cid>')
@login_required
def remove_cart(cid):
    conn = get_db()
    conn.execute("DELETE FROM cart WHERE id=? AND user_id=?", (cid, session['user_id']))
    conn.commit()
    conn.close()
    flash('Article retiré du panier.', 'info')
    return redirect(url_for('cart'))

# ============================================================
# COMMANDES
# ============================================================
@app.route('/checkout')
@login_required
def checkout():
    conn = get_db()
    items = conn.execute('''
        SELECT c.quantity, p.name, p.price as unit_price, p.stock
        FROM cart c JOIN products p ON c.product_id=p.id
        WHERE c.user_id=?
    ''', (session['user_id'],)).fetchall()
    conn.close()
    if not items:
        flash('Votre panier est vide.', 'warning')
        return redirect(url_for('cart'))
    subtotal = sum(i['unit_price'] * i['quantity'] for i in items)
    return render_template('checkout', items=items, subtotal=subtotal)


@app.route('/order/place', methods=['POST'])
@login_required
def place_order():
    shipping_address = sanitize_input(request.form.get('shipping_address', ''))
    payment_method   = request.form.get('payment_method', 'carte')
    notes            = sanitize_input(request.form.get('notes', ''))

    if not shipping_address:
        flash('L\'adresse de livraison est obligatoire.', 'danger')
        return redirect(url_for('checkout'))

    conn = get_db()
    items = conn.execute('''
        SELECT c.id as cart_id, c.quantity, c.product_id, p.price, p.stock, ps.size
        FROM cart c JOIN products p ON c.product_id=p.id
        LEFT JOIN product_sizes ps ON c.size_id=ps.id
        WHERE c.user_id=?
    ''', (session['user_id'],)).fetchall()

    if not items:
        flash('Votre panier est vide.', 'warning')
        conn.close()
        return redirect(url_for('cart'))

    total = sum(i['price'] * i['quantity'] for i in items) * 1.2
    try:
        cur = conn.execute(
            "INSERT INTO orders (user_id,total_amount,shipping_address,payment_method,notes) VALUES (?,?,?,?,?)",
            (session['user_id'], total, shipping_address, payment_method, notes)
        )
        order_id = cur.lastrowid
        for item in items:
            conn.execute(
                "INSERT INTO order_items (order_id,product_id,size,quantity,unit_price) VALUES (?,?,?,?,?)",
                (order_id, item['product_id'], item['size'], item['quantity'], item['price'])
            )
            conn.execute("UPDATE products SET stock=stock-? WHERE id=?",
                         (item['quantity'], item['product_id']))
        conn.execute("DELETE FROM cart WHERE user_id=?", (session['user_id'],))
        conn.commit()
        flash(f'Commande #{order_id} passée avec succès !', 'success')
        return redirect(url_for('order_detail', oid=order_id))
    except Exception as e:
        conn.rollback()
        flash('Erreur lors de la commande. Réessayez.', 'danger')
        return redirect(url_for('checkout'))
    finally:
        conn.close()


@app.route('/orders')
@login_required
def orders():
    conn = get_db()
    orders_list = conn.execute('''
        SELECT o.*, COUNT(oi.id) as item_count
        FROM orders o LEFT JOIN order_items oi ON o.id=oi.order_id
        WHERE o.user_id=? GROUP BY o.id ORDER BY o.order_date DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('orders', orders=orders_list)


@app.route('/order/<int:oid>')
@login_required
def order_detail(oid):
    conn = get_db()
    order = conn.execute("SELECT * FROM orders WHERE id=?", (oid,)).fetchone()
    if not order or (order['user_id'] != session['user_id'] and session.get('role') != 'admin'):
        abort(403)
    items = conn.execute('''
        SELECT oi.*, p.name FROM order_items oi
        JOIN products p ON oi.product_id=p.id
        WHERE oi.order_id=?
    ''', (oid,)).fetchall()
    conn.close()
    return render_template('order_detail', order=order, items=items)

# ============================================================
# WISHLIST
# ============================================================
@app.route('/wishlist')
@login_required
def wishlist_view():
    conn = get_db()
    products_list = conn.execute('''
        SELECT p.*, c.name as cat_name FROM wishlist w
        JOIN products p ON w.product_id=p.id
        LEFT JOIN categories c ON p.category_id=c.id
        WHERE w.user_id=? ORDER BY w.added_at DESC
    ''', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('wishlist', products=products_list)


@app.route('/wishlist/toggle/<int:pid>', methods=['POST'])
@login_required
def toggle_wishlist(pid):
    conn = get_db()
    existing = conn.execute(
        "SELECT id FROM wishlist WHERE user_id=? AND product_id=?",
        (session['user_id'], pid)
    ).fetchone()
    if existing:
        conn.execute("DELETE FROM wishlist WHERE id=?", (existing['id'],))
        conn.commit()
        conn.close()
        return jsonify({'status': 'removed'})
    else:
        conn.execute("INSERT INTO wishlist (user_id,product_id) VALUES (?,?)", (session['user_id'], pid))
        conn.commit()
        conn.close()
        return jsonify({'status': 'added'})

# ============================================================
# ADMIN
# ============================================================
@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db()
    stats = {
        'products': conn.execute("SELECT COUNT(*) FROM products WHERE is_active=1").fetchone()[0],
        'orders':   conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0],
        'users':    conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        'revenue':  conn.execute("SELECT SUM(total_amount) FROM orders WHERE status!='annulee'").fetchone()[0],
    }
    recent_orders = conn.execute('''
        SELECT o.*, u.username FROM orders o JOIN users u ON o.user_id=u.id
        ORDER BY o.order_date DESC LIMIT 5
    ''').fetchall()
    low_stock = conn.execute(
        "SELECT name, stock FROM products WHERE is_active=1 AND stock<=5 ORDER BY stock LIMIT 10"
    ).fetchall()
    conn.close()
    return render_template('admin_dashboard', stats=stats, recent_orders=recent_orders, low_stock=low_stock)


@app.route('/admin/products')
@admin_required
def admin_products():
    q = sanitize_input(request.args.get('q', ''))
    conn = get_db()
    if q:
        products_list = conn.execute('''
            SELECT p.*, c.name as cat_name FROM products p
            LEFT JOIN categories c ON p.category_id=c.id
            WHERE p.name LIKE ? ORDER BY p.created_at DESC
        ''', (f'%{q}%',)).fetchall()
    else:
        products_list = conn.execute('''
            SELECT p.*, c.name as cat_name FROM products p
            LEFT JOIN categories c ON p.category_id=c.id
            ORDER BY p.created_at DESC
        ''').fetchall()
    conn.close()
    return render_template('admin_products', products=products_list, q=q)


@app.route('/admin/products/add', methods=['GET', 'POST'])
@admin_required
def admin_add_product():
    conn = get_db()
    categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    if request.method == 'POST':
        name        = sanitize_input(request.form.get('name', ''))
        description = sanitize_input(request.form.get('description', ''))
        price       = float(request.form.get('price', 0))
        stock       = int(request.form.get('stock', 0))
        category_id = request.form.get('category_id') or None
        image_url   = request.form.get('image_url', '').strip()
        is_active   = int(request.form.get('is_active', 1))
        conn.execute(
            "INSERT INTO products (name,description,price,stock,category_id,image_url,is_active,created_by) VALUES (?,?,?,?,?,?,?,?)",
            (name, description, price, stock, category_id, image_url, is_active, session['user_id'])
        )
        conn.commit()
        conn.close()
        flash('Produit ajouté !', 'success')
        return redirect(url_for('admin_products'))
    conn.close()
    return render_template('admin_product_form', product=None, categories=categories)


@app.route('/admin/products/<int:pid>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_product(pid):
    conn = get_db()
    product    = conn.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    if not product:
        abort(404)
    if request.method == 'POST':
        name        = sanitize_input(request.form.get('name', ''))
        description = sanitize_input(request.form.get('description', ''))
        price       = float(request.form.get('price', 0))
        stock       = int(request.form.get('stock', 0))
        category_id = request.form.get('category_id') or None
        image_url   = request.form.get('image_url', '').strip()
        is_active   = int(request.form.get('is_active', 1))
        conn.execute(
            "UPDATE products SET name=?,description=?,price=?,stock=?,category_id=?,image_url=?,is_active=? WHERE id=?",
            (name, description, price, stock, category_id, image_url, is_active, pid)
        )
        conn.commit()
        conn.close()
        flash('Produit modifié !', 'success')
        return redirect(url_for('admin_products'))
    conn.close()
    return render_template('admin_product_form', product=product, categories=categories)


@app.route('/admin/products/<int:pid>/delete', methods=['POST'])
@admin_required
def admin_delete_product(pid):
    conn = get_db()
    conn.execute("UPDATE products SET is_active=0 WHERE id=?", (pid,))
    conn.commit()
    conn.close()
    flash('Produit supprimé.', 'success')
    return redirect(url_for('admin_products'))


@app.route('/admin/users')
@admin_required
def admin_users():
    conn = get_db()
    users = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('admin_users', users=users)


@app.route('/admin/users/<int:uid>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(uid):
    if uid == session['user_id']:
        flash('Impossible de désactiver votre propre compte.', 'danger')
        return redirect(url_for('admin_users'))
    conn = get_db()
    user = conn.execute("SELECT is_active FROM users WHERE id=?", (uid,)).fetchone()
    if user:
        conn.execute("UPDATE users SET is_active=? WHERE id=?", (0 if user['is_active'] else 1, uid))
        conn.commit()
    conn.close()
    flash('Statut utilisateur mis à jour.', 'success')
    return redirect(url_for('admin_users'))


@app.route('/admin/orders')
@admin_required
def admin_orders():
    conn = get_db()
    orders_list = conn.execute('''
        SELECT o.*, u.username FROM orders o
        JOIN users u ON o.user_id=u.id
        ORDER BY o.order_date DESC
    ''').fetchall()
    conn.close()
    return render_template('admin_orders', orders=orders_list)


@app.route('/admin/orders/<int:oid>/status', methods=['POST'])
@admin_required
def admin_update_order_status(oid):
    status = request.form.get('status', 'en_attente')
    conn = get_db()
    conn.execute("UPDATE orders SET status=? WHERE id=?", (status, oid))
    conn.commit()
    conn.close()
    flash('Statut de la commande mis à jour.', 'success')
    return redirect(url_for('admin_orders'))


@app.route('/admin/categories')
@admin_required
def admin_categories():
    conn = get_db()
    categories = conn.execute("SELECT * FROM categories ORDER BY name").fetchall()
    conn.close()
    return render_template('admin_categories', categories=categories)


@app.route('/admin/categories/add', methods=['POST'])
@admin_required
def admin_add_category():
    name        = sanitize_input(request.form.get('name', ''))
    description = sanitize_input(request.form.get('description', ''))
    icon        = request.form.get('icon', '📦').strip() or '📦'
    if name:
        conn = get_db()
        conn.execute("INSERT INTO categories (name,description,icon) VALUES (?,?,?)", (name, description, icon))
        conn.commit()
        conn.close()
        flash('Catégorie ajoutée !', 'success')
    return redirect(url_for('admin_categories'))


@app.route('/admin/categories/<int:cid>/delete', methods=['POST'])
@admin_required
def admin_delete_category(cid):
    conn = get_db()
    conn.execute("DELETE FROM categories WHERE id=?", (cid,))
    conn.commit()
    conn.close()
    flash('Catégorie supprimée.', 'success')
    return redirect(url_for('admin_categories'))

# ============================================================
# GESTION DES ERREURS
# ============================================================
@app.errorhandler(404)
def not_found(e):
    return render_template('404'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('403'), 403

@app.errorhandler(500)
def server_error(e):
    return render_template('404'), 500

# ============================================================
# LANCEMENT — TOUJOURS EN DERNIER
# ============================================================
if __name__ == '__main__':
    init_db()
    print("✅ Base de données initialisée")
    
    # Récupérer l'adresse IP locale automatiquement
    import socket
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    
    print("🚀 V-LINE démarré sur :")
    print(f"   → http://127.0.0.1:5000 (sur cet ordinateur)")
    print(f"   → http://{local_ip}:5000 (sur le réseau local)")
    print("👤 Admin : admin / Admin@VLine2024!")
    
    # Écouter sur toutes les interfaces réseau
    app.run(host='0.0.0.0', debug=True, port=5000)