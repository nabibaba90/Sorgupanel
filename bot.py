#!/usr/bin/env python3
# b_fixed2.py - templates path duplication bug fixed + full mapping preserved
# Çalıştır: python b_fixed2.py (proje kökünde ol — içinde templates/ ve static/ bulunmalı)

import os
import time
import hmac
import binascii
import hashlib
import logging
import threading
import re
from collections import defaultdict
from functools import wraps
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from flask import (
    Flask, request, jsonify, Response, send_from_directory, session, abort, redirect
)

# ---------------- CONFIG ----------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-CHANGE_ME')
# VIP bilgileri kullanıcı talebine göre güncellendi:
VIP_USERNAME = os.environ.get('VIP_USERNAME', 'Keneviz')
VIP_PASSWORD = os.environ.get('VIP_PASSWORD', 'keneviz0101')
FREE_USERNAME = os.environ.get('FREE_USERNAME', 'free_user')
FREE_PASSWORD = os.environ.get('FREE_PASSWORD', 'free_pass')
KENVIZ_CHALLENGE_TOKEN = os.environ.get('KENVIZ_CHALLENGE_TOKEN', 'letmein')

ALLOWED_OUTBOUND_HOSTS = os.environ.get(
    'ALLOWED_OUTBOUND_HOSTS',
    'ezelnabapi-dppd.onrender.com,kenevizbotapi.onrender.com,localhost,127.0.0.1'
).split(',')

RATE_LIMIT_PER_MINUTE = int(os.environ.get('RATE_LIMIT_PER_MINUTE', '15'))
BLOCK_SECONDS = int(os.environ.get('BLOCK_SECONDS', '300'))
GLOBAL_REQUEST_THRESHOLD_10S = int(os.environ.get('GLOBAL_REQUEST_THRESHOLD_10S', '1500'))
MAX_CONCURRENT_REQUESTS = int(os.environ.get('MAX_CONCURRENT_REQUESTS', '100'))

# ---------------- APP ----------------
app = Flask(__name__, static_folder=STATIC_DIR, template_folder=TEMPLATES_DIR)
app.secret_key = SECRET_KEY
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=False)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('b_fixed2')

# ---------- HTTP session retries ----------
session_requests = requests.Session()
retries = Retry(total=2, backoff_factor=0.3, status_forcelist=(500,502,503,504))
session_requests.mount('https://', HTTPAdapter(max_retries=retries))
session_requests.mount('http://', HTTPAdapter(max_retries=retries))

# ---------- in-memory rate data ----------
lock = threading.Lock()
requests_by_ip = defaultdict(list)
blocked_ips = {}
recent_global_requests = []
concurrent_semaphore = threading.BoundedSemaphore(value=MAX_CONCURRENT_REQUESTS)

# ---------- helpers ----------
re_digits = re.compile(r'^\d+$')
re_safe_domain = re.compile(r'^[a-zA-Z0-9.-]+$')
re_safe_simple = re.compile(r'^[\w @._-]+$')

def is_valid_tc(tc: str) -> bool:
    return bool(tc and re_digits.match(tc) and len(tc) == 11)

def is_valid_gsm(gsm: str) -> bool:
    return bool(gsm and re_digits.match(gsm) and 9 <= len(gsm) <= 15)

def is_safe_domain(domain: str) -> bool:
    if not domain or '://' in domain:
        return False
    return bool(re_safe_domain.match(domain))

def safe_param(s: str, max_len=200) -> bool:
    return bool(s is not None and len(s) <= max_len and re_safe_simple.match(s))

def get_remote_addr():
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def temporary_block(ip):
    with lock:
        blocked_ips[ip] = int(time.time()) + BLOCK_SECONDS
    logger.warning("IP %s blocked for %s seconds", ip, BLOCK_SECONDS)

def is_blocked(ip):
    now = int(time.time())
    expiry = blocked_ips.get(ip)
    if expiry and expiry > now:
        return True
    if expiry and expiry <= now:
        with lock:
            blocked_ips.pop(ip, None)
    return False

def record_request(ip):
    now = int(time.time())
    with lock:
        lst = requests_by_ip[ip]
        lst.append(now)
        while lst and lst[0] < now - 60:
            lst.pop(0)
        recent_global_requests.append(now)
        while recent_global_requests and recent_global_requests[0] < now - 10:
            recent_global_requests.pop(0)

def rate_limit_exceeded(ip):
    with lock:
        lst = requests_by_ip[ip]
        now = int(time.time())
        while lst and lst[0] < now - 60:
            lst.pop(0)
        return len(lst) > RATE_LIMIT_PER_MINUTE

def too_many_global_requests():
    with lock:
        return len(recent_global_requests) > GLOBAL_REQUEST_THRESHOLD_10S

# ---------- security headers ----------
@app.after_request
def set_security_headers(resp):
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['Referrer-Policy'] = 'no-referrer-when-downgrade'
    resp.headers['Server'] = 'keneviz-server'
    resp.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' https://ezelnabapi-dppd.onrender.com http://localhost http://127.0.0.1;"
    )
    return resp

# ---------- decorators ----------
def rate_limit(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        ip = get_remote_addr()
        if is_blocked(ip):
            return jsonify({'error':'IP geçici olarak engellendi.'}), 403
        record_request(ip)
        if too_many_global_requests():
            return jsonify({'error':'Sunucu yoğunluğu, tekrar deneyin.'}), 503
        if rate_limit_exceeded(ip):
            temporary_block(ip)
            return jsonify({'error':f'Rate limit aşıldı. IP {BLOCK_SECONDS}s engellendi.'}), 429

        ua = (request.headers.get('User-Agent') or '').lower()
        suspicious_ua = ['curl/','python-requests','wget','scrapy','libwww-perl','bot']
        if any(s in ua for s in suspicious_ua) and not session.get('user'):
            with lock:
                if len(requests_by_ip[get_remote_addr()]) > max(2, RATE_LIMIT_PER_MINUTE//2):
                    temporary_block(ip)
                    return jsonify({'error':'Otomatik istek tespit edildi.'}), 429

        acquired = concurrent_semaphore.acquire(blocking=False)
        if not acquired:
            return jsonify({'error':'Sunucu meşgul. Tekrar deneyin.'}), 503
        try:
            return f(*args, **kwargs)
        finally:
            concurrent_semaphore.release()
    return wrapped

# ---------- util: outbound ----------
def _host_allowed(hostname: str) -> bool:
    if not hostname: return False
    hostname = hostname.lower()
    for a in ALLOWED_OUTBOUND_HOSTS:
        a = a.strip().lower()
        if not a: continue
        if a == '*': return True
        if hostname == a or hostname.endswith('.' + a):
            return True
    return False

def fetch_api_get(url, params=None):
    """
    Fetch an external API using the configured session.
    - Enforces allowed hostnames.
    - Forwards incoming User-Agent (or X-Forwarded-User-Agent) to outbound request.
    - Uses timeout=(5, 30) => connect 5s, read 30s.
    - Returns remote response content and remote status code / content-type directly.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname or (parsed.netloc.split(':')[0] if parsed.netloc else None)
        if not _host_allowed(host):
            logger.warning('Outbound disallowed host: %s', host)
            return jsonify({'error':'Dış API isteği reddedildi'}), 403

        # Prefer explicit forwarded header, then real UA, then default.
        forwarded_ua = request.headers.get('X-Forwarded-User-Agent') or request.headers.get('User-Agent') or 'keneviz-proxy/1.0'
        headers = {
            'User-Agent': forwarded_ua,
            'Accept': 'application/json, text/plain, */*'
        }
        logger.info('Proxying to %s (UA=%s) params=%s', host, forwarded_ua, params)

        # Connect timeout 5s, read timeout 30s -> total wait for response data up to ~30s
        resp = session_requests.get(url, params=params, timeout=(30, 30), headers=headers)

        # forward content and status code from remote without raising
        content = resp.content or b''
        content_type = resp.headers.get('Content-Type', 'application/octet-stream')
        logger.info('Received %s from %s (status=%s, len=%d)', url, host, resp.status_code, len(content))
        return Response(content, status=resp.status_code, mimetype=content_type)

    except requests.exceptions.ConnectTimeout:
        logger.exception('connect timeout when contacting %s', url)
        return jsonify({'error':'Dış API bağlantı zaman aşımı (connect)'}), 504
    except requests.exceptions.ReadTimeout:
        logger.exception('read timeout when contacting %s', url)
        return jsonify({'error':'Dış API cevap zaman aşımı (read)'}), 504
    except requests.exceptions.RequestException as e:
        logger.exception('fetch_api_get request exception')
        # For many request exceptions, 502 Bad Gateway is appropriate.
        return jsonify({'error':'Dış API hatası','message':str(e)}), 502
    except Exception as e:
        logger.exception('fetch_api_get unexpected error')
        return jsonify({'error':'Dış API hatası','message':str(e)}), 500

# ---------- safe template sender ----------
def safe_send_template(filename):
    path = os.path.join(TEMPLATES_DIR, filename)
    if not os.path.isfile(path):
        logger.warning('Template yok: %s', path)
        abort(404)
    return send_from_directory(TEMPLATES_DIR, filename)

# ---------- static/assets routes ----------
@app.route('/assets/<path:filename>')
@rate_limit
def assets(filename):
    return send_from_directory(TEMPLATES_DIR, filename)

@app.route('/static/<path:filename>')
@rate_limit
def static_files(filename):
    return send_from_directory(STATIC_DIR, filename)

@app.route('/favicon.ico')
def favicon():
    candidates = [
        os.path.join(TEMPLATES_DIR, 'favicon.ico'),
        os.path.join(STATIC_DIR, 'favicon.ico'),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return send_from_directory(os.path.dirname(c), os.path.basename(c))
    return '', 204

# ---------- robot gate ----------
EXEMPT_PATH_PREFIXES = ('/static/', '/assets/', '/favicon.ico', '/robots.txt')
EXEMPT_PATHS = set(['/robot_dogrulama', '/keneviz_challenge', '/keneviz_verify', '/keneviz_pass', '/login', '/api/login', '/api/user'])

@app.before_request
def require_robot_challenge():
    if request.method == 'OPTIONS':
        return None
    path = request.path
    for pfx in EXEMPT_PATH_PREFIXES:
        if path.startswith(pfx):
            return None
    if path in EXEMPT_PATHS:
        return None
    if path == '/health' or path.startswith('/.well-known'):
        return None
    if session.get('passed_challenge'):
        return None
    if path.startswith('/api/'):
        return jsonify({'error':'Robot doğrulamasını geçmeden erişim yok.'}), 403
    return safe_send_template('robot_dogrulama.html')

# ---------- robot endpoints ----------
@app.route('/robot_dogrulama')
def robot_page():
    return safe_send_template('robot_dogrulama.html')

@app.route('/keneviz_challenge', methods=['POST'])
@rate_limit
def keneviz_challenge():
    try:
        nonce = binascii.hexlify(os.urandom(16)).decode()
        ts = int(time.time())
        session['keneviz_challenge'] = {'nonce':nonce, 'ts':ts}
        return jsonify({'challenge':nonce,'ts':ts}), 200
    except Exception:
        logger.exception('challenge create failed')
        return jsonify({'error':'challenge oluşturulamadı'}), 500

@app.route('/keneviz_verify', methods=['POST'])
@rate_limit
def keneviz_verify():
    data = request.get_json() or {}
    challenge_val = data.get('challenge') or data.get('nonce')
    client_meta = data.get('client_meta') or {}
    saved = session.get('keneviz_challenge')
    if not saved or not challenge_val:
        return jsonify({'success':False,'reason':'missing_challenge'}), 400
    now = int(time.time())
    if abs(now - int(saved.get('ts',0))) > 180:
        return jsonify({'success':False,'reason':'challenge_expired'}), 400
    if challenge_val != saved.get('nonce'):
        return jsonify({'success':False,'reason':'challenge_mismatch'}), 400
    try:
        if client_meta.get('webdriver'):
            return jsonify({'success':False,'reason':'webdriver_detected'}), 403
        moves = int(client_meta.get('moves') or 0)
        touch = bool(client_meta.get('touch'))
        hw = int(client_meta.get('hw') or 0)
        ua = (request.headers.get('User-Agent') or '').lower()
        suspicious_ua = ['curl/','python-requests','bot','wget','scrapy','libwww-perl']
        if any(s in ua for s in suspicious_ua) and moves < 1 and not touch:
            return jsonify({'success':False,'reason':'suspicious_ua'}), 403
        if moves < 1 and not touch and hw <= 1:
            return jsonify({'success':False,'reason':'no_interaction_detected'}), 403
        session['passed_challenge'] = True
        token = binascii.hexlify(os.urandom(16)).decode()
        session['keneviz_token'] = token
        session.pop('keneviz_challenge', None)
        return jsonify({'success':True,'verification_token':token}), 200
    except Exception:
        logger.exception('verify error')
        return jsonify({'success':False,'reason':'error'}), 500

@app.route('/keneviz_pass', methods=['POST'])
@rate_limit
def keneviz_pass():
    token = None
    if request.is_json:
        token = (request.json or {}).get('token')
    else:
        token = request.form.get('token')
    if token and token == KENVIZ_CHALLENGE_TOKEN:
        session['passed_challenge'] = True
        return jsonify({'success':True}), 200
    return jsonify({'success':False}), 400

# ---------- auth api ----------
@app.route('/api/login', methods=['POST'])
@rate_limit
def api_login():
    # Eğer klasik form POST ise (tarayıcı doğrudan form submit) -> redirect ile oturum kur
    if not request.is_json:
        username = (request.form.get('username') or '').strip()
        password = request.form.get('password') or ''
        if request.form.get('free'):
            session['user'] = {'username': FREE_USERNAME, 'role': 'free'}
            return redirect('/')
        if username == VIP_USERNAME and hmac.compare_digest(password, VIP_PASSWORD):
            session['user'] = {'username': VIP_USERNAME, 'role': 'vip'}
            return redirect('/')
        # Başarısız form postunda tekrar login sayfası
        return safe_send_template('login.html'), 401

    # JSON (AJAX / fetch) isteği
    data = request.get_json() or {}
    if data.get('free'):
        session['user'] = {'username': FREE_USERNAME, 'role': 'free'}
        return jsonify({'success': True, 'username': FREE_USERNAME, 'role': 'free', 'redirect': '/'}), 200
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    # JSON login için doğru değişkenler kullanıldı:
    if username == VIP_USERNAME and hmac.compare_digest(password, VIP_PASSWORD):
        session['user'] = {'username': VIP_USERNAME, 'role': 'vip'}
        return jsonify({'success': True, 'username': VIP_USERNAME, 'role': 'vip', 'redirect': '/'}), 200
    return jsonify({'success': False, 'message': 'Geçersiz kimlik bilgileri'}), 401

@app.route('/api/logout', methods=['POST'])
@rate_limit
def api_logout():
    session.pop('user', None)
    return jsonify({'success': True}), 200

@app.route('/api/user', methods=['GET'])
@rate_limit
def api_user():
    u = session.get('user')
    if not u:
        return jsonify({'logged_in': False, 'role': 'guest'}), 200
    return jsonify({'logged_in': True, 'username': u.get('username'), 'role': u.get('role')}), 200

# ---------- frontend pages ----------
@app.route('/')
@rate_limit
def index():
    u = session.get('user')
    if u:
        return safe_send_template('index.html')
    return safe_send_template('login.html')

@app.route('/login')
@rate_limit
def login_page():
    return safe_send_template('login.html')

@app.route('/sorgu.html')
@rate_limit
def sorgu_html():
    return safe_send_template('sorgu.html')

@app.route('/abonelik.html')
@rate_limit
def abonelik_html():
    path = os.path.join(TEMPLATES_DIR, 'abonelik.html')
    if os.path.isfile(path):
        return send_from_directory(TEMPLATES_DIR, 'abonelik.html')
    return "<h3>Abonelik sayfası yok (templates/abonelik.html)</h3>", 200

# ---------- api/sorgu mapping (tam mapping ekli) ----------
# Genişletilmiş mapping: api adı -> backend endpoint path
API_ENDPOINT_MAP = {
    'tc_sorgulama': 'tc_sorgulama',
    'tc_pro_sorgulama': 'tc_pro_sorgulama',
    'tc_pro': 'tc_pro_sorgulama',
    'yas': 'tc_sorgulama',
    'ad_soyad_pro': 'ad_soyad_pro',
    'is_yeri': 'is_yeri',
    'tc_gsm': 'tc_gsm',
    'adres': 'adres',
    'hane': 'hane',
    'apartman': 'apartman',
    'ada_parsel': 'ada_parsel',
    'aile': 'aile',
    'aile_pro': 'aile_pro',
    'es': 'es',
    'sulale': 'sulale',
    'lgs': 'lgs',
    'e-kurs': 'e_kurs',
    'e_kurs': 'e_kurs',
    'mhrs_randevu': 'mhrs_randevu',
    'prem_adres': 'prem_adres',
    'sgk_pro': 'sgk_pro',
    'vergi_levhasi': 'vergi_levhasi',
    'diploma': 'diploma',
    'basvuru': 'basvuru',
    'nobetci_eczane': 'nobetci_eczane',
    'randevu': 'randevu',
    'internet': 'internet',
    'personel': 'personel',
    'universite': 'universite',
    'sertifika': 'sertifika',
    'lgs_2': 'lgs_2',
    'muhalle': 'muhalle',
    'vesika': 'vesika',
    'ehliyet': 'ehliyet',
    'boy': 'boy',
    'ayak_no': 'ayak_no',
    'cm': 'cm',
    'burc': 'burc',
    'cocuk': 'cocuk',
    'baba': 'baba',
    'anne': 'anne',
    'ad_soyad': 'ad_soyad',
    'adi_il_ilce': 'adi_il_ilce',
    'prem_ad': 'prem_ad',
    'interpol': 'interpol',
    'sehit': 'sehit',
    'gsm_tc': 'gsm_tc',
    'operator': 'operator',
    'arac_parca': 'arac_parca',
    'arac_borc': 'arac_borc',
    'ip': 'ip',
    'dns': 'dns',
    'whois': 'whois',
    'subdomain': 'subdomain',
    'leak': 'leak',
    'telegram_sorgu': 'telegram_sorgu',
    'sifre_encrypt': 'sifre_encrypt',
    'facebook': 'facebook',
    'havadurumu': 'havadurumu',
    'email': 'email',
    'nude': 'nude',
    'vergi': 'vergi_levhasi',
    'url': 'url',
    'domain': 'domain',
    'query': 'query',
    'okulno': 'okulno',
    'kullanici': 'telegram_sorgu',
    'plaka': 'plaka',
    'numara': 'numara',
}

# Parametre gereksinimleri
API_PARAM_MAP = {
    'tc_sorgulama': ['tc'],
    'tc_pro_sorgulama': ['tc'],
    'tc_pro': ['tc'],
    'yas': ['tc'],
    'ad_soyad_pro': ['tc'],
    'is_yeri': ['tc'],
    'tc_gsm': ['tc'],
    'adres': ['tc'],
    'hane': ['tc'],
    'apartman': ['tc'],
    'ada_parsel': ['tc'],
    'aile': ['tc'],
    'aile_pro': ['tc'],
    'es': ['tc'],
    'sulale': ['tc'],
    'lgs': ['tc'],
    'e_kurs': ['tc','okulno'],
    'mhrs_randevu': ['tc'],
    'prem_adres': ['tc'],
    'sgk_pro': ['tc'],
    'vergi_levhasi': ['tc'],
    'diploma': ['tc'],
    'basvuru': ['tc'],
    'nobetci_eczane': ['tc'],
    'randevu': ['tc'],
    'internet': ['tc'],
    'personel': ['tc'],
    'universite': ['tc'],
    'sertifika': ['tc'],
    'lgs_2': ['tc'],
    'muhalle': ['tc'],
    'vesika': ['tc'],
    'ehliyet': ['tc'],
    'boy': ['tc'],
    'ayak_no': ['tc'],
    'cm': ['tc'],
    'burc': ['tc'],
    'cocuk': ['tc'],
    'baba': ['tc'],
    'anne': ['tc'],
    'ad_soyad': ['ad','soyad','il','ilce'],
    'adi_il_ilce': ['ad','il','ilce'],
    'prem_ad': ['ad','il','ilce'],
    'interpol': ['ad','soyad'],
    'sehit': ['ad','soyad'],
    'gsm_tc': ['gsm'],
    'operator': ['gsm'],
    'arac_parca': ['plaka'],
    'arac_borc': ['plaka'],
    'ip': ['domain'],
    'dns': ['domain'],
    'whois': ['domain'],
    'subdomain': ['url'],
    'leak': ['query'],
    'telegram_sorgu': ['kullanici'],
    'sifre_encrypt': ['method','password'],
    'facebook': ['numara'],
    'havadurumu': ['sehir'],
    'email': ['email'],
    'nude': [],
    'vergi': ['vergi'],
    'url': ['url'],
    'domain': ['domain'],
    'query': ['query'],
    'okulno': ['okulno'],
    'kullanici': ['kullanici'],
    'plaka': ['plaka'],
    'numara': ['numara'],
}

PREMIUM_APIS = {
    'e_kurs', 'prem_ad', 'prem_adres', 'sgk_pro', 'vergi_levhasi', 'facebook',
    'diploma', 'internet', 'personel', 'interpol', 'sehit', 'arac_parca',
    'arac_borc', 'lgs_2', 'vesika', 'ehliyet', 'mhrs_randevu'
}

@app.route('/api/sorgu', methods=['POST'])
@rate_limit
def api_sorgu():
    data = request.get_json() or {}
    api_name = (data.get('api') or '').strip()
    if not api_name:
        return jsonify({'error':'api param gerekli'}), 400

    # normalize both dash/underscore variants
    key1 = api_name
    key2 = api_name.replace('-', '_')

    # premium guard
    if key1 in PREMIUM_APIS or key2 in PREMIUM_APIS:
        u = session.get('user')
        if not u or u.get('role') != 'vip':
            return jsonify({'error':'Bu sorgu sadece VIP kullanıcılar içindir.'}), 403

    # find endpoint and param spec
    endpoint = API_ENDPOINT_MAP.get(key1) or API_ENDPOINT_MAP.get(key2) or key2
    params_spec = API_PARAM_MAP.get(key1) or API_PARAM_MAP.get(key2)
    if params_spec is None:
        return jsonify({'error':'Bilinmeyen API veya mapping eksik','api':api_name}), 400

    # collect and validate params
    params = {}
    for p in params_spec:
        # accept both dashed and underscored keys
        val = None
        for variant in (p, p.replace('-', '_')):
            if variant in data:
                val = (data.get(variant) or '').strip()
                break
        if val is None:
            return jsonify({'error':f'Missing parameter: {p}'}), 400
        if p == 'tc' and not is_valid_tc(val):
            return jsonify({'error':'Geçersiz TC','param':p}), 400
        if p == 'gsm' and not is_valid_gsm(val):
            return jsonify({'error':'Geçersiz GSM','param':p}), 400
        if p in ('domain','url') and not is_safe_domain(val):
            return jsonify({'error':'Geçersiz domain/url','param':p}), 400
        if not safe_param(val):
            return jsonify({'error':'Geçersiz param','param':p}), 400
        params[p] = val

    base = 'https://kenevizbotapi.onrender.com/api/'
    return fetch_api_get(base + endpoint, params=params)

# ---------- health ----------
@app.route('/health')
def health():
    return jsonify({'ok': True, 'time': int(time.time())})

# ---------- run ----------
if __name__ == '__main__':
    logger.info("BASE_DIR=%s TEMPLATES_DIR=%s STATIC_DIR=%s", BASE_DIR, TEMPLATES_DIR, STATIC_DIR)
    if not os.path.isdir(TEMPLATES_DIR):
        logger.error("templates dizini bulunamadı: %s", TEMPLATES_DIR)
    else:
        logger.info("Templates files: %s", ', '.join(sorted(os.listdir(TEMPLATES_DIR))))
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
