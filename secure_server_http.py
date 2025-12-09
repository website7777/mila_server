#!/usr/bin/env python3
"""
HTTP-only версия безопасного сервера синхронизации буфера обмена
Работает без WebSocket для совместимости с облачными платформами
"""

import json
import hashlib
import time
import sqlite3
import os
import secrets
import logging
import threading
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
import uuid
import bcrypt
from urllib.parse import urlparse, parse_qs

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Переменные окружения
PORT = int(os.environ.get('PORT', 8080))
HOST = os.environ.get('HOST', '0.0.0.0')
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_urlsafe(64))
TOKEN_EXPIRY_HOURS = int(os.environ.get('TOKEN_EXPIRY_HOURS', 24))
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
LOGIN_COOLDOWN_MINUTES = int(os.environ.get('LOGIN_COOLDOWN_MINUTES', 15))

# Глобальные переменные
login_attempts = {}  # IP -> {attempts: int, last_attempt: datetime}
db_path = 'secure_clipboard_sync.db'
server_running = True

def init_database():
    """Инициализация безопасной базы данных"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Пользователи с улучшенной безопасностью
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    ''')
    
    # Сессии пользователей
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            device_id TEXT,
            device_name TEXT,
            ip_address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    # Миграция: приводим старые записи к is_active=1, если поле было NULL
    cursor.execute('''
        UPDATE user_sessions
        SET is_active = 1
        WHERE is_active IS NULL
    ''')
    conn.commit()
    
    # Логи активности
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            details TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Буфер обмена для каждого пользователя
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS clipboard_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            content_hash TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            device_id TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("Secure database initialized")

def generate_salt() -> str:
    """Генерация соли для пароля"""
    return secrets.token_hex(32)

def hash_password(password: str, salt: str) -> str:
    """Безопасное хеширование пароля с солью"""
    # bcrypt уже включает соль, поэтому используем простое хеширование
    # Обрезаем пароль до 72 байт для совместимости с bcrypt
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, salt: str, hash_: str) -> bool:
    """Проверка пароля"""
    try:
        # bcrypt уже включает соль в хеш, поэтому используем простую проверку  
        password_bytes = password.encode('utf-8')
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
        return bcrypt.checkpw(password_bytes, hash_.encode('utf-8'))
    except Exception as e:
        logger.error(f"Password verification error: {e}")
        return False

def generate_secure_token() -> str:
    """Генерация безопасного токена"""
    return secrets.token_urlsafe(48)

def is_ip_blocked(ip_address: str) -> bool:
    """Проверка блокировки IP"""
    if ip_address not in login_attempts:
        return False
    
    attempts_data = login_attempts[ip_address]
    if attempts_data['attempts'] >= MAX_LOGIN_ATTEMPTS:
        cooldown_until = attempts_data['last_attempt'] + timedelta(minutes=LOGIN_COOLDOWN_MINUTES)
        if datetime.now() < cooldown_until:
            return True
        else:
            # Сброс попыток после окончания блокировки
            del login_attempts[ip_address]
    
    return False

def record_login_attempt(ip_address: str, success: bool):
    """Записывает попытку входа"""
    if not ip_address:
        return
        
    if success:
        # Успешный вход - сброс счетчика
        if ip_address in login_attempts:
            del login_attempts[ip_address]
    else:
        # Неуспешная попытка
        if ip_address not in login_attempts:
            login_attempts[ip_address] = {'attempts': 0, 'last_attempt': datetime.now()}
        
        login_attempts[ip_address]['attempts'] += 1
        login_attempts[ip_address]['last_attempt'] = datetime.now()

def log_activity(user_id: int, action: str, ip_address: str = None, details: str = None):
    """Логирование активности пользователя"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, ip_address, details)
            VALUES (?, ?, ?, ?)
        ''', (user_id, action, ip_address, details))
        
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Activity logging error: {e}")

def register_user_secure(username: str, password: str, email: str = "", ip_address: str = None) -> dict:
    """Безопасная регистрация пользователя"""
    try:
        # Проверка блокировки IP
        if is_ip_blocked(ip_address):
            return {'success': False, 'error': 'IP временно заблокирован из-за множественных неудачных попыток'}
        
        # Валидация данных
        if not username or len(username) < 3:
            return {'success': False, 'error': 'Имя пользователя должно быть не менее 3 символов'}
        
        if not password or len(password) < 6:
            return {'success': False, 'error': 'Пароль должен быть не менее 6 символов'}
            
        if len(password) > 50:  # Ограничиваем длину пароля
            return {'success': False, 'error': 'Пароль слишком длинный. Максимум 50 символов.'}
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Проверка существования пользователя
        cursor.execute("SELECT id FROM users WHERE username = ? OR email = ?", (username, email))
        if cursor.fetchone():
            conn.close()
            record_login_attempt(ip_address, False)
            return {'success': False, 'error': 'Пользователь с таким именем или email уже существует'}
        
        # Создание пользователя
        salt = generate_salt()
        password_hash = hash_password(password, salt)
        
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, salt)
            VALUES (?, ?, ?, ?)
        ''', (username, email, password_hash, salt))
        
        user_id = cursor.lastrowid
        
        # Создание первой сессии
        token = generate_secure_token()
        expires_at = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
        
        cursor.execute('''
            INSERT INTO user_sessions (user_id, token, ip_address, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (user_id, token, ip_address, expires_at))
        
        conn.commit()
        conn.close()
        
        # Логирование
        log_activity(user_id, "USER_REGISTERED", ip_address)
        record_login_attempt(ip_address, True)
        
        logger.info(f"New user registered: {username}")
        return {
            'success': True, 
            'token': token, 
            'expires_in': TOKEN_EXPIRY_HOURS * 3600,
            'username': username
        }
        
    except Exception as e:
        logger.error(f"Registration error for {username}: {e}")
        # Более детальная обработка ошибок
        error_message = str(e)
        if "password cannot be longer than 72 bytes" in error_message:
            return {'success': False, 'error': 'Пароль слишком длинный. Максимум 50 символов.'}
        elif "UNIQUE constraint failed" in error_message:
            return {'success': False, 'error': 'Пользователь с таким именем уже существует'}
        else:
            return {'success': False, 'error': f'Ошибка регистрации: {error_message}'}

def authenticate_user_secure(username: str, password: str, device_id: str = "", device_name: str = "", ip_address: str = None) -> dict:
    """Безопасная аутентификация пользователя"""
    try:
        # Проверка блокировки IP
        if is_ip_blocked(ip_address):
            return {'success': False, 'error': 'IP временно заблокирован из-за множественных неудачных попыток'}
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Получение данных пользователя
        cursor.execute('''
            SELECT id, username, password_hash, salt, is_active, login_attempts, locked_until
            FROM users WHERE username = ?
        ''', (username,))
        
        user_data = cursor.fetchone()
        if not user_data:
            conn.close()
            record_login_attempt(ip_address, False)
            return {'success': False, 'error': 'Неверное имя пользователя или пароль'}
        
        user_id, db_username, password_hash, salt, is_active, login_attempts_db, locked_until = user_data
        
        # Проверка активности аккаунта
        if not is_active:
            conn.close()
            return {'success': False, 'error': 'Аккаунт деактивирован'}
        
        # Проверка блокировки аккаунта
        if locked_until:
            try:
                locked_datetime = datetime.fromisoformat(locked_until)
                if locked_datetime > datetime.now():
                    conn.close()
                    return {'success': False, 'error': 'Аккаунт временно заблокирован'}
            except:
                pass  # Игнорируем ошибки парсинга даты
        
        # Проверка пароля
        logger.info(f"Verifying password for user {username}")
        password_valid = verify_password(password, salt, password_hash)
        logger.info(f"Password verification result for {username}: {password_valid}")
        
        if not password_valid:
            # Увеличение счетчика неудачных попыток
            new_attempts = (login_attempts_db or 0) + 1
            logger.warning(f"Failed login attempt #{new_attempts} for user {username}")
            cursor.execute('''
                UPDATE users SET login_attempts = ?
                WHERE id = ?
            ''', (new_attempts, user_id))
            
            # Блокировка после 5 неудачных попыток
            if new_attempts >= 5:
                locked_until = datetime.now() + timedelta(minutes=30)
                cursor.execute('''
                    UPDATE users SET locked_until = ?
                    WHERE id = ?
                ''', (locked_until.isoformat(), user_id))
                log_activity(user_id, "ACCOUNT_LOCKED", ip_address)
            
            conn.commit()
            conn.close()
            record_login_attempt(ip_address, False)
            log_activity(user_id, "LOGIN_FAILED", ip_address)
            return {'success': False, 'error': 'Неверное имя пользователя или пароль'}
        
        # Сброс счетчика попыток при успешном входе
        cursor.execute('''
            UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (user_id,))
        
        # Создание новой сессии
        token = generate_secure_token()
        expires_at = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
        
        cursor.execute('''
            INSERT INTO user_sessions (user_id, token, device_id, device_name, ip_address, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, token, device_id, device_name, ip_address, expires_at))
        
        conn.commit()
        conn.close()
        
        # Логирование
        log_activity(user_id, "LOGIN_SUCCESS", ip_address, details=f"Device: {device_name}")
        record_login_attempt(ip_address, True)
        
        logger.info(f"User authenticated: {username}")
        return {
            'success': True, 
            'token': token, 
            'expires_in': TOKEN_EXPIRY_HOURS * 3600,
            'username': username
        }
        
    except Exception as e:
        logger.error(f"Authentication error for {username}: {e}")
        # Более детальная обработка ошибок
        error_message = str(e)
        if "password cannot be longer than 72 bytes" in error_message:
            return {'success': False, 'error': 'Пароль слишком длинный'}
        else:
            return {'success': False, 'error': f'Ошибка аутентификации: {error_message}'}

def get_user_by_token(token: str) -> dict:
    """Получение пользователя по токену с проверкой истечения"""
    try:
        token = (token or '').strip()
        logger.info(f"Validating token: {token[:10]}...{token[-10:] if len(token) > 20 else token}")
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.id, u.username, s.expires_at, s.is_active
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.token = ? AND (s.is_active = 1 OR s.is_active IS NULL)
        ''', (token,))
        
        result = cursor.fetchone()
        
        if not result:
            logger.warning(f"Token not found in database: {token[:10]}...")
            conn.close()
            return None
            
        user_id, username, expires_at, is_active = result
        logger.info(f"Found token for user {username}, active: {is_active}, expires: {expires_at}")
        
        if not is_active:
            logger.warning(f"Token is inactive for user {username}")
            conn.close()
            return None
        
        # Проверка истечения токена
        try:
            expires_dt = datetime.fromisoformat(expires_at)
        except Exception as parse_err:
            # Если дата в неожиданном формате, не отбрасываем токен вслепую
            logger.error(f"Failed to parse expires_at for token {token[:10]}...: {parse_err}; raw={expires_at}")
            expires_dt = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)

        now = datetime.now()
        # Разрешаем небольшой дрейф часов (±5 минут) чтобы не инвалидировать токены из‑за рассинхронизации
        if expires_dt + timedelta(minutes=5) <= now:
            logger.warning(f"Token expired for user {username}: {expires_dt} <= {now}")
            # Деактивируем истёкший токен
            cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE token = ?', (token,))
            conn.commit()
            conn.close()
            return None
        
        logger.info(f"Token valid for user {username}")
        conn.close()
        return {'user_id': user_id, 'username': username}
        
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return None

def store_clipboard_data(user_id: int, content: str, device_id: str = ""):
    """Сохранение данных буфера обмена"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        # Удаляем старые записи этого пользователя (оставляем только последнюю)
        cursor.execute('''
            DELETE FROM clipboard_data 
            WHERE user_id = ? AND created_at < (
                SELECT MAX(created_at) FROM clipboard_data WHERE user_id = ?
            )
        ''', (user_id, user_id))
        
        cursor.execute('''
            INSERT INTO clipboard_data (user_id, content, content_hash, device_id)
            VALUES (?, ?, ?, ?)
        ''', (user_id, content, content_hash, device_id))
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Error storing clipboard data: {e}")

def get_clipboard_data(user_id: int, since_timestamp: str = None) -> dict:
    """Получение последних данных буфера обмена для пользователя"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        if since_timestamp:
            cursor.execute('''
                SELECT content, device_id, created_at FROM clipboard_data 
                WHERE user_id = ? AND created_at > ?
                ORDER BY created_at DESC LIMIT 1
            ''', (user_id, since_timestamp))
        else:
            cursor.execute('''
                SELECT content, device_id, created_at FROM clipboard_data 
                WHERE user_id = ?
                ORDER BY created_at DESC LIMIT 1
            ''', (user_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if result:
            content, device_id, created_at = result
            return {
                'success': True,
                'content': content,
                'device_id': device_id,
                'timestamp': created_at
            }
        else:
            return {'success': True, 'content': None}
            
    except Exception as e:
        logger.error(f"Error retrieving clipboard data: {e}")
        return {'success': False, 'error': str(e)}

class SecureHTTPHandler(BaseHTTPRequestHandler):
    def get_client_ip(self):
        """Получение IP клиента"""
        return self.client_address[0]
    
    def do_OPTIONS(self):
        """Обработка CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def do_GET(self):
        """Обработка GET запросов"""        
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            response = {'status': 'ok', 'service': 'secure-clipboard-sync', 'version': '2.1'}
            self.wfile.write(json.dumps(response).encode())
        elif self.path.startswith('/sync'):
            # Получение данных буфера обмена (polling)
            self.handle_sync_request()
        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({'error': 'Not found'}).encode())
    
    def do_POST(self):
        """Обработка POST запросов"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        client_ip = self.get_client_ip()
        
        try:
            data = json.loads(post_data.decode('utf-8'))
        except:
            self.send_error_response({'error': 'Invalid JSON'})
            return
        
        logger.info(f"Received {self.path} request from {client_ip}")
        
        if self.path == '/register':
            self.handle_register(data, client_ip)
        elif self.path == '/auth':
            self.handle_auth(data, client_ip)
        elif self.path == '/push':
            self.handle_push(data, client_ip)
        else:
            self.send_error_response({'error': 'Endpoint not found'})
    
    def handle_register(self, data: dict, client_ip: str):
        """Обработка регистрации"""
        username = data.get('username', '')
        password = data.get('password', '')
        email = data.get('email', '')
        
        result = register_user_secure(username, password, email, client_ip)
        logger.info(f"Result for /register from {client_ip}: {result.get('success')}")
        
        self.send_json_response(result)
    
    def handle_auth(self, data: dict, client_ip: str):
        """Обработка аутентификации"""
        username = data.get('username', '')
        password = data.get('password', '')
        device_id = data.get('device_id', '')
        device_name = data.get('device_name', '')
        
        result = authenticate_user_secure(username, password, device_id, device_name, client_ip)
        logger.info(f"Result for /auth from {client_ip}: {result.get('success')}")
        
        self.send_json_response(result)
    
    def handle_push(self, data: dict, client_ip: str):
        """Обработка отправки данных буфера обмена"""
        token = data.get('token', '')
        content = data.get('content', '')
        device_id = data.get('device_id', '')
        
        logger.info(f"Push request from {client_ip} with token {token[:10]}...")
        
        user_data = get_user_by_token(token)
        if not user_data:
            logger.warning(f"Push failed - invalid token from {client_ip}")
            self.send_error_response({'error': 'Invalid or expired token'})
            return
        
        logger.info(f"Push from user {user_data['username']}")
        store_clipboard_data(user_data['user_id'], content, device_id)
        log_activity(user_data['user_id'], "CLIPBOARD_PUSH", client_ip)
        
        self.send_json_response({'success': True})
    
    def handle_sync_request(self):
        """Обработка запроса на получение данных буфера обмена"""
        # Парсинг параметров из URL
        from urllib.parse import urlparse, parse_qs
        parsed_url = urlparse(self.path)
        params = parse_qs(parsed_url.query)
        
        token = params.get('token', [''])[0]
        since = params.get('since', [None])[0]
        
        user_data = get_user_by_token(token)
        if not user_data:
            self.send_error_response({'error': 'Invalid or expired token'})
            return
        
        result = get_clipboard_data(user_data['user_id'], since)
        self.send_json_response(result)
    
    def send_json_response(self, data: dict):
        """Отправка JSON ответа"""
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def send_error_response(self, error_data: dict):
        """Отправка ошибки"""
        self.send_response(400)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(error_data).encode())

def cleanup_expired_sessions():
    """Очистка истёкших сессий"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Деактивируем истёкшие сессии
        cursor.execute('''
            UPDATE user_sessions 
            SET is_active = 0 
            WHERE expires_at <= datetime('now') AND is_active = 1
        ''')
        
        # Удаляем старые записи буфера (старше 7 дней)
        cursor.execute('''
            DELETE FROM clipboard_data 
            WHERE created_at <= datetime('now', '-7 days')
        ''')
        
        # Удаляем старые логи (старше 30 дней)
        cursor.execute('''
            DELETE FROM activity_logs 
            WHERE timestamp <= datetime('now', '-30 days')
        ''')
        
        conn.commit()
        conn.close()
        
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")

def signal_handler(signum, frame):
    """Обработчик сигналов для корректного завершения"""
    global server_running
    logger.info(f"Received signal {signum}, shutting down...")
    server_running = False

def main():
    """Запуск HTTP-only сервера"""
    global server_running
    
    # Регистрация обработчиков сигналов
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Инициализация базы данных
    init_database()
    
    logger.info(f"Starting secure HTTP-only server on {HOST}:{PORT}")
    
    # Запуск HTTP сервера
    http_server = HTTPServer((HOST, PORT), SecureHTTPHandler)
    
    logger.info(f"Secure HTTP server running on {HOST}:{PORT}")
    logger.info("Enhanced security features enabled")
    logger.info("HTTP polling mode for cloud compatibility")
    
    try:
        http_server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        # Очистка при завершении
        cleanup_expired_sessions()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Secure server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
