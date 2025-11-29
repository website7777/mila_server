#!/usr/bin/env python3
"""
Безопасная версия сервера синхронизации буфера обмена для публичного использования
Полная изоляция пользователей и улучшенная безопасность
"""

import asyncio
import websockets
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

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Переменные окружения
PORT = int(os.environ.get('PORT', 8765))
HOST = os.environ.get('HOST', '0.0.0.0')
SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_urlsafe(64))
TOKEN_EXPIRY_HOURS = int(os.environ.get('TOKEN_EXPIRY_HOURS', 24))
MAX_LOGIN_ATTEMPTS = int(os.environ.get('MAX_LOGIN_ATTEMPTS', 5))
LOGIN_COOLDOWN_MINUTES = int(os.environ.get('LOGIN_COOLDOWN_MINUTES', 15))

# Глобальные переменные
user_connections = {}  # username -> {token: websocket}
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
            email TEXT UNIQUE,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            login_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP
        )
    ''')
    
    # Сессии с истечением срока
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
    
    # Изолированные данные буфера для каждого пользователя
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
    # Обрезаем пароль до 72 байт для совместимости с bcrypt
    password_combined = (password + salt)
    password_bytes = password_combined.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, salt: str, hash_: str) -> bool:
    """Проверка пароля"""
    try:
        # Обрезаем пароль до 72 байт для совместимости с bcrypt  
        password_combined = (password + salt)
        password_bytes = password_combined.encode('utf-8')
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
            login_attempts[ip_address] = {'attempts': 0, 'last_attempt': datetime.now()}
    
    return False

def record_login_attempt(ip_address: str, success: bool):
    """Запись попытки входа"""
    if ip_address not in login_attempts:
        login_attempts[ip_address] = {'attempts': 0, 'last_attempt': datetime.now()}
    
    if success:
        login_attempts[ip_address] = {'attempts': 0, 'last_attempt': datetime.now()}
    else:
        login_attempts[ip_address]['attempts'] += 1
        login_attempts[ip_address]['last_attempt'] = datetime.now()

def log_activity(user_id: int, action: str, ip_address: str = None, user_agent: str = None, details: str = None):
    """Логирование активности пользователя"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO activity_logs (user_id, action, ip_address, user_agent, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, action, ip_address, user_agent, details))
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error(f"Error logging activity: {e}")

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
        if not verify_password(password, salt, password_hash):
            # Увеличение счетчика неудачных попыток
            new_attempts = (login_attempts_db or 0) + 1
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
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.id, u.username, s.expires_at
            FROM users u
            JOIN user_sessions s ON u.id = s.user_id
            WHERE s.token = ? AND s.is_active = 1
        ''', (token,))
        
        result = cursor.fetchone()
        if not result:
            conn.close()
            return None
        
        user_id, username, expires_at_str = result
        expires_at = datetime.fromisoformat(expires_at_str)
        
        # Проверка истечения токена
        if datetime.now() > expires_at:
            cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE token = ?', (token,))
            conn.commit()
            conn.close()
            return None
        
        conn.close()
        return {'user_id': user_id, 'username': username}
        
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return None

def store_clipboard_data(user_id: int, content: str, device_id: str = None):
    """Сохранение данных буфера для пользователя"""
    try:
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Проверяем, не дублируется ли контент
        cursor.execute('''
            SELECT id FROM clipboard_data 
            WHERE user_id = ? AND content_hash = ?
            ORDER BY created_at DESC LIMIT 1
        ''', (user_id, content_hash))
        
        if not cursor.fetchone():
            cursor.execute('''
                INSERT INTO clipboard_data (user_id, content, content_hash, device_id)
                VALUES (?, ?, ?, ?)
            ''', (user_id, content, content_hash, device_id))
            
            # Ограничиваем историю (последние 100 записей)
            cursor.execute('''
                DELETE FROM clipboard_data 
                WHERE user_id = ? AND id NOT IN (
                    SELECT id FROM clipboard_data 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC LIMIT 100
                )
            ''', (user_id, user_id))
            
            conn.commit()
        
        conn.close()
    except Exception as e:
        logger.error(f"Error storing clipboard data: {e}")

async def handle_websocket_connection(websocket, path):
    """Обработка WebSocket подключения с изоляцией пользователей"""
    user_data = None
    token = None
    
    try:
        # Получение токена из первого сообщения
        auth_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        auth_data = json.loads(auth_message)
        
        if auth_data.get('type') != 'auth':
            await websocket.close(code=4000, reason='Authentication required')
            return
            
        token = auth_data.get('token', '').strip()
        if not token:
            await websocket.close(code=4001, reason='Token required')
            return
            
        user_data = get_user_by_token(token)
        if not user_data:
            await websocket.close(code=4002, reason='Invalid or expired token')
            return
        
        username = user_data['username']
        user_id = user_data['user_id']
        
        # Регистрируем пользователя в изолированном пространстве
        if username not in user_connections:
            user_connections[username] = {}
        user_connections[username][token] = websocket
        
        logger.info(f"User {username} connected for sync")
        log_activity(user_id, "WEBSOCKET_CONNECTED")
        
        # Подтверждение аутентификации
        await websocket.send(json.dumps({
            'type': 'auth_success',
            'message': 'Connected to secure clipboard sync',
            'username': username
        }))
        
        # Обработка сообщений синхронизации
        async for message in websocket:
            try:
                data = json.loads(message)
                if data.get('type') == 'clipboard_sync':
                    content = data.get('content', '')
                    device_id = data.get('device_id', '')
                    
                    # Сохраняем в базу
                    store_clipboard_data(user_id, content, device_id)
                    
                    # Отправляем ТОЛЬКО другим устройствам ЭТОГО ЖЕ пользователя
                    if username in user_connections:
                        for other_token, other_ws in user_connections[username].items():
                            if other_token != token and other_ws != websocket:
                                try:
                                    await other_ws.send(json.dumps({
                                        'type': 'clipboard_sync',
                                        'content': content,
                                        'timestamp': time.time(),
                                        'device_id': device_id
                                    }))
                                except:
                                    # Удаляем отключенные соединения
                                    if other_token in user_connections[username]:
                                        del user_connections[username][other_token]
                    
                    log_activity(user_id, "CLIPBOARD_SYNC", details=f"Content length: {len(content)}")
                                    
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from {username}")
            except Exception as e:
                logger.error(f"Message handling error for {username}: {e}")
                break
                
    except asyncio.TimeoutError:
        await websocket.close(code=4003, reason='Authentication timeout')
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        # Очистка при отключении
        if user_data and token:
            username = user_data['username']
            if username in user_connections and token in user_connections[username]:
                del user_connections[username][token]
                if not user_connections[username]:
                    del user_connections[username]
            log_activity(user_data['user_id'], "WEBSOCKET_DISCONNECTED")
            logger.info(f"User {username} disconnected")

# HTTP сервер для аутентификации
class SecureAuthHandler(BaseHTTPRequestHandler):
    def get_client_ip(self):
        """Получение IP клиента"""
        return self.client_address[0]
    
    def do_OPTIONS(self):
        """Обработка CORS preflight запросов"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def do_GET(self):
        """Обработка GET запросов"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        
        html_content = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Secure Clipboard Sync Server</title>
            <meta charset="utf-8">
        </head>
        <body>
            <h1>🔒 Secure Clipboard Sync Server</h1>
            <p>✅ Server is running with enhanced security!</p>
            <p>🛡️ Features:</p>
            <ul>
                <li>User isolation</li>
                <li>Token expiration</li>
                <li>Rate limiting</li>
                <li>Activity logging</li>
                <li>Secure password hashing</li>
            </ul>
            <p>🚀 Use your desktop client to connect securely.</p>
        </body>
        </html>
        """
        self.wfile.write(html_content.encode('utf-8'))
    
    def do_POST(self):
        """Обработка POST запросов"""
        client_ip = self.get_client_ip()
        
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length == 0:
                self.send_error_response(400, 'No data provided')
                return
                
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            path = self.path
            username = data.get('username', 'unknown')
            logger.info(f"Received {path} request from {client_ip} for user: {username}")
            
            if path == '/register':
                result = register_user_secure(
                    data.get('username', ''),
                    data.get('password', ''),
                    data.get('email', ''),
                    client_ip
                )
            elif path == '/auth':
                result = authenticate_user_secure(
                    data.get('username', ''),
                    data.get('password', ''),
                    data.get('device_id', ''),
                    data.get('device_name', ''),
                    client_ip
                )
            else:
                result = {'success': False, 'error': 'Unknown endpoint'}
            
            logger.info(f"Result for {path} from {client_ip}: {result.get('success', False)}")
            
            self.send_json_response(result)
            
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON from {client_ip}")
            self.send_error_response(400, 'Invalid JSON')
        except Exception as e:
            logger.error(f"POST request error from {client_ip}: {e}")
            self.send_error_response(500, 'Server error')
    
    def send_json_response(self, data):
        """Отправка JSON ответа"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def send_error_response(self, status_code, error_message):
        """Отправка ошибки"""
        self.send_response(status_code)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps({'success': False, 'error': error_message}).encode())
    
    def log_message(self, format, *args):
        """Отключаем стандартное логирование HTTP сервера"""
        pass

def cleanup_expired_sessions():
    """Очистка истекших сессий"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('UPDATE user_sessions SET is_active = 0 WHERE expires_at < ?', 
                      (datetime.now().isoformat(),))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} expired sessions")
    except Exception as e:
        logger.error(f"Session cleanup error: {e}")

async def cleanup_task():
    """Периодическая очистка"""
    while server_running:
        await asyncio.sleep(3600)  # Каждый час
        cleanup_expired_sessions()

def signal_handler(signum, frame):
    """Обработчик сигналов для корректного завершения"""
    global server_running
    logger.info(f"Received signal {signum}, shutting down...")
    server_running = False

async def main():
    """Запуск безопасного сервера"""
    global server_running
    
    # Регистрация обработчиков сигналов
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Инициализация базы данных
    init_database()
    
    # Запуск задачи очистки
    cleanup_task_handle = asyncio.create_task(cleanup_task())
    
    # В облачной среде запускаем HTTP + WebSocket на одном порту
    if 'PORT' in os.environ:
        logger.info(f"Starting secure server in cloud environment on port {PORT}")
        
        # Запускаем HTTP сервер в отдельном потоке
        http_server = HTTPServer((HOST, PORT), SecureAuthHandler)
        http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        http_thread.start()
        
        logger.info(f"Secure HTTP API server running on {HOST}:{PORT}")
        logger.info(f"Secure WebSocket server starting on {HOST}:{PORT}")
        
        # WebSocket сервер на том же порту (но платформа не поддерживает это)
        # Поэтому используем альтернативный подход через HTTP upgrade
        try:
            # Пытаемся запустить WebSocket сервер на следующем порту
            ws_port = PORT + 1
            async with websockets.serve(handle_websocket_connection, HOST, ws_port):
                logger.info(f"Secure WebSocket server running on {HOST}:{ws_port}")
                logger.info("Enhanced security features enabled")
                
                while server_running:
                    await asyncio.sleep(1)
        except Exception as e:
            logger.error(f"WebSocket server error: {e}")
            # Если WebSocket сервер не запускается, работаем только с HTTP
            logger.info("Running in HTTP-only mode")
            while server_running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            cleanup_task_handle.cancel()
    else:
        # Локальная среда - HTTP + WebSocket
        logger.info("Starting secure server in local environment")
        
        # HTTP сервер для аутентификации
        http_server = HTTPServer((HOST, 8080), SecureAuthHandler)
        http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
        http_thread.start()
        
        logger.info(f"Secure HTTP server running on {HOST}:8080")
        logger.info(f"Secure WebSocket server starting on {HOST}:{PORT}")
        
        # WebSocket сервер для синхронизации
        try:
            async with websockets.serve(handle_websocket_connection, HOST, PORT):
                logger.info(f"Secure clipboard sync server running on {HOST}:{PORT}")
                logger.info("Enhanced security features enabled")
                
                while server_running:
                    await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            cleanup_task_handle.cancel()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Secure server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
