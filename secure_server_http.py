#!/usr/bin/env python3
"""
Безопасный сервер синхронизации буфера обмена v3.0
Полностью переписанный для стабильной работы на DigitalOcean
"""

import json
import sqlite3
import os
import secrets
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
import bcrypt
from urllib.parse import urlparse, parse_qs

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Конфигурация
PORT = int(os.environ.get('PORT', 8080))
HOST = os.environ.get('HOST', '0.0.0.0')
TOKEN_EXPIRY_HOURS = 720  # 30 дней вместо 24 часов
DB_PATH = 'clipboard_sync.db'

class Database:
    """Упрощенная работа с базой данных"""
    
    @staticmethod
    def get_connection():
        """Создает подключение к БД с правильными настройками"""
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=NORMAL')
        conn.row_factory = sqlite3.Row
        return conn
    
    @staticmethod
    def init():
        """Инициализация базы данных"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            logger.info(f"Initializing database at: {DB_PATH}")
            
            # Таблица пользователей
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Таблица сессий
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    token TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Таблица буфера обмена
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS clipboard (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    content TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            ''')
            
            # Создаем индексы для быстрого поиска
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_clipboard_user ON clipboard(user_id, created_at DESC)')
            
            conn.commit()
            conn.close()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            raise

class Auth:
    """Аутентификация и авторизация"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Хеширует пароль с помощью bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """Проверяет пароль"""
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except:
            return False
    
    @staticmethod
    def generate_token() -> str:
        """Генерирует безопасный токен"""
        return secrets.token_urlsafe(48)
    
    @staticmethod
    def register(username: str, password: str) -> dict:
        """Регистрация нового пользователя"""
        logger.info(f"Registration attempt for username: {username}")
        
        if not username or len(username) < 3:
            return {'success': False, 'error': 'Username must be at least 3 characters'}
        
        if not password or len(password) < 6:
            return {'success': False, 'error': 'Password must be at least 6 characters'}
        
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            # Проверяем, существует ли пользователь
            cursor.execute('SELECT id FROM users WHERE username = ?', (username,))
            if cursor.fetchone():
                conn.close()
                return {'success': False, 'error': 'Username already exists'}
            
            # Создаем пользователя
            password_hash = Auth.hash_password(password)
            cursor.execute(
                'INSERT INTO users (username, password_hash) VALUES (?, ?)',
                (username, password_hash)
            )
            user_id = cursor.lastrowid
            logger.info(f"User inserted with id: {user_id}")
            
            # Создаем токен
            token = Auth.generate_token()
            expires_at = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
            logger.info(f"Token created, expires_at: {expires_at.isoformat()}")
            
            cursor.execute(
                'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)',
                (user_id, token, expires_at.isoformat())
            )
            logger.info(f"Session inserted for user_id: {user_id}, token: {token[:20]}...")
            
            conn.commit()
            
            # Проверяем, что токен действительно сохранился
            cursor.execute('SELECT token FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', (user_id,))
            saved_session = cursor.fetchone()
            if saved_session and saved_session['token'] == token:
                logger.info(f"✓ Session verified in DB for user: {username}")
            else:
                logger.error(f"✗ Session NOT found in DB after insert! user_id: {user_id}")
            
            conn.close()
            
            logger.info(f"User registered successfully: {username}")
            return {
                'success': True,
                'token': token,
                'username': username,
                'expires_in': TOKEN_EXPIRY_HOURS * 3600
            }
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def login(username: str, password: str) -> dict:
        """Аутентификация пользователя"""
        logger.info(f"Login attempt for username: {username}")
        
        try:
            conn = Database.get_connection()
            logger.info(f"Connected to database for login")
            cursor = conn.cursor()
            
            # Получаем пользователя
            logger.info(f"Querying user: {username}")
            cursor.execute(
                'SELECT id, username, password_hash FROM users WHERE username = ?',
                (username,)
            )
            user = cursor.fetchone()
            logger.info(f"User query result: {user is not None}")
            
            if not user:
                logger.warning(f"User not found: {username}")
                conn.close()
                return {'success': False, 'error': 'Invalid username or password'}
            
            logger.info(f"User found, verifying password")
            # Проверяем пароль
            if not Auth.verify_password(password, user['password_hash']):
                logger.warning(f"Password verification failed for: {username}")
                conn.close()
                return {'success': False, 'error': 'Invalid username or password'}
            
            logger.info(f"Password verified, creating token")
            # Создаем новую сессию
            token = Auth.generate_token()
            expires_at = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
            logger.info(f"Token generated: {token[:20]}..., expires_at: {expires_at.isoformat()}")
            
            cursor.execute(
                'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)',
                (user['id'], token, expires_at.isoformat())
            )
            logger.info(f"Session insert executed")
            
            conn.commit()
            logger.info(f"Session committed to database")
            conn.close()
            
            logger.info(f"User logged in successfully: {username}")
            return {
                'success': True,
                'token': token,
                'username': user['username'],
                'expires_in': TOKEN_EXPIRY_HOURS * 3600
            }
            
        except Exception as e:
            logger.error(f"Login error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {'success': False, 'error': str(e)}
    
    @staticmethod
    def validate_token(token: str) -> dict:
        """Проверяет токен и возвращает данные пользователя"""
        logger.info(f"validate_token called with token: {repr(token[:30] if token else token)}...")
        
        if not token:
            logger.warning("validate_token: token is empty or None")
            return None
        
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            logger.info(f"Connected to DB for validation, token length: {len(token)}")
            logger.debug(f"Validating token: {token[:20]}...")
            
            # Ищем активную сессию
            cursor.execute('''
                SELECT s.user_id, s.expires_at, u.username
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
            ''', (token,))
            
            session = cursor.fetchone()
            logger.info(f"Session query returned: {session is not None}")
            
            # Диагностика: если токен не найден, проверим сессии в БД
            if not session:
                cursor.execute('SELECT COUNT(*) as count FROM sessions')
                session_count = cursor.fetchone()['count']
                logger.warning(f"Token not found: {token[:20]}... (Total sessions in DB: {session_count})")
                # Дополнительная диагностика - выводим первые токены из БД
                cursor.execute('SELECT token FROM sessions LIMIT 1')
                first_token = cursor.fetchone()
                if first_token:
                    db_token = first_token['token']
                    logger.warning(f"First token in DB (first 30 chars): {db_token[:30]}")
                    logger.warning(f"Received token (first 30 chars): {token[:30]}")
                    logger.warning(f"Tokens match: {db_token == token}")
                conn.close()
                return None
            
            # Проверяем срок действия
            try:
                expires_at = datetime.fromisoformat(session['expires_at'])
                if expires_at < datetime.now():
                    logger.warning(f"Token expired for user: {session['username']}")
                    conn.close()
                    return None
            except Exception as te:
                logger.error(f"Token expiry parse error: {te}, expires_at: {session['expires_at']}")
            
            conn.close()
            logger.info(f"Token valid for user: {session['username']}")
            return {
                'user_id': session['user_id'],
                'username': session['username']
            }
            
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return None

class ClipboardManager:
    """Управление буфером обмена"""
    
    @staticmethod
    def push(user_id: int, content: str) -> bool:
        """Сохраняет содержимое буфера обмена"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            # Удаляем старые записи (оставляем последние 10)
            cursor.execute('''
                DELETE FROM clipboard 
                WHERE user_id = ? AND id NOT IN (
                    SELECT id FROM clipboard 
                    WHERE user_id = ? 
                    ORDER BY created_at DESC 
                    LIMIT 10
                )
            ''', (user_id, user_id))
            
            # Добавляем новую запись
            cursor.execute(
                'INSERT INTO clipboard (user_id, content) VALUES (?, ?)',
                (user_id, content)
            )
            
            conn.commit()
            conn.close()
            
            logger.info(f"Clipboard pushed for user_id: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Push error: {e}")
            return False
    
    @staticmethod
    def get(user_id: int, since: str = None) -> dict:
        """Получает последнее содержимое буфера обмена"""
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            if since:
                cursor.execute('''
                    SELECT id, content, created_at 
                    FROM clipboard 
                    WHERE user_id = ? AND created_at > ?
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''', (user_id, since))
            else:
                cursor.execute('''
                    SELECT id, content, created_at 
                    FROM clipboard 
                    WHERE user_id = ?
                    ORDER BY created_at DESC 
                    LIMIT 1
                ''', (user_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'success': True,
                    'content': result['content'],
                    'timestamp': result['created_at'],
                    'device_id': '',  # Совместимость с клиентом
                    'id': result['id']
                }
            else:
                return {
                    'success': True,
                    'content': None,
                    'timestamp': None
                }
                
        except Exception as e:
            logger.error(f"Get error: {e}")
            return {'success': False, 'error': str(e)}

class RequestHandler(BaseHTTPRequestHandler):
    """HTTP обработчик запросов"""
    
    def log_message(self, format, *args):
        """Переопределяем логирование"""
        pass  # Используем logger вместо print
    
    def send_json(self, data: dict, status: int = 200):
        """Отправляет JSON ответ"""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    
    def do_OPTIONS(self):
        """Обработка CORS preflight"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    
    def do_GET(self):
        """Обработка GET запросов"""
        parsed = urlparse(self.path)
        
        if parsed.path == '/':
            self.send_json({
                'status': 'ok',
                'service': 'clipboard-sync',
                'version': '3.0'
            })
            
        elif parsed.path == '/sync':
            # Получение данных буфера обмена
            params = parse_qs(parsed.query)
            token = params.get('token', [''])[0]
            since = params.get('since', [None])[0]
            
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            
            result = ClipboardManager.get(user['user_id'], since)
            self.send_json(result)
            
        else:
            self.send_json({'error': 'Not found'}, 404)
    
    def do_POST(self):
        """Обработка POST запросов"""
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        logger.info(f"POST {self.path} - Content-Length: {content_length}")
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            logger.info(f"Received data: {data}")
        except Exception as e:
            logger.error(f"JSON parse error: {e}, raw data: {post_data[:200]}")
            self.send_json({'error': 'Invalid JSON'}, 400)
            return
        
        if self.path == '/register':
            result = Auth.register(
                data.get('username', ''),
                data.get('password', '')
            )
            self.send_json(result, 200 if result['success'] else 400)
            
        elif self.path == '/auth':
            result = Auth.login(
                data.get('username', ''),
                data.get('password', '')
            )
            self.send_json(result, 200 if result['success'] else 400)
            
        elif self.path == '/push':
            token = data.get('token', '')
            content = data.get('content', '')
            
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            
            success = ClipboardManager.push(user['user_id'], content)
            self.send_json({'success': success})
            
        else:
            logger.warning(f"Unknown endpoint: {self.path}")
            self.send_json({'error': 'Endpoint not found'}, 404)

def main():
    """Запуск сервера"""
    # Инициализация базы данных с повторными попытками
    max_retries = 3
    for attempt in range(max_retries):
        try:
            Database.init()
            logger.info("Database initialization successful")
            break
        except Exception as e:
            logger.error(f"Database init attempt {attempt + 1} failed: {e}")
            if attempt < max_retries - 1:
                import time
                time.sleep(1)
            else:
                logger.error("Failed to initialize database after all retries")
                raise
    
    # Создание и запуск HTTP сервера
    server = HTTPServer((HOST, PORT), RequestHandler)
    
    logger.info(f"Server starting on {HOST}:{PORT}")
    logger.info(f"Token expiry: {TOKEN_EXPIRY_HOURS} hours")
    logger.info("Server is ready!")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == '__main__':
    main()
