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
    level=logging.DEBUG,
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
        import os
        abs_path = os.path.abspath(DB_PATH)
        logger.debug(f"Connecting to database at: {abs_path}")
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.execute('PRAGMA journal_mode=WAL')
        conn.execute('PRAGMA synchronous=FULL')  # FULL instead of NORMAL to force disk write
        conn.execute('PRAGMA busy_timeout=30000')
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
            token_hash = hash(token)  # Для отслеживания
            logger.info(f"Token generated, length: {len(token)}, first 20: {token[:20]}, hash: {token_hash}")
            
            expires_at = datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)
            logger.info(f"Token expires_at: {expires_at.isoformat()}")
            
            cursor.execute(
                'INSERT INTO sessions (user_id, token, expires_at) VALUES (?, ?, ?)',
                (user_id, token, expires_at.isoformat())
            )
            logger.info(f"Session inserted, lastrowid: {cursor.lastrowid}")
            
            conn.commit()
            logger.info(f"Database commit successful")
            
            # Force WAL checkpoint to ensure data is written to disk
            conn.execute('PRAGMA wal_checkpoint(RESTART)')
            logger.debug(f"WAL checkpoint forced")
            
            # Проверяем, что токен действительно сохранился - новое подключение
            verify_conn = Database.get_connection()
            verify_cursor = verify_conn.cursor()
            verify_cursor.execute('SELECT token, expires_at FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', (user_id,))
            saved_session = verify_cursor.fetchone()
            
            if saved_session:
                saved_token = saved_session['token']
                saved_hash = hash(saved_token)
                logger.info(f"Token retrieved from DB, first 20: {saved_token[:20]}, hash: {saved_hash}")
                logger.info(f"Token match: {saved_token == token} (stored == created)")
                logger.info(f"Token length stored: {len(saved_token)}")
                logger.info(f"Expires_at in DB: {saved_session['expires_at']}")
            else:
                logger.error(f"✗ Session NOT found in DB after insert!")
            verify_conn.close()
            conn.close()
            
            logger.info(f"✓ User registered: {username}, returning token: {token[:20]}...")
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
        token_hash = hash(token) if token else None
        logger.info(f"validate_token: token length={len(token) if token else 0}, hash={token_hash}, first 20: {token[:20] if token else 'EMPTY'}")
        
        if not token:
            logger.warning("validate_token: token is empty or None")
            return None
        
        try:
            conn = Database.get_connection()
            cursor = conn.cursor()
            
            logger.debug(f"Querying sessions table...")
            
            # Сначала проверим сессии вообще
            cursor.execute('SELECT COUNT(*) as total FROM sessions')
            total_sessions = cursor.fetchone()['total']
            logger.debug(f"Total sessions in DB: {total_sessions}")
            
            # Проверяем первый токен
            if total_sessions > 0:
                cursor.execute('SELECT token FROM sessions LIMIT 1')
                first = cursor.fetchone()
                if first:
                    first_token = first['token']
                    first_hash = hash(first_token)
                    logger.debug(f"First token in DB: first 20: {first_token[:20]}, hash: {first_hash}, length: {len(first_token)}")
            
            # Ищем активную сессию с нашим токеном
            logger.debug(f"Searching for exact token match...")
            cursor.execute('''
                SELECT s.id, s.user_id, s.expires_at, u.username
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.token = ?
            ''', (token,))
            
            session = cursor.fetchone()
            logger.info(f"Session query result: {session is not None}")
            
            if not session:
                # Дополнительная диагностика
                logger.warning(f"Token NOT found in DB: {token[:20]}... (hash: {token_hash})")
                
                # Показываем все токены из БД для сравнения
                cursor.execute('SELECT id, token, expires_at FROM sessions ORDER BY created_at DESC LIMIT 3')
                recent_tokens = cursor.fetchall()
                logger.warning(f"Last 3 tokens in DB:")
                for idx, row in enumerate(recent_tokens):
                    t = row['token']
                    t_hash = hash(t)
                    logger.warning(f"  [{idx}] first 20: {t[:20]}, hash: {t_hash}, length: {len(t)}, match: {t == token}")
                
                conn.close()
                return None
            
            # Проверяем срок действия
            expires_at = session['expires_at']
            logger.debug(f"Token expires_at: {expires_at}")
            
            try:
                exp_dt = datetime.fromisoformat(expires_at)
                now = datetime.now()
                time_remaining = (exp_dt - now).total_seconds()
                logger.info(f"Token expiry check: expires={expires_at}, now={now.isoformat()}, remaining seconds: {time_remaining}")
                
                if exp_dt < now:
                    logger.warning(f"Token EXPIRED for user: {session['username']}")
                    conn.close()
                    return None
            except Exception as te:
                logger.error(f"Token expiry parse error: {te}")
                logger.error(f"Expires_at value: {repr(expires_at)}")
            
            logger.info(f"✓ Token VALID for user: {session['username']}, remaining: {time_remaining}s")
            conn.close()
            
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
