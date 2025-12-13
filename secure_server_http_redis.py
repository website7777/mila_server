#!/usr/bin/env python3
"""
Безопасный сервер синхронизации буфера обмена v3.0 (Valkey/Redis)
Работает с DigitalOcean Managed Valkey/Redis
"""

import json
import os
import secrets
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timedelta
import bcrypt
from urllib.parse import urlparse, parse_qs
import redis

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
TOKEN_EXPIRY_HOURS = 720  # 30 дней
REDIS_URL = os.environ.get('REDIS_URL')
REDIS_HOST = os.environ.get('REDIS_HOST')
REDIS_PORT = os.environ.get('REDIS_PORT')
REDIS_USERNAME = os.environ.get('REDIS_USERNAME')
REDIS_PASSWORD = os.environ.get('REDIS_PASSWORD')

class RedisDB:
    """Работа с Valkey/Redis"""
    @staticmethod
    def get_connection():
        if REDIS_URL:
            pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True)
            return redis.Redis(connection_pool=pool)
        else:
            return redis.Redis(
                host=REDIS_HOST,
                port=int(REDIS_PORT or 6379),
                username=REDIS_USERNAME,
                password=REDIS_PASSWORD,
                decode_responses=True
            )

class Auth:
    @staticmethod
    def hash_password(password: str) -> str:
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        try:
            return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
        except:
            return False

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(48)

    @staticmethod
    def register(username: str, password: str) -> dict:
        logger.info(f"Registration attempt for username: {username}")
        if not username or len(username) < 3:
            return {'success': False, 'error': 'Username must be at least 3 characters'}
        if not password or len(password) < 6:
            return {'success': False, 'error': 'Password must be at least 6 characters'}
        r = RedisDB.get_connection()
        if r.hexists('users', username):
            return {'success': False, 'error': 'Username already exists'}
        password_hash = Auth.hash_password(password)
        user_id = r.incr('user_id_seq')
        r.hset('users', username, password_hash)
        r.hset('user_ids', username, user_id)
        token = Auth.generate_token()
        expires_at = (datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)).isoformat()
        r.hset(f'session:{token}', mapping={
            'user_id': user_id,
            'username': username,
            'expires_at': expires_at
        })
        r.sadd('sessions', token)
        logger.info(f"✓ User registered: {username}, returning token: {token[:20]}...")
        return {
            'success': True,
            'token': token,
            'username': username,
            'expires_in': TOKEN_EXPIRY_HOURS * 3600
        }

    @staticmethod
    def login(username: str, password: str) -> dict:
        logger.info(f"Login attempt for username: {username}")
        r = RedisDB.get_connection()
        password_hash = r.hget('users', username)
        if not password_hash:
            return {'success': False, 'error': 'Invalid username or password'}
        if not Auth.verify_password(password, password_hash):
            return {'success': False, 'error': 'Invalid username or password'}
        user_id = r.hget('user_ids', username)
        token = Auth.generate_token()
        expires_at = (datetime.now() + timedelta(hours=TOKEN_EXPIRY_HOURS)).isoformat()
        r.hset(f'session:{token}', mapping={
            'user_id': user_id,
            'username': username,
            'expires_at': expires_at
        })
        r.sadd('sessions', token)
        logger.info(f"User logged in successfully: {username}")
        return {
            'success': True,
            'token': token,
            'username': username,
            'expires_in': TOKEN_EXPIRY_HOURS * 3600
        }

    @staticmethod
    def validate_token(token: str) -> dict:
        r = RedisDB.get_connection()
        session = r.hgetall(f'session:{token}')
        if not session:
            return None
        expires_at = session.get('expires_at')
        if not expires_at:
            return None
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            now = datetime.now()
            if exp_dt < now:
                return None
        except:
            return None
        return {
            'user_id': int(session['user_id']),
            'username': session['username']
        }

class ClipboardManager:
    @staticmethod
    def push(user_id: int, content: str, device_id: str = '', content_type: str = 'text') -> dict:
        r = RedisDB.get_connection()
        key = f'clipboard:{user_id}'
        timestamp = datetime.now().isoformat()
        item_id = r.incr(f'clipboard_id:{user_id}')
        # Сохраняем контент вместе с device_id, type и уникальным ID
        item = json.dumps({
            'id': item_id,
            'content': content,
            'device_id': device_id,
            'type': content_type,  # 'text' или 'image'
            'timestamp': timestamp
        })
        r.lpush(key, item)
        r.ltrim(key, 0, 9)  # Оставляем последние 10 записей
        logger.info(f"Pushed {content_type} item #{item_id} from device {device_id[:8] if device_id else 'unknown'}...")
        return {'success': True, 'id': item_id}

    @staticmethod
    def get(user_id: int, requesting_device_id: str = '') -> dict:
        r = RedisDB.get_connection()
        key = f'clipboard:{user_id}'
        
        # Получаем last_id для этого устройства с сервера
        last_id_key = f'last_id:{user_id}:{requesting_device_id}'
        last_id = int(r.get(last_id_key) or 0)
        
        items = r.lrange(key, 0, 9)  # Получаем последние 10 записей
        logger.info(f"SYNC: device={requesting_device_id[:8] if requesting_device_id else 'none'}, server_last_id={last_id}, items={len(items)}")
        
        for item_str in items:
            try:
                item = json.loads(item_str)
                item_id = item.get('id', 0)
                item_device_id = item.get('device_id', '')
                
                # Возвращаем только данные от ДРУГИХ устройств И только новые (id > last_id)
                if item_device_id != requesting_device_id and item_id > last_id:
                    # Обновляем last_id на сервере для этого устройства
                    r.set(last_id_key, item_id)
                    logger.info(f"  → Returning item #{item_id}, updated last_id to {item_id}")
                    return {
                        'success': True,
                        'content': item.get('content'),
                        'type': item.get('type', 'text'),
                        'timestamp': item.get('timestamp'),
                        'device_id': item_device_id,
                        'id': item_id
                    }
            except Exception as e:
                logger.error(f"Error parsing clipboard item: {e}")
                pass
        
        return {
            'success': True,
            'content': None,
            'timestamp': None,
            'id': last_id
        }

class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass
    def send_json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.end_headers()
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == '/':
            self.send_json({
                'status': 'ok',
                'service': 'clipboard-sync',
                'version': '3.0-redis'
            })
        elif parsed.path == '/sync':
            params = parse_qs(parsed.query)
            token = params.get('token', [''])[0]
            device_id = params.get('device_id', [''])[0]
            # last_id теперь хранится на сервере, параметр клиента игнорируется
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = ClipboardManager.get(user['user_id'], requesting_device_id=device_id)
            self.send_json(result)
        else:
            self.send_json({'error': 'Not found'}, 404)
    def do_POST(self):
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
            device_id = data.get('device_id', '')
            content_type = data.get('type', 'text')  # 'text' или 'image'
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            
            # Логируем тип контента
            if content_type == 'image':
                logger.info(f"Received image from device {device_id[:8] if device_id else 'unknown'}, base64 length: {len(content)}")
            else:
                logger.info(f"Received text from device {device_id[:8] if device_id else 'unknown'}: {content[:50] if content else 'empty'}...")
            
            result = ClipboardManager.push(user['user_id'], content, device_id, content_type)
            self.send_json(result)
        else:
            logger.warning(f"Unknown endpoint: {self.path}")
            self.send_json({'error': 'Endpoint not found'}, 404)

def main():
    logger.info("Server starting...")
    server = HTTPServer((HOST, PORT), RequestHandler)
    logger.info(f"Server running on {HOST}:{PORT}")
    logger.info(f"Token expiry: {TOKEN_EXPIRY_HOURS} hours")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Server error: {e}")

if __name__ == '__main__':
    main()
