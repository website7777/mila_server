#!/usr/bin/env python3
"""
Безопасный сервер синхронизации + Удаленное управление ПК v4.0 (Valkey/Redis)
Работает с DigitalOcean Managed Valkey/Redis
Поддерживает:
- Регистрацию и авторизацию пользователей
- Синхронизацию буфера обмена
- Удаленное управление ПК (команды от телефона к ПК)
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
import time

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

# Время жизни команд (сек)
COMMAND_TTL = 300  # 5 минут
# Время жизни результатов (сек)
RESULT_TTL = 600  # 10 минут


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
            'user_id': user_id,
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
            'user_id': int(user_id),
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
    """Синхронизация буфера обмена"""
    
    @staticmethod
    def push(user_id: int, content: str, device_id: str = '', content_type: str = 'text') -> dict:
        r = RedisDB.get_connection()
        key = f'clipboard:{user_id}'
        timestamp = datetime.now().isoformat()
        item_id = r.incr(f'clipboard_id:{user_id}')
        item = json.dumps({
            'id': item_id,
            'content': content,
            'device_id': device_id,
            'type': content_type,
            'timestamp': timestamp
        })
        r.lpush(key, item)
        r.ltrim(key, 0, 9)
        logger.info(f"Pushed {content_type} item #{item_id} from device {device_id[:8] if device_id else 'unknown'}...")
        return {'success': True, 'id': item_id}

    @staticmethod
    def get(user_id: int, requesting_device_id: str = '') -> dict:
        r = RedisDB.get_connection()
        key = f'clipboard:{user_id}'
        last_id_key = f'last_id:{user_id}:{requesting_device_id}'
        last_id = int(r.get(last_id_key) or 0)
        items = r.lrange(key, 0, 9)
        
        for item_str in items:
            try:
                item = json.loads(item_str)
                item_id = item.get('id', 0)
                item_device_id = item.get('device_id', '')
                
                if item_device_id != requesting_device_id and item_id > last_id:
                    r.set(last_id_key, item_id)
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


class PCControlManager:
    """Управление удаленными ПК через очереди команд"""
    
    @staticmethod
    def register_pc(user_id: int, pc_id: str, pc_name: str = '') -> dict:
        """Регистрация ПК пользователя"""
        r = RedisDB.get_connection()
        pc_key = f'pc:{user_id}:{pc_id}'
        r.hset(pc_key, mapping={
            'pc_id': pc_id,
            'pc_name': pc_name or pc_id,
            'status': 'online',
            'last_seen': datetime.now().isoformat()
        })
        r.sadd(f'user_pcs:{user_id}', pc_id)
        logger.info(f"PC registered: {pc_name} ({pc_id}) for user {user_id}")
        return {'success': True, 'pc_id': pc_id}

    @staticmethod
    def heartbeat(user_id: int, pc_id: str) -> dict:
        """Обновление статуса ПК"""
        r = RedisDB.get_connection()
        pc_key = f'pc:{user_id}:{pc_id}'
        r.hset(pc_key, mapping={
            'status': 'online',
            'last_seen': datetime.now().isoformat()
        })
        return {'success': True}

    @staticmethod
    def get_pcs(user_id: int) -> dict:
        """Получить список ПК пользователя"""
        r = RedisDB.get_connection()
        pc_ids = r.smembers(f'user_pcs:{user_id}')
        pcs = []
        for pc_id in pc_ids:
            pc_data = r.hgetall(f'pc:{user_id}:{pc_id}')
            if pc_data:
                # Проверяем, онлайн ли ПК (последний heartbeat не более 30 сек назад)
                last_seen = pc_data.get('last_seen')
                if last_seen:
                    try:
                        last_seen_dt = datetime.fromisoformat(last_seen)
                        is_online = (datetime.now() - last_seen_dt).seconds < 30
                        pc_data['status'] = 'online' if is_online else 'offline'
                    except:
                        pc_data['status'] = 'offline'
                pcs.append(pc_data)
        return {'success': True, 'pcs': pcs}

    @staticmethod
    def send_command(user_id: int, pc_id: str, command_type: str, command_data: dict) -> dict:
        """Отправить команду на ПК (от телефона/браузера)"""
        r = RedisDB.get_connection()
        command_id = secrets.token_urlsafe(16)
        command_queue = f'commands:{user_id}:{pc_id}'
        
        command = {
            'id': command_id,
            'type': command_type,
            'data': command_data,
            'timestamp': datetime.now().isoformat(),
            'status': 'pending'
        }
        
        r.lpush(command_queue, json.dumps(command))
        r.expire(command_queue, COMMAND_TTL)
        
        logger.info(f"Command sent: {command_type} to PC {pc_id} (cmd_id: {command_id})")
        return {'success': True, 'command_id': command_id}

    @staticmethod
    def get_commands(user_id: int, pc_id: str) -> dict:
        """Получить команды для ПК (вызывается с ПК)"""
        r = RedisDB.get_connection()
        command_queue = f'commands:{user_id}:{pc_id}'
        
        commands = []
        # Забираем все ожидающие команды
        while True:
            cmd_str = r.rpop(command_queue)
            if not cmd_str:
                break
            try:
                cmd = json.loads(cmd_str)
                commands.append(cmd)
            except:
                pass
        
        if commands:
            logger.info(f"Returning {len(commands)} commands to PC {pc_id}")
        
        return {'success': True, 'commands': commands}

    @staticmethod
    def send_result(user_id: int, pc_id: str, command_id: str, result: dict) -> dict:
        """Отправить результат выполнения команды (от ПК)"""
        r = RedisDB.get_connection()
        result_key = f'result:{user_id}:{pc_id}:{command_id}'
        
        result_data = {
            'command_id': command_id,
            'result': result,
            'timestamp': datetime.now().isoformat()
        }
        
        r.set(result_key, json.dumps(result_data))
        r.expire(result_key, RESULT_TTL)
        
        # Также публикуем в pubsub для real-time
        r.publish(f'results:{user_id}:{pc_id}', json.dumps(result_data))
        
        logger.info(f"Result received for command {command_id}")
        return {'success': True}

    @staticmethod
    def get_result(user_id: int, pc_id: str, command_id: str) -> dict:
        """Получить результат команды (вызывается с телефона/браузера)"""
        r = RedisDB.get_connection()
        result_key = f'result:{user_id}:{pc_id}:{command_id}'
        
        result_str = r.get(result_key)
        if result_str:
            result = json.loads(result_str)
            return {'success': True, 'data': result}
        
        return {'success': True, 'data': None, 'status': 'pending'}

    @staticmethod
    def push_screen(user_id: int, pc_id: str, image_base64: str, width: int, height: int) -> dict:
        """ПК отправляет скриншот экрана"""
        r = RedisDB.get_connection()
        screen_key = f'screen:{user_id}:{pc_id}'
        
        screen_data = {
            'image': image_base64,
            'width': width,
            'height': height,
            'timestamp': datetime.now().isoformat()
        }
        
        r.set(screen_key, json.dumps(screen_data))
        r.expire(screen_key, 30)  # Экран живет 30 сек
        
        return {'success': True}

    @staticmethod
    def get_screen(user_id: int, pc_id: str) -> dict:
        """Браузер/телефон получает скриншот экрана"""
        r = RedisDB.get_connection()
        screen_key = f'screen:{user_id}:{pc_id}'
        
        screen_str = r.get(screen_key)
        if screen_str:
            screen = json.loads(screen_str)
            return {
                'success': True,
                'image': screen.get('image'),
                'width': screen.get('width'),
                'height': screen.get('height'),
                'timestamp': screen.get('timestamp')
            }
        
        return {'success': True, 'image': None}


class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, data: dict, status: int = 200):
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)
        # Нормализуем путь (убираем двойные слеши)
        path = parsed.path.replace('//', '/')
        
        if path == '/':
            self.send_json({
                'status': 'ok',
                'service': 'pc-control-sync',
                'version': '4.0-redis'
            })
            
        elif path == '/sync':
            # Синхронизация буфера обмена
            token = params.get('token', [''])[0]
            device_id = params.get('device_id', [''])[0]
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = ClipboardManager.get(user['user_id'], requesting_device_id=device_id)
            self.send_json(result)
            
        elif path == '/pc/list':
            # Список ПК пользователя
            token = params.get('token', [''])[0]
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = PCControlManager.get_pcs(user['user_id'])
            self.send_json(result)
            
        elif path == '/pc/commands':
            # ПК запрашивает команды
            token = params.get('token', [''])[0]
            pc_id = params.get('pc_id', [''])[0]
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            # Также обновляем heartbeat
            PCControlManager.heartbeat(user['user_id'], pc_id)
            result = PCControlManager.get_commands(user['user_id'], pc_id)
            self.send_json(result)
            
        elif path == '/pc/result':
            # Браузер/телефон запрашивает результат команды
            token = params.get('token', [''])[0]
            pc_id = params.get('pc_id', [''])[0]
            command_id = params.get('command_id', [''])[0]
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = PCControlManager.get_result(user['user_id'], pc_id, command_id)
            self.send_json(result)
            
        elif path == '/pc/screen':
            # Браузер/телефон запрашивает скриншот экрана
            token = params.get('token', [''])[0]
            pc_id = params.get('pc_id', [''])[0]
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = PCControlManager.get_screen(user['user_id'], pc_id)
            self.send_json(result)
            
        else:
            self.send_json({'error': 'Not found'}, 404)

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        # Нормализуем путь
        path = self.path.replace('//', '/')
        logger.info(f"POST {path} - Content-Length: {content_length}")
        
        try:
            data = json.loads(post_data.decode('utf-8')) if content_length > 0 else {}
        except Exception as e:
            logger.error(f"JSON parse error: {e}")
            self.send_json({'error': 'Invalid JSON'}, 400)
            return

        # === Авторизация ===
        if path == '/register':
            result = Auth.register(
                data.get('username', ''),
                data.get('password', '')
            )
            self.send_json(result, 200 if result['success'] else 400)
            
        elif path == '/auth':
            result = Auth.login(
                data.get('username', ''),
                data.get('password', '')
            )
            self.send_json(result, 200 if result['success'] else 400)
            
        # === Буфер обмена ===
        elif path == '/push':
            token = data.get('token', '')
            content = data.get('content', '')
            device_id = data.get('device_id', '')
            content_type = data.get('type', 'text')
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = ClipboardManager.push(user['user_id'], content, device_id, content_type)
            self.send_json(result)
            
        # === PC Control ===
        elif path == '/pc/register':
            # Регистрация ПК
            token = data.get('token', '')
            pc_id = data.get('pc_id', '')
            pc_name = data.get('pc_name', '')
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = PCControlManager.register_pc(user['user_id'], pc_id, pc_name)
            self.send_json(result)
            
        elif path == '/pc/heartbeat':
            # Heartbeat от ПК
            token = data.get('token', '')
            pc_id = data.get('pc_id', '')
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = PCControlManager.heartbeat(user['user_id'], pc_id)
            self.send_json(result)
            
        elif path == '/pc/command':
            # Отправка команды на ПК (от телефона/браузера)
            token = data.get('token', '')
            pc_id = data.get('pc_id', '')
            command_type = data.get('command_type', '')
            command_data = data.get('command_data', {})
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = PCControlManager.send_command(user['user_id'], pc_id, command_type, command_data)
            self.send_json(result)
            
        elif path == '/pc/result':
            # ПК отправляет результат команды
            token = data.get('token', '')
            pc_id = data.get('pc_id', '')
            command_id = data.get('command_id', '')
            result_data = data.get('result', {})
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = PCControlManager.send_result(user['user_id'], pc_id, command_id, result_data)
            self.send_json(result)
            
        elif path == '/pc/screen':
            # ПК отправляет скриншот
            token = data.get('token', '')
            pc_id = data.get('pc_id', '')
            image = data.get('image', '')
            width = data.get('width', 0)
            height = data.get('height', 0)
            user = Auth.validate_token(token)
            if not user:
                self.send_json({'error': 'Invalid or expired token'}, 400)
                return
            result = PCControlManager.push_screen(user['user_id'], pc_id, image, width, height)
            self.send_json(result)
            
        else:
            logger.warning(f"Unknown endpoint: {path}")
            self.send_json({'error': 'Endpoint not found'}, 404)


def main():
    logger.info("PC Control Server starting...")
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
