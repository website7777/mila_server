#!/usr/bin/env python3
"""
Упрощенная версия сервера синхронизации буфера обмена
Исправлены все проблемы с WebSocket и HTTP
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
from http.server import HTTPServer, BaseHTTPRequestHandler

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Глобальные переменные для простоты
clients = {}  # token -> websocket
user_devices = {}  # username -> set of tokens
db_path = 'clipboard_sync.db'

def init_database():
    """Инициализация базы данных"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            device_id TEXT NOT NULL,
            device_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (username) REFERENCES users (username)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info("База данных инициализирована")

def hash_password(password: str) -> str:
    """Хеширование пароля"""
    return hashlib.sha256(password.encode()).hexdigest()

def generate_token() -> str:
    """Генерация токена сессии"""
    return secrets.token_urlsafe(32)

async def register_user(username: str, password: str, email: str = "", device_id: str = "", device_name: str = "") -> dict:
    """Регистрация нового пользователя"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            conn.close()
            return {'success': False, 'error': 'Пользователь уже существует'}
        
        password_hash = hash_password(password)
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                     (username, password_hash, email))
        
        token = generate_token()
        cursor.execute("INSERT INTO sessions (token, username, device_id, device_name) VALUES (?, ?, ?, ?)",
                     (token, username, device_id, device_name))
        
        conn.commit()
        conn.close()
        
        if username not in user_devices:
            user_devices[username] = set()
        user_devices[username].add(token)
        
        logger.info(f"Зарегистрирован новый пользователь: {username}")
        return {'success': True, 'token': token}
        
    except Exception as e:
        logger.error(f"Ошибка регистрации пользователя {username}: {e}")
        return {'success': False, 'error': 'Ошибка сервера'}

async def authenticate_user(username: str, password: str, device_id: str = "", device_name: str = "") -> dict:
    """Аутентификация пользователя"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        password_hash = hash_password(password)
        cursor.execute("SELECT username FROM users WHERE username = ? AND password_hash = ?",
                     (username, password_hash))
        
        if not cursor.fetchone():
            conn.close()
            return {'success': False, 'error': 'Неверное имя пользователя или пароль'}
        
        token = generate_token()
        cursor.execute("INSERT INTO sessions (token, username, device_id, device_name) VALUES (?, ?, ?, ?)",
                     (token, username, device_id, device_name))
        
        conn.commit()
        conn.close()
        
        if username not in user_devices:
            user_devices[username] = set()
        user_devices[username].add(token)
        
        logger.info(f"Авторизован пользователь: {username}")
        return {'success': True, 'token': token}
        
    except Exception as e:
        logger.error(f"Ошибка аутентификации пользователя {username}: {e}")
        return {'success': False, 'error': 'Ошибка сервера'}

def get_username_by_token(token: str) -> str:
    """Получение имени пользователя по токену"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM sessions WHERE token = ?", (token,))
        result = cursor.fetchone()
        conn.close()
        return result[0] if result else None
    except Exception as e:
        logger.error(f"Ошибка получения пользователя по токену: {e}")
        return None

async def handle_websocket_connection(websocket):
    """Обработка WebSocket подключения"""
    token = None
    username = None
    
    try:
        # Получение токена из заголовков (новый способ для websockets 15+)
        headers = dict(websocket.request.headers) if hasattr(websocket, 'request') else {}
        auth_header = headers.get('authorization') or headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header[7:]
            username = get_username_by_token(token)
            
            if not username:
                await websocket.close(code=1008, reason='Invalid token')
                return
            
            # Регистрируем клиента
            clients[token] = websocket
            logger.info(f"Подключен клиент пользователя {username} (токен: {token[:8]}...)")
            
            # Отправляем список устройств
            device_list = list(user_devices.get(username, set()))
            await websocket.send(json.dumps({
                'type': 'device_list',
                'devices': device_list
            }))
            
            # Обработка сообщений
            async for message in websocket:
                await handle_message(token, username, message)
        else:
            logger.warning(f"Подключение без авторизации. Заголовки: {list(headers.keys())}")
            await websocket.close(code=1008, reason='Missing or invalid authorization')
            return
            
    except websockets.exceptions.ConnectionClosed:
        logger.info(f"Клиент отключен: {username}")
    except Exception as e:
        logger.error(f"Ошибка обработки WebSocket: {e}")
    finally:
        # Очистка при отключении
        if token and token in clients:
            del clients[token]
        if username and token:
            user_devices.get(username, set()).discard(token)

async def handle_message(sender_token: str, sender_username: str, message: str):
    """Обработка сообщения от клиента"""
    try:
        data = json.loads(message)
        msg_type = data.get('type')
        
        logger.info(f"Получено сообщение типа {msg_type} от {sender_username}")
        
        # Пересылаем сообщение всем остальным устройствам пользователя
        user_tokens = user_devices.get(sender_username, set())
        
        for token in user_tokens:
            if token != sender_token and token in clients:
                try:
                    await clients[token].send(message)
                except Exception as e:
                    logger.error(f"Ошибка отправки сообщения клиенту {token}: {e}")
                    # Удаляем неактивного клиента
                    if token in clients:
                        del clients[token]
                    user_tokens.discard(token)
                    
    except json.JSONDecodeError:
        logger.error("Получено некорректное JSON сообщение")
    except Exception as e:
        logger.error(f"Ошибка обработки сообщения: {e}")

# HTTP сервер для аутентификации
class SimpleAuthHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        """Обработка CORS preflight запросов"""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'POST, GET, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
    
    def do_POST(self):
        """Обработка POST запросов"""
        try:
            content_length = int(self.headers['Content-Length'])
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            path = self.path
            
            if path == '/register':
                result = asyncio.run(register_user(
                    data.get('username', ''),
                    data.get('password', ''),
                    data.get('email', ''),
                    data.get('device_id', ''),
                    data.get('device_name', '')
                ))
            elif path == '/auth':
                result = asyncio.run(authenticate_user(
                    data.get('username', ''),
                    data.get('password', ''),
                    data.get('device_id', ''),
                    data.get('device_name', '')
                ))
            else:
                result = {'success': False, 'error': 'Неизвестный путь'}
            
            self.send_response(200)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps(result).encode())
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({'success': False, 'error': str(e)}).encode())

async def main():
    """Запуск сервера"""
    # Инициализация базы данных
    init_database()
    
    # HTTP сервер для аутентификации
    http_server = HTTPServer(('0.0.0.0', 8080), SimpleAuthHandler)
    http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
    http_thread.start()
    
    logger.info("HTTP сервер запущен на порту 8080 (для аутентификации)")
    logger.info("WebSocket сервер запускается на порту 8765 (для синхронизации)")
    
    # WebSocket сервер для синхронизации
    async with websockets.serve(handle_websocket_connection, '0.0.0.0', 8765):
        logger.info("Сервер синхронизации буфера обмена запущен!")
        logger.info("Используйте Ctrl+C для остановки")
        
        try:
            await asyncio.Future()  # Запуск навсегда
        except KeyboardInterrupt:
            logger.info("Остановка сервера...")

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Сервер остановлен пользователем")