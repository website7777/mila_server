#!/usr/bin/env python3
"""
Объединенный сервер синхронизации буфера обмена
HTTP API + WebSocket на одном порту для облачного развертывания
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
import signal
import sys
from urllib.parse import urlparse, parse_qs
import threading
from websockets.server import serve

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Переменные окружения
PORT = int(os.environ.get('PORT', 8765))
HOST = os.environ.get('HOST', '0.0.0.0')

# Глобальные переменные
clients = {}
user_devices = {}
db_path = 'clipboard_sync.db'
server_running = True

def init_database():
    """Инициализация базы данных"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                device_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
        return True
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

def hash_password(password):
    """Хеширование пароля"""
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate_user(username, password):
    """Аутентификация пользователя"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        password_hash = hash_password(password)
        cursor.execute('SELECT username FROM users WHERE username = ? AND password_hash = ?',
                      (username, password_hash))
        
        result = cursor.fetchone()
        conn.close()
        
        return result is not None
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return False

def register_user(username, password):
    """Регистрация нового пользователя"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        password_hash = hash_password(password)
        cursor.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)',
                      (username, password_hash))
        
        conn.commit()
        conn.close()
        logger.info(f"User {username} registered successfully")
        return True
    except sqlite3.IntegrityError:
        logger.warning(f"Username {username} already exists")
        return False
    except Exception as e:
        logger.error(f"Registration error: {e}")
        return False

def create_session(username, device_id="unknown"):
    """Создание сессии"""
    try:
        token = secrets.token_urlsafe(32)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('INSERT INTO sessions (username, token, device_id) VALUES (?, ?, ?)',
                      (username, token, device_id))
        
        conn.commit()
        conn.close()
        
        return token
    except Exception as e:
        logger.error(f"Session creation error: {e}")
        return None

def get_user_by_token(token):
    """Получение пользователя по токену"""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT username FROM sessions WHERE token = ?', (token,))
        result = cursor.fetchone()
        
        conn.close()
        return result[0] if result else None
    except Exception as e:
        logger.error(f"Token validation error: {e}")
        return None

async def handle_http_request(path, headers, body):
    """Обработка HTTP запросов"""
    try:
        # CORS заголовки
        cors_headers = {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Content-Type': 'application/json'
        }
        
        if not body:
            return 400, cors_headers, json.dumps({'error': 'No data provided'})
            
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return 400, cors_headers, json.dumps({'error': 'Invalid JSON'})
        
        if path == '/register':
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            
            if not username or not password:
                return 400, cors_headers, json.dumps({'error': 'Username and password required'})
            
            if register_user(username, password):
                token = create_session(username, data.get('device_id', 'unknown'))
                if token:
                    return 200, cors_headers, json.dumps({
                        'success': True, 
                        'token': token,
                        'message': 'Registration successful'
                    })
                else:
                    return 500, cors_headers, json.dumps({'error': 'Session creation failed'})
            else:
                return 409, cors_headers, json.dumps({'error': 'Username already exists'})
                
        elif path == '/auth':
            username = data.get('username', '').strip()
            password = data.get('password', '').strip()
            
            if not username or not password:
                return 400, cors_headers, json.dumps({'error': 'Username and password required'})
            
            if authenticate_user(username, password):
                token = create_session(username, data.get('device_id', 'unknown'))
                if token:
                    return 200, cors_headers, json.dumps({
                        'success': True, 
                        'token': token,
                        'message': 'Authentication successful'
                    })
                else:
                    return 500, cors_headers, json.dumps({'error': 'Session creation failed'})
            else:
                return 401, cors_headers, json.dumps({'error': 'Invalid credentials'})
        else:
            return 404, cors_headers, json.dumps({'error': 'Not found'})
            
    except Exception as e:
        logger.error(f"HTTP request error: {e}")
        return 500, {'Content-Type': 'application/json'}, json.dumps({'error': 'Internal server error'})

async def handle_websocket_connection(websocket):
    """Обработка WebSocket соединений"""
    token = None
    username = None
    
    try:
        # Получаем токен из первого сообщения
        auth_message = await asyncio.wait_for(websocket.recv(), timeout=10.0)
        auth_data = json.loads(auth_message)
        
        if auth_data.get('type') != 'auth':
            await websocket.close(code=4000, reason='Authentication required')
            return
            
        token = auth_data.get('token', '').strip()
        if not token:
            await websocket.close(code=4001, reason='Token required')
            return
            
        username = get_user_by_token(token)
        if not username:
            await websocket.close(code=4002, reason='Invalid token')
            return
            
        # Регистрируем клиента
        clients[token] = websocket
        if username not in user_devices:
            user_devices[username] = set()
        user_devices[username].add(token)
        
        logger.info(f"User {username} connected with token {token[:8]}...")
        
        # Отправляем подтверждение
        await websocket.send(json.dumps({
            'type': 'auth_success',
            'message': 'Authentication successful'
        }))
        
        # Обрабатываем сообщения
        async for message in websocket:
            try:
                data = json.loads(message)
                if data.get('type') == 'clipboard_sync':
                    content = data.get('content', '')
                    
                    # Отправляем контент всем устройствам пользователя
                    if username in user_devices:
                        for device_token in user_devices[username].copy():
                            if device_token != token and device_token in clients:
                                try:
                                    await clients[device_token].send(json.dumps({
                                        'type': 'clipboard_sync',
                                        'content': content,
                                        'timestamp': time.time()
                                    }))
                                except:
                                    # Удаляем отключенного клиента
                                    user_devices[username].discard(device_token)
                                    clients.pop(device_token, None)
                                    
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from {username}")
            except Exception as e:
                logger.error(f"Message handling error: {e}")
                break
                
    except asyncio.TimeoutError:
        logger.warning("WebSocket authentication timeout")
        await websocket.close(code=4003, reason='Authentication timeout')
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        # Очистка при отключении
        if token and username:
            clients.pop(token, None)
            if username in user_devices:
                user_devices[username].discard(token)
                if not user_devices[username]:
                    del user_devices[username]
            logger.info(f"User {username} disconnected")

async def handler(websocket, path):
    """Общий обработчик для HTTP и WebSocket"""
    try:
        # Проверяем тип запроса
        if hasattr(websocket, 'request') and hasattr(websocket.request, 'method'):
            # Это HTTP запрос
            if websocket.request.method == 'OPTIONS':
                # CORS preflight
                await websocket.send("HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, GET, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n\r\n")
                return
            elif websocket.request.method == 'POST':
                # HTTP POST запрос
                body = await websocket.recv() if hasattr(websocket, 'recv') else ''
                headers = dict(websocket.request.headers) if hasattr(websocket.request, 'headers') else {}
                
                status, response_headers, response_body = await handle_http_request(path, headers, body)
                
                # Отправляем HTTP ответ
                response = f"HTTP/1.1 {status} OK\r\n"
                for key, value in response_headers.items():
                    response += f"{key}: {value}\r\n"
                response += "\r\n" + response_body
                
                await websocket.send(response)
                return
        
        # Иначе это WebSocket соединение
        await handle_websocket_connection(websocket)
        
    except Exception as e:
        logger.error(f"Handler error: {e}")
        try:
            await websocket.close()
        except:
            pass

def signal_handler(signum, frame):
    """Обработчик сигналов для корректного завершения"""
    global server_running
    logger.info(f"Received signal {signum}, shutting down...")
    server_running = False
    sys.exit(0)

async def main():
    """Главная функция"""
    global server_running
    
    # Регистрация обработчиков сигналов
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    # Инициализация базы данных
    if not init_database():
        logger.error("Failed to initialize database, exiting...")
        return
    
    logger.info(f"Starting unified server on {HOST}:{PORT}")
    
    try:
        # Простой WebSocket сервер
        async with serve(handle_websocket_connection, HOST, PORT):
            logger.info(f"Server started successfully on {HOST}:{PORT}")
            logger.info("Use Ctrl+C to stop")
            
            # Ждем сигнала завершения
            while server_running:
                await asyncio.sleep(1)
                
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        logger.info("Server shutdown complete")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")