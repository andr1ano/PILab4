import socket
import threading
import os
import json
import random

PORT = 7700
DB_FILE = 'database.json'

RESOURCE_ID = "FILESERVER_B"

MAX_CONNECTIONS = 10

# ================= КРИПТОГРАФІЯ =================
SHIFT_KEY = 7

def crc16_hash(text: str) -> str:
    data = text.encode('utf-8')
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc = crc << 1
            crc &= 0xFFFF
    return f"{crc:04X}"

def encrypt_shift(text: str) -> str:
    result = []
    for char in text:
        shifted = (ord(char) + SHIFT_KEY) % 0x110000
        result.append(chr(shifted))
    return "".join(result)

def decrypt_shift(text: str) -> str:
    result = []
    for char in text:
        shifted = (ord(char) - SHIFT_KEY) % 0x110000
        result.append(chr(shifted))
    return "".join(result)

def encrypt_keyed(text: str, key: str) -> str:
    if not key:
        key = "0"
    chunks = []
    for i, char in enumerate(text):
        k = ord(key[i % len(key)])
        shifted = (ord(char) + k) % 0x110000
        chunks.append(f"{shifted:06x}")
    return "".join(chunks)

def decrypt_keyed(text: str, key: str) -> str:
    if not key:
        key = "0"
    chars = []
    idx = 0
    for pos in range(0, len(text), 6):
        chunk = text[pos:pos + 6]
        code = int(chunk, 16)
        k = ord(key[idx % len(key)])
        original = (code - k) % 0x110000
        chars.append(chr(original))
        idx += 1
    return "".join(chars)

def freshness(n: int) -> int:
    return (n + 1) % 1_000_000_000

# ================= ТРАНСПОРТНИЙ РІВЕНЬ (шифр зсуву, 7 символів) =================
def send_tcp(conn: socket.socket, msg: str):
    encrypted = encrypt_shift(msg)
    conn.sendall(encrypted.encode('utf-8'))

def receive_tcp(conn: socket.socket) -> str:
    data = conn.recv(8192)
    if not data:
        raise ConnectionError("З'єднання закрито.")
    return decrypt_shift(data.decode('utf-8'))

# ================= РІВЕНЬ СЕАНСОВОГО КЛЮЧА Ks =================
def send_secure(conn: socket.socket, msg: str, ks: str):
    send_tcp(conn, encrypt_keyed(msg, ks))

def receive_secure(conn: socket.socket, ks: str) -> str:
    return decrypt_keyed(receive_tcp(conn), ks)

# ================= СТАН СЕРВЕРА =================
users_db = {}
server_master_key = None
db_lock = threading.Lock()

active_users = set()
active_users_lock = threading.Lock()

connection_semaphore = threading.BoundedSemaphore(MAX_CONNECTIONS)

def load_database():
    global users_db, server_master_key
    if os.path.exists(DB_FILE):
        try:
            with open(DB_FILE, 'r', encoding='utf-8') as f:
                raw = json.load(f)
            if isinstance(raw, dict) and "users" in raw and "server_master_key" in raw:
                users_db = raw["users"]
                server_master_key = raw["server_master_key"]
            else:
                users_db = raw
                server_master_key = crc16_hash(f"KB-{random.randint(0, 10**9)}")
                save_database()
            print(f"[DB] Базу даних успішно завантажено з '{DB_FILE}'")
            return
        except Exception as e:
            print(f"[DB] Помилка завантаження бази: {e}. Створення нової бази.")

    users_db = {
        "ADMIN": {
            "password_hash": crc16_hash("admin"),
            "is_blocked": False,
            "must_change_password": False
        }
    }
    server_master_key = crc16_hash(f"KB-{random.randint(0, 10**9)}")
    save_database()
    print(f"[DB] Створено нову базу даних у файлі '{DB_FILE}'")

def save_database():
    with db_lock:
        with open(DB_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                "server_master_key": server_master_key,
                "users": users_db
            }, f, indent=4, ensure_ascii=False)

# ================= СЕРВЕРНА ЧАСТИНА =================
def udp_discovery():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind(('', PORT))
    print(f"[UDP] Очікування broadcast-запитів на порту {PORT}...")

    while True:
        data, addr = udp_socket.recvfrom(1024)
        if data.decode('utf-8') == "DISCOVER":
            udp_socket.sendto(b"SERVER_HERE", addr)

def get_server_files():
    ignored = {DB_FILE, os.path.basename(__file__)}
    files = [f for f in os.listdir('.') if os.path.isfile(f) and f not in ignored]
    return files


def kdc_handshake(conn: socket.socket):
    attempts = 0
    while attempts < 3:
        msg = receive_tcp(conn)
        parts = msg.split('|', 2)
        if parts[0] != "KDC_REQ" or len(parts) < 3:
            send_tcp(conn, "ERROR|Помилка протоколу.")
            return None, None

        username, enc1 = parts[1], parts[2]

        if username not in users_db:
            attempts += 1
            send_tcp(conn, f"ERROR|Користувача не знайдено. Залишилось спроб: {3 - attempts}")
            continue

        if users_db[username]["is_blocked"]:
            send_tcp(conn, "ERROR|Обліковий запис заблоковано адміністратором.")
            continue

        with active_users_lock:
            if username in active_users:
                send_tcp(conn, "ERROR|Цей користувач вже знаходиться в системі (онлайн).")
                continue

        k_a = users_db[username]["password_hash"]

        ok, r1 = False, None
        try:
            inner1 = decrypt_keyed(enc1, k_a)
            r1_str, idb_recv, tag = inner1.split('|', 2)
            r1 = int(r1_str)
            ok = (idb_recv == RESOURCE_ID and tag == "CONNECT_B")
        except Exception:
            ok = False

        if not ok:
            attempts += 1
            send_tcp(conn, f"ERROR|Невірний пароль. Залишилось спроб: {3 - attempts}")
            continue

        ks = random.randint(10 ** 8, 10 ** 9 - 1)
        ticket = encrypt_keyed(f"{ks}|{username}", server_master_key)
        inner2 = f"{freshness(r1)}|{ks}|{RESOURCE_ID}|{ticket}"
        enc2 = encrypt_keyed(inner2, k_a)
        send_tcp(conn, f"KDC_RES|{enc2}")

        try:
            msg3 = receive_tcp(conn)
        except (ConnectionError, OSError):
            return None, None
        parts3 = msg3.split('|', 2)
        if parts3[0] != "B_AUTH" or len(parts3) < 3:
            send_tcp(conn, "ERROR|Помилка протоколу (очікувалось B_AUTH).")
            return None, None

        ticket_recv, enc_r2 = parts3[1], parts3[2]
        try:
            ticket_inner = decrypt_keyed(ticket_recv, server_master_key)
            ks_from_ticket, idA_from_ticket = ticket_inner.split('|', 1)
            if ks_from_ticket != str(ks) or idA_from_ticket != username:
                raise ValueError("Квиток недійсний")
            r2 = int(decrypt_keyed(enc_r2, str(ks)))
        except Exception:
            send_tcp(conn, "B_ERROR|Автентифікація не вдалася.")
            return None, None

        status = "FIRST" if users_db[username].get("must_change_password", False) else "OK"
        payload4 = f"{freshness(r2)}|{status}"
        enc4 = encrypt_keyed(payload4, str(ks))
        send_tcp(conn, f"B_OK|{enc4}")

        with active_users_lock:
            active_users.add(username)

        return username, str(ks)

    return None, None

def handle_client(conn: socket.socket, addr):
    current_user = None
    ks = None

    try:
        current_user, ks = kdc_handshake(conn)
        if not current_user:
            return

        if users_db[current_user].get("must_change_password", False):
            msg = receive_secure(conn, ks)
            parts = msg.split('|', 1)
            if parts[0] == "CHANGE_PASS":
                users_db[current_user]["password_hash"] = parts[1]
                users_db[current_user]["must_change_password"] = False
                save_database()
                send_secure(conn, "SUCCESS|Пароль успішно змінено. Вхід виконано.", ks)
            else:
                send_secure(conn, "ERROR|Очікувалась зміна пароля. Сесію закрито.", ks)
                return
        else:
            send_secure(conn, "SUCCESS|Вхід виконано успішно.", ks)

        while True:
            msg = receive_secure(conn, ks)
            parts = msg.split('|')
            cmd = parts[0]

            if cmd == "EXIT":
                break

            if current_user == "ADMIN":
                if cmd == "ADD_USER":
                    new_user, new_hash = parts[1], parts[2]
                    if new_user in users_db:
                        send_secure(conn, "ERROR|Користувач із таким ім'ям вже існує.", ks)
                    else:
                        users_db[new_user] = {
                            "password_hash": new_hash,
                            "is_blocked": False,
                            "must_change_password": True
                        }
                        save_database()
                        send_secure(conn,
                                    f"OK|Користувача '{new_user}' успішно додано. Він має змінити пароль при першому вході.",
                                    ks)

                elif cmd == "BLOCK_USER":
                    target_user = parts[1]
                    if target_user == "ADMIN":
                        send_secure(conn, "ERROR|Неможливо заблокувати обліковий запис адміністратора.", ks)
                    elif target_user not in users_db:
                        send_secure(conn, f"ERROR|Користувача '{target_user}' немає в базі даних.", ks)
                    elif users_db[target_user]["is_blocked"]:
                        send_secure(conn, f"ERROR|Користувач '{target_user}' вже заблокований.", ks)
                    else:
                        users_db[target_user]["is_blocked"] = True
                        save_database()
                        send_secure(conn, f"OK|Користувача '{target_user}' заблоковано.", ks)

                elif cmd == "CHANGE_PASS":
                    users_db["ADMIN"]["password_hash"] = parts[1]
                    save_database()
                    send_secure(conn, "OK|Пароль адміністратора змінено.", ks)
                else:
                    send_secure(conn, "ERROR|Невідома команда.", ks)

            else:
                if cmd == "LIST_FILES":
                    files = get_server_files()
                    send_secure(conn, f"OK|{json.dumps(files)}", ks)

                elif cmd == "GET_FILE":
                    filename = parts[1]
                    if os.path.exists(filename) and os.path.isfile(filename):
                        try:
                            with open(filename, 'r', encoding='utf-8') as f:
                                content = f.read()
                            send_secure(conn, f"OK|{content}", ks)
                        except UnicodeDecodeError:
                            send_secure(conn, "ERROR|Файл не є текстовим або має непідтримуване кодування.", ks)
                        except Exception as e:
                            send_secure(conn, f"ERROR|Помилка відкриття файлу: {e}", ks)
                    else:
                        send_secure(conn, "ERROR|Файл не знайдено на сервері.", ks)

                elif cmd == "CHANGE_PASS":
                    users_db[current_user]["password_hash"] = parts[1]
                    save_database()
                    send_secure(conn, "OK|Пароль успішно змінено.", ks)
                else:
                    send_secure(conn, "ERROR|Недостатньо прав або невідома команда.", ks)

    except ConnectionError:
        pass
    except Exception as e:
        print(f"Помилка з'єднання з клієнтом {addr}: {e}")
    finally:
        if current_user:
            with active_users_lock:
                active_users.discard(current_user)
        conn.close()
        connection_semaphore.release()

def start_server():
    load_database()

    threading.Thread(target=udp_discovery, daemon=True).start()

    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server.bind(('0.0.0.0', PORT))
    tcp_server.listen(5)
    print(f"[TCP] Сервер успішно запущено на порту {PORT}")

    while True:
        connection_semaphore.acquire()
        conn, addr = tcp_server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

if __name__ == "__main__":
    start_server()
