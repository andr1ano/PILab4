import socket
import sys
import json
import random

PORT = 7700
RESOURCE_ID = "FILESERVER_B"

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

# ================= ДОПОМІЖНІ ФУНКЦІЇ =================
def read_password(prompt="Пароль: "):
    print(prompt, end='', flush=True)
    password = ""
    try:
        import msvcrt
        while True:
            char = msvcrt.getch()
            if char in (b'\r', b'\n'):
                print('')
                break
            elif char == b'\x08':
                if len(password) > 0:
                    password = password[:-1]
                    sys.stdout.write('\b \b')
                    sys.stdout.flush()
            else:
                password += char.decode('utf-8', 'ignore')
                sys.stdout.write('*')
                sys.stdout.flush()
    except ImportError:
        import getpass
        password = getpass.getpass(prompt="")
    return password

def send_tcp(conn: socket.socket, msg: str):
    encrypted = encrypt_shift(msg)
    conn.sendall(encrypted.encode('utf-8'))

def receive_tcp(conn: socket.socket) -> str:
    data = conn.recv(8192)
    if not data:
        raise ConnectionError("З'єднання закрито.")
    return decrypt_shift(data.decode('utf-8'))

def send_secure(conn: socket.socket, msg: str, ks: str):
    send_tcp(conn, encrypt_keyed(msg, ks))

def receive_secure(conn: socket.socket, ks: str) -> str:
    return decrypt_keyed(receive_tcp(conn), ks)

# ================= КЛІЄНТСЬКА ЛОГІКА =================
def kdc_login(tcp_socket):
    while True:
        user = input("Логін: ")
        password = read_password("Пароль: ")
        k_a = crc16_hash(password)

        r1 = random.randint(10 ** 5, 10 ** 6 - 1)
        inner1 = f"{r1}|{RESOURCE_ID}|CONNECT_B"
        enc1 = encrypt_keyed(inner1, k_a)
        send_tcp(tcp_socket, f"KDC_REQ|{user}|{enc1}")

        resp = receive_tcp(tcp_socket)
        parts = resp.split('|', 1)

        if parts[0] == "ERROR":
            print("\n" + parts[1])
            if "Залишилось спроб: 0" in parts[1]:
                return None, None, None
            print()
            continue

        if parts[0] != "KDC_RES":
            print("\nПомилка протоколу під час автентифікації.")
            return None, None, None

        try:
            inner2 = decrypt_keyed(parts[1], k_a)
            f_r1_recv, ks_str, idb_recv, ticket = inner2.split('|', 3)
            if int(f_r1_recv) != freshness(r1) or idb_recv != RESOURCE_ID:
                raise ValueError()
        except Exception:
            print("\nПомилка протоколу: некоректна відповідь ЦРК.")
            return None, None, None

        r2 = random.randint(10 ** 5, 10 ** 6 - 1)
        enc_r2 = encrypt_keyed(str(r2), ks_str)
        send_tcp(tcp_socket, f"B_AUTH|{ticket}|{enc_r2}")

        resp2 = receive_tcp(tcp_socket).split('|', 1)
        if resp2[0] != "B_OK":
            print("\nАвтентифікація об'єктом B не вдалася.")
            return None, None, None

        try:
            payload4 = decrypt_keyed(resp2[1], ks_str)
            f_r2_recv, status = payload4.split('|', 1)
            if int(f_r2_recv) != freshness(r2):
                raise ValueError()
        except Exception:
            print("\nПомилка протоколу: об'єкт B не підтвердив сеансовий ключ.")
            return None, None, None

        print("\n[Протокол 1] Сеансовий ключ Ks успішно встановлено між A і B.")
        return user, ks_str, status

def start_client():
    print("Пошук сервера через UDP Broadcast (очікування)...")
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    udp_socket.settimeout(3.0)

    server_ip = ""
    while not server_ip:
        try:
            udp_socket.sendto(b"DISCOVER", ('255.255.255.255', PORT))
            data, addr = udp_socket.recvfrom(1024)
            if data.decode('utf-8') == "SERVER_HERE":
                server_ip = addr[0]
                print(f"Сервер знайдено: {server_ip}")
        except socket.timeout:
            print("Сервер не знайдено. Повторна спроба...")

    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_socket.connect((server_ip, PORT))
    except Exception as e:
        print(f"Не вдалося підключитися до сервера: {e}")
        return

    try:
        role = ""

        user, ks, status = kdc_login(tcp_socket)
        if not user:
            return

        if status == "FIRST":
            print("\nЦе ваш перший вхід. За вимогами безпеки ви повинні змінити пароль.")
            while True:
                p1 = read_password("Новий пароль: ")
                p2 = read_password("Повторіть пароль: ")
                if p1 == p2:
                    send_secure(tcp_socket, f"CHANGE_PASS|{crc16_hash(p1)}", ks)
                    cp_resp = receive_secure(tcp_socket, ks).split('|', 1)
                    print("\n" + cp_resp[1])
                    if cp_resp[0] == "SUCCESS":
                        role = user
                        break
                    else:
                        return
                else:
                    print("Паролі не співпадають. Спробуйте ще раз.\n")
        else:
            resp = receive_secure(tcp_socket, ks).split('|', 1)
            print("\n" + resp[1])
            role = user

        while True:
            print(f"\n--- МЕНЮ [{role}] ---")
            print("1. Довідка")
            print("2. Змінити свій пароль")

            if role == "ADMIN":
                print("3. Додати користувача")
                print("4. Заблокувати користувача")
            else:
                print("3. Переглянути список документів на сервері та завантажити текст")

            print("0. Вихід")
            choice = input("> ")

            if choice == "0":
                send_secure(tcp_socket, "EXIT", ks)
                break

            elif choice == "1":
                print("\n" + "=" * 40)
                print("ДОВІДКА:")
                print("Програма: Клієнт-Серверна система на сокетах.")
                print("Автори: Терещук Андрій, Коваленко Олександр, Полозюк Дмитро. Група КН-51мн.")
                print("=" * 40)

            elif choice == "2":
                p1 = read_password("Новий пароль: ")
                p2 = read_password("Повторіть пароль: ")
                if p1 == p2:
                    send_secure(tcp_socket, f"CHANGE_PASS|{crc16_hash(p1)}", ks)
                    print("\n" + receive_secure(tcp_socket, ks).split('|', 1)[1])
                else:
                    print("\nПаролі не співпадають!")

            elif role == "ADMIN" and choice == "3":
                u = input("Ім'я нового користувача: ")
                p1 = read_password("Тимчасовий пароль: ")
                p2 = read_password("Підтвердіть пароль: ")
                if p1 == p2:
                    send_secure(tcp_socket, f"ADD_USER|{u}|{crc16_hash(p1)}", ks)
                    print("\n" + receive_secure(tcp_socket, ks).split('|', 1)[1])
                else:
                    print("\nПаролі не співпадають!")

            elif role == "ADMIN" and choice == "4":
                u = input("Ім'я користувача для блокування: ")
                send_secure(tcp_socket, f"BLOCK_USER|{u}", ks)
                print("\n" + receive_secure(tcp_socket, ks).split('|', 1)[1])

            elif role != "ADMIN" and choice == "3":
                send_secure(tcp_socket, "LIST_FILES", ks)
                resp = receive_secure(tcp_socket, ks).split('|', 1)

                if resp[0] == "OK":
                    files = json.loads(resp[1])
                    if not files:
                        print("На сервері немає доступних файлів.")
                        continue

                    print("\nДоступні файли на сервері:")
                    for idx, fname in enumerate(files, 1):
                        print(f"{idx}. {fname}")

                    file_idx = input("\nВведіть номер файлу (або 0 для скасування): ")
                    if file_idx.isdigit() and 1 <= int(file_idx) <= len(files):
                        selected_file = files[int(file_idx) - 1]
                        send_secure(tcp_socket, f"GET_FILE|{selected_file}", ks)

                        file_resp = receive_secure(tcp_socket, ks).split('|', 1)
                        if file_resp[0] == "OK":
                            print(f"\n--- Вміст файлу '{selected_file}' ---")
                            print(file_resp[1])
                            print("-" * 35)
                        else:
                            print(f"\nПомилка: {file_resp[1]}")
                    else:
                        print("Скасовано.")

    except (ConnectionError, OSError):
        print("\n[!] Зв'язок із сервером втрачено. Роботу завершено.")
    finally:
        tcp_socket.close()

if __name__ == "__main__":
    start_client()
