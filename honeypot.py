import json
import socket
import threading
import time
import paramiko

HOST = "127.0.0.1"   # only your own computer, never the internet
PORT = 2222
LOGFILE = "honeypot_log.jsonl"

host_key = paramiko.RSAKey.generate(2048)
lock = threading.Lock()


def save(entry):
    with lock:
        with open(LOGFILE, "a") as f:
            f.write(json.dumps(entry) + "\n")


class FakeSSH(paramiko.ServerInterface):
    def __init__(self, ip):
        self.ip = ip

    def check_auth_password(self, username, password):
        entry = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": self.ip,
            "username": username,
            "password": password,
        }
        save(entry)
        print(f"[{entry['time']}] {self.ip} tried {username} / {password}")
        return paramiko.AUTH_FAILED   # always reject

    def get_allowed_auths(self, username):
        return "password"


def handle(client, addr):
    transport = paramiko.Transport(client)
    try:
        transport.add_server_key(host_key)
        transport.start_server(server=FakeSSH(addr[0]))
        transport.accept(30)
    except Exception:
        pass
    finally:
        transport.close()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((HOST, PORT))
    sock.listen(20)
    print(f"Honeypot listening on {HOST}:{PORT}  (Ctrl+C to stop)")
    while True:
        client, addr = sock.accept()
        threading.Thread(target=handle, args=(client, addr), daemon=True).start()


if __name__ == "__main__":
    main()
