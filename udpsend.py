import socket
import time

UDP_IP = "192.168.1.69"  
UDP_PORT = 4321          
FILE_PATH = "test.txt"   
INTERVAL = 3             

def send_file():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with open(FILE_PATH, "rb") as f:
            data = f.read()
            sock.sendto(data, (UDP_IP, UDP_PORT))
            print(f"[+] Sent {len(data)} bytes to {UDP_IP}:{UDP_PORT}")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()

if __name__ == "__main__":
    while True:
        send_file()
        time.sleep(INTERVAL) 