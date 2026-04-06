import socket, struct, time, sys

if len(sys.argv) < 4:
    print("Usage: python3 spoof_test.py <fake_src_ip> <dst_ip> <dst_port>")
    print("Example: python3 spoof_test.py 146.70.104.252 178.131.186.36 54569")
    sys.exit(1)

fake_src_ip = sys.argv[1]
dst_ip = sys.argv[2]
dst_port = int(sys.argv[3])

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

src_ip_packed = socket.inet_aton(fake_src_ip)
dst_ip_packed = socket.inet_aton(dst_ip)

count = 0
while True:
    count += 1
    data = f"SPOOFTEST_{count}".encode()
    udp_len = 8 + len(data)
    udp = struct.pack('!HHHH', 443, dst_port, udp_len, 0) + data
    total = 20 + len(udp)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, count & 0xFFFF, 0x4000, 128, 17, 0, src_ip_packed, dst_ip_packed)
    s.sendto(ip + udp, (dst_ip, dst_port))
    print(f"[{count}] Sent spoofed pkt to {dst_ip}:{dst_port} from {fake_src_ip}:443")
    time.sleep(6)
