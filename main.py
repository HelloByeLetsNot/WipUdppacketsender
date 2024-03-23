import socket
import struct

def checksum(data):
    # If the length of the data is odd, pad it with zero
    if len(data) % 2 != 0:
        data += b'\x00'
    # Calculate the checksum
    checksum = 0
    for i in range(0, len(data), 2):
        checksum += (data[i] << 8) + data[i+1]
    checksum = (checksum >> 16) + (checksum & 0xffff)
    checksum += checksum >> 16
    checksum = ~checksum & 0xffff
    return checksum

def send_udp_packet(target_ip, target_port, spoofed_ip, payload):
    try:
        # Create a raw socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error as e:
        print("Socket creation failed:", e)
        return

    # Set the IP header
    ip_header = struct.pack('!BBHHHBBH4s4s', 4 << 4, 0, 20 + 8 + len(payload), 0, 64, socket.IPPROTO_UDP, 0, socket.inet_aton(spoofed_ip), socket.inet_aton(target_ip))

    # Set the UDP header
    udp_header = struct.pack('!HHHH', 12345, target_port, 8 + len(payload), 0)

    # Calculate checksums
    pseudo_header = struct.pack('4s4sBBH', socket.inet_aton(spoofed_ip), socket.inet_aton(target_ip), 0, socket.IPPROTO_UDP, len(udp_header) + len(payload))
    data = pseudo_header + udp_header + payload.encode()
    udp_checksum = checksum(data)

    # Update IP header with checksum
    ip_header = ip_header[:10] + struct.pack('H', checksum(ip_header)) + ip_header[12:]

    # Update UDP header with checksum
    udp_header = struct.pack('!HHHH', 12345, target_port, 8 + len(payload), udp_checksum)

    try:
        # Send the packet to the target IP address and port
        s.sendto(ip_header + udp_header + payload.encode(), (target_ip, target_port))
        print("Packet sent successfully!")
    except socket.error as e:
        print("Packet sending failed:", e)
    finally:
        # Close the socket
        s.close()

# Example usage
target_ip = '192.168.1.100'
target_port = 12345
spoofed_ip = '192.168.1.101'
payload = 'Hello, world!'

send_udp_packet(target_ip, target_port, spoofed_ip, payload)