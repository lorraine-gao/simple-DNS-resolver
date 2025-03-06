
import socket
import random
import sys
import struct
from io import BytesIO

SERVER_PORT = 53
QUERY_TYPE_A = 1


def start_server():
    host = 'localhost'
    port = int(sys.argv[1])
    if len(sys.argv) != 2:
        print('Error: invalid arguments')

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))

    server_socket.listen(1)
    print('Server is listening on port', port)
    while True:
        conn, address = server_socket.accept()
        print('Connection from', address)

        root_servers = []
        with open("named.root", "r") as file:
            for line in file:
                if not line.strip().startswith(";"):
                    name, ttl, class_, ip_address = line.strip().split()
                    if class_ == "A":
                        root_servers.append(name)
        # print(root_servers)
        
        while True:
            data = conn.recv(1024).decode() #解析域名
        
            if not data:
                break
            message = eval(data)
            domain_name = message[0]
            timeout = int(message[1])
            query_tpye = message[2]
            print('Received from client: ' + domain_name) 
            # print('Received from client: ' + timeout) 
            print('Received from client: ' + query_tpye) 
            query = construct_query(domain_name,query_tpye)

            current_server_ip = root_servers[0]
            current_server_port = SERVER_PORT

            while True:
                # print(current_server_ip)
                response = send_dns_query(query, current_server_ip, current_server_port,timeout)
                result = parse_response(response)
                print(result)
                if is_ip_address(result):
                    conn.send(result.encode())
                    break
                elif result[:5] == 'Error':
                    conn.send(result.encode())
                    break
                else:
                    current_server_ip = result
                    # break

        conn.close()
    
def is_ip_address(address):
    try:
        socket.inet_aton(address)
        return True
    except socket.error:
        return False
    
def send_dns_query(query, server_ip, server_port,timeout):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        # send query to dns server
        client_socket.sendto(query, (server_ip, server_port))
 
        # timeout
        client_socket.settimeout(timeout)

        response , _  = client_socket.recvfrom(1024)
        return response
    except socket.timeout:
        print(f"Error: Query to {server_ip} timed out.")
    finally:
        client_socket.close()


def construct_query(domain_name,query_tpye):

    ID = random.getrandbits(16) & 0xFFFF  # use any ID randomly

    flags_int = 0
    QNAME = b''
    for part in domain_name.split('.'):
        QNAME += bytes([len(part)]) + part.encode()
    QNAME += b'\x00'

    if query_tpye == 'a':
        QTYPE = b'\x00\x01'  # A type query
    if query_tpye == 'ns':
        QTYPE = b'\x00\x02'  # NS type query
    if query_tpye == 'mx':
        QTYPE = b'\x00\x0F'  # mx type query
    if query_tpye == 'cname':
        QTYPE = b'\x00\x05'  # cname type query


    QCLASS = b'\x00\x01' # Internet

    query = struct.pack('!HHHHHH', ID, flags_int , 1, 0, 0, 0)
    
    query += QNAME + QTYPE + QCLASS 
    # print(query)
    return query


def parse_response(response): 
    flag = bin(int.from_bytes(response[2:4],'big'))
    # print(flag)
    if flag[-4:] == '0000':  # Check if is a response
        result={}  #a
        answer_count = int.from_bytes(response[6:8], byteorder='big')
        auth_acoount = int.from_bytes(response[8:10], byteorder='big')
        
        if answer_count > 0:
            ip_address = []
            ip_address = '.'.join(str(byte) for byte in response[-4:])  
            return ip_address
        
        #if there is no answer，return a next authorinative name servers
        else:  
            questart = response[12:]
            # print('questart',questart)
            domain_parts = []
            i = 0
            while i < len(questart):
                label_length = questart[i]
                i += 1

                if label_length == 0:  # finish
                    break

                label = questart[i:i + label_length].decode('utf-8')
                domain_parts.append(label)
                i += label_length
            
            domain_parts = '.'.join(domain_parts)
            # print(domain_parts)
            length = i
            # print(length)

            authstart = questart[length+4:]  #把response删掉前面的，现在是authoritative section
            # print('authstart',authstart)
            auname = authstart[12:] #把前面的ttl啥的删掉 --这里有bug，不能确定第一个domain name一定就是2个字节
            # print('aunamestart',auname)

            domain_name = []
            pointer = 0
            # print('au_name_start',auname)

            while pointer < len(auname):
                au_label = auname[pointer] ##表示每个字节，直接是十进制
                # print(au_label)

                if au_label == 0:  # End of domain name
                    break
                else:  #所以au_label是长度字节

                    if (au_label & 0xC0) == 0xC0:  ##有压缩指针的情况
                        
                        forward = pointer + 1  
                        start_point = auname[forward] #要从起始位置开始往后偏移多少个字节
                     
                        for_message_start = response[start_point:] #准备开始计算的位置,这是一条字节信息
                        # print('准备开始计算的位置',for_message_start)

                        for_message_pointer = 0

                        while for_message_pointer < len(for_message_start):
                            for_mess_label = for_message_start[for_message_pointer]
                            if for_mess_label == 0:
                                pointer += 2
                                break
                            else:
                                for_message_pointer += 1
                                for_mess_byte =(for_message_start[for_message_pointer : for_message_pointer + for_mess_label].decode())
                                # print('偏移指针读出的消息',for_mess_byte)
                                for_message_pointer +=for_mess_label
                                # print('读完消息后的偏移的索引',for_message_pointer)
                                pointer += 2
                                domain_name.append(for_mess_byte +'.')
                        
                    else:
                        pointer  += 1 #所以就要往后移一个，到内容字节
                        byte_message = (auname[pointer : pointer + au_label].decode())
                       
                        domain_name.append(byte_message+'.')
                        # print(domain_name)
                        pointer += au_label
                  

            domain_name = ''.join(domain_name)
            return domain_name

    elif flag[-4:] == '0001':
        temp = "Error: there is a format error."
        return temp
    
    elif flag[-4:] == '0010':
        temp = "Error: there is a server failure."
        return temp

    elif flag[-4:] == '0011':
        temp = "Error: there is a name failure."
        return temp

    return None



if __name__ == '__main__':
    start_server()