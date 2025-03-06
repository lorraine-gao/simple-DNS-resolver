import sys
import socket

class invalidargumenterror(Exception):
    pass

def start_client():
    try:
        if len(sys.argv) <= 4:
            raise invalidargumenterror
        
        host = sys.argv[1]
        port = int(sys.argv[2])
        data =sys.argv[3]
        temp = sys.argv[4]
        timeout = int(sys.argv[4]) if len(sys.argv) >4 else 5
        query_type = sys.argv[5] if len(sys.argv) >5 else 'A'
        query_type = query_type.lower()
        # print(len(sys.argv))

        
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(timeout)
        
        try:
            message = [data,timeout,query_type]
            message = str(message)
            
            client_socket.connect((host, port))

            client_socket.send(message.encode())
            # client_socket.send(timeout.encode())
            # client_socket.send(timer.encode())


            result = client_socket.recv(1024).decode()
            print('this is ip address: ' + result) #这里最后调格式就好
        except socket.timeout:
            print("Timeout: Server did not respond within 5 seconds.")
        finally:
            client_socket.close()


    except invalidargumenterror:
        print('Error: invalid arguments\nUsage: client resolver_ip resolver_port name timeout')
    except ValueError:
        print('Error: invalid arguments.\nUsage:port need be a integer.')




if __name__ == '__main__':
    start_client()
