import socket
import sys
import argparse
import time
import binascii
from dnsRequest import build_dns_request
from dnsResponse import decode_response
from utils import is_valid_hostname, is_valid_server_address
import time

def send_dns_query(domain_name, dns_server, dns_port, qtype, max_retries, timeout):
    # Build the DNS request packet
    dns_request = build_dns_request(domain_name, qtype)
    # print(binascii.hexlify(dns_request).decode("utf-8"))
    query_size = len(binascii.hexlify(dns_request).decode("utf-8"))

    # Create a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Specify the DNS server's address and port
    server_address = (dns_server[1:], dns_port)

    retries = 1

    while retries <= max_retries:

        try:
            # Send the DNS request packet to the DNS server
        
            start_time = time.time()  # Record the current time
            udp_socket.sendto(dns_request, server_address)

            # Receive the DNS response
            response, _ = udp_socket.recvfrom(1024)
            end_time = time.time()  # Record the time after the function has completed

            # Close the UDP socket
            udp_socket.close()

            elapsed_time = end_time - start_time 

            return response, elapsed_time, retries, query_size

        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(timeout)
            retries += 1


    return None, None, max_retries, e

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("-t", dest="timeout", help="how long to wait", type=int, default=5, required=False)
    parser.add_argument("-r", dest="max_retries", help="number of max retries", type=int, default=3, required=False)
    parser.add_argument("-p", dest="port_number", help="port number", type=int, default=53, required=False)

    # Define mutually exclusive groups for the flags
    group = parser.add_mutually_exclusive_group(required=False)

    # Add the mutually exclusive flags
    group.add_argument("-mx", action="store_true")
    group.add_argument("-ns", action="store_true")

    # Define regular (positional) arguments
    parser.add_argument("server_address", help="address of server")
    parser.add_argument("hostname", help="hostname to look for")

    args = parser.parse_args()

    if args.mx:
        args.type = "MX"
    elif args.ns:
        args.type = "NS"
    else: args.type = "A"

    if args.timeout <= 0:
        print("\nERROR \t Incorrect input syntax: Timeout has to be greater than 0")
        exit()
    if args.port_number < 0:
        print("\nERROR \t Incorrect input syntax: Port number has to be greater than or equal to 0")
        exit()
    if args.max_retries < 0: 
        print("\nERROR \t Incorrect input syntax: Max retries has to be greater than or equal to 0")
        exit()

    if not args.server_address:
        print("\nERROR \t Incorrect input syntax: Please add a server address")
        exit()
    # if not is_valid_server_address(args.server_address, args.port_number, args.timeout):
    #     print("\nERROR \t Incorrect input syntax: Server address is not valid")
    #     exit()

    if not args.hostname:
        print("\nERROR \t Incorrect input syntax: Please add a hostname")
        exit()
    if not is_valid_hostname(args.hostname):
        print("\nERROR \t Incorrect input syntax: Hostname is not valid")
        exit()
    
    #Action

    print("DnsClient sending request for", args.hostname)
    print("Server:", args.server_address)
    print("Request type:", args.type)

    response, elapsed_time, retries, query_size = send_dns_query(args.hostname, args.server_address, args.port_number, args.type, args.max_retries, args.timeout)

    print("Response received after " + str(elapsed_time) + " seconds ("+ str(retries) +" retries)")
 
    if response == None and retries == args.max_retries:
        print("ERROR \t Maximum number of retries "+ str(args.max_retries) +" exceeded")
        exit()
    
    response = decode_response(response, query_size)
    # hi = decode_message(binascii.hexlify(response).decode("utf-8"))
    # print(response)
    # print(hi)

if __name__ == "__main__":
    main()
