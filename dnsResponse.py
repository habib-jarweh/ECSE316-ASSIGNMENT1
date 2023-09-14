import binascii
import socket
from collections import OrderedDict

def decode_response(response, query_size):    
    message = binascii.hexlify(response).decode("utf-8")

    ID = message[0:4] # Id extracted
    FLAGS = message[4:8] # Flags extracted
    QDCOUNT = message[8:12] # Number of questions extracted
    ANCOUNT = int(message[12:16], 16) # Number of answers extracted
    NSCOUNT = int(message[16:20], 16) # Number of records in Authoritative section extracted
    ARCOUNT = int(message[20:24], 16) # Number of records in Additional section

    # Main stuff start at query_size

    POINTER = message[query_size: query_size+4]
    TYPE_RESPONSE = int(message[query_size+4: query_size+8], 16)
    RESPONSE_CLASS_IN = message[query_size+8: query_size+12]
    TTL = int(message[query_size+12:query_size+20], 16)
    RDLENGTH = int(message[query_size + 20:query_size + 24], 16)
    DATA = message[query_size+24: query_size+24+(RDLENGTH * 2)]

    if ANCOUNT >= 1:
        print("***Answer Section (" + str(ANCOUNT) +" records)***")

    
    auth = "auth" if NSCOUNT else "noauth"

    if TYPE_RESPONSE == 1: #then A
        IP_ADDRESS = socket.inet_ntoa(bytes.fromhex(DATA))
        print("IP\t" + IP_ADDRESS + "\t" + str(TTL) + "\t" + auth)
    elif TYPE_RESPONSE == 2: #then NS
        DATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(DATA, 0, [])))
        print("NS \t " + DATA_decoded + " \t " + str(TTL) + "\t" + auth)
    elif TYPE_RESPONSE == 15: #then MX
        DATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(DATA, 0, [])))
        print("MX\t" + DATA_decoded + " \t " + str(TTL) + "\t" + auth)
    elif TYPE_RESPONSE == 5: #then CNAME
        DATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(DATA, 0, [])))
        print("CNAME\t" + DATA_decoded + "\t" + str(TTL) + "\t" +auth)
    else:
        print("NOTFOUND")

    
    if ARCOUNT >= 1:
        print("***Additional Section (" + str(ARCOUNT) +" records)***")

#this function has been taken from open-source code: https://gist.github.com/mrpapercut/92422ecf06b5ab8e64e502da5e33b9f7
def parse_parts(message, start, parts):
    part_start = start + 2
    part_len = message[start:part_start]
    
    if len(part_len) == 0:
        return parts
    
    part_end = part_start + (int(part_len, 16) * 2)
    parts.append(message[part_start:part_end])

    if message[part_end:part_end + 2] == "00" or part_end > len(message):
        return parts
    else:
        return parse_parts(message, part_end, parts)
