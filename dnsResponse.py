import binascii
import socket


def decode_response(response, query_size):    

    message = binascii.hexlify(response).decode("utf-8")

    ID = message[0:4] # Id extracted
    FLAGS = message[4:8] # Flags extracted
    AA = int(bin(int(FLAGS, 16))[7])
    ERROR_CODE = int(FLAGS[3], 16)
    if ERROR_CODE == 1:
        print("\nERROR \t Format error: the name server was unable to interpret the query")
        exit()
    elif ERROR_CODE == 2:
        print("\nERROR \t Server failure: the name server was unable to process this query due to a problem with the name server")
        exit()
    elif ERROR_CODE == 3:
        print("NOTFOUND")
        exit()
    elif ERROR_CODE == 4:
        print("\nERROR \t Not implemented: the name server does not support the requested kind of query")
        exit()
    elif ERROR_CODE == 5:
        print("\nERROR \t Refused: the name server refuses to perform the requested operation for policy reasons")
        exit()
    

    QDCOUNT = message[8:12] # Number of questions extracted
    ANCOUNT = int(message[12:16], 16) # Number of answers extracted
    NSCOUNT = int(message[16:20], 16) # Number of records in Authoritative section extracted
    ARCOUNT = int(message[20:24], 16) # Number of records in Additional section

    # Main stuff start at query_size
    pointer = query_size

    print(NSCOUNT)
    print(AA)
    AUTH = "auth" if bool(AA) else "noauth"

    if ANCOUNT >= 1:
        print("***Answer Section (" + str(ANCOUNT) +" records)***")

        for i in range(0, ANCOUNT):

            POINTER = message[pointer: pointer+4]
            TYPE_RESPONSE = int(message[pointer+4: pointer+8], 16)
            RESPONSE_CLASS_IN = message[pointer+8: pointer+12]
            TTL = int(message[pointer+12:pointer+20], 16)
            RDLENGTH = int(message[pointer + 20:pointer + 24], 16)
            DATA = message[pointer+24: pointer+24+(RDLENGTH * 2)]

            pointer = pointer+24+(RDLENGTH * 2)

            if TYPE_RESPONSE == 1: #then A
                IP_ADDRESS = socket.inet_ntoa(bytes.fromhex(DATA))
                print("IP\t" + IP_ADDRESS + "\t" + str(TTL) + "\t" + AUTH)
            elif TYPE_RESPONSE == 2: #then NS
                DATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(DATA, 0, [])))
                print("NS \t " + DATA_decoded + " \t " + str(TTL) + "\t" + AUTH)
            elif TYPE_RESPONSE == 15: #then MX
                DATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(DATA, 0, [])))
                print("MX\t" + DATA_decoded + " \t " + str(TTL) + "\t" + AUTH)
            elif TYPE_RESPONSE == 5: #then CNAME
                DATA_decoded = ".".join(map(lambda p: binascii.unhexlify(p).decode('iso8859-1'), parse_parts(DATA, 0, [])))
                print("CNAME\t" + DATA_decoded + "\t" + str(TTL) + "\t" +AUTH)
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
