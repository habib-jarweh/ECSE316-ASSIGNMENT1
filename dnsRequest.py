import random

def build_dns_request(domain_name, qtype):

    # Generate a random 16-bit ID
    ID = random.randint(0, 65534)
        # QR OPCode  AA  TC  RD  RA  ZZ   RCode
        # 0  0000    0   0   1   0   000  0000
    FLAGS = 0b0000000100000000 
    QDCOUNT = 1  # Number of questions in the query
    ANCOUNT = 0  # Number of resource records in answer section
    NSCOUNT = 0  # Number of resource records in authority section
    ARCOUNT = 0  # Number of resource records in additional section

    #Handle domain name
    qname = bytearray()
    if not domain_name.startswith("www."):
        domain_name = "www." + domain_name
    
    for label in domain_name.split('.'):
        qname.append(len(label))
        qname.extend(label.encode('utf-8'))
    qname.append(0) # Finish query name will zero-length octet

    # Handle QTYPE
    if qtype == "A":
        QTYPE = 1
    elif qtype == "NS":
        QTYPE = 2
    else:
        QTYPE = 15
    qtype_bytes = QTYPE.to_bytes(2, byteorder='big')

    # Handle QCLASS
    QCLASS = 1
    qclass_bytes = QCLASS.to_bytes(2, byteorder='big')

    # Construct the DNS request packet header
    dns_request_packet = bytearray()
    dns_request_packet.extend(ID.to_bytes(2, byteorder='big'))
    dns_request_packet.extend(FLAGS.to_bytes(2, byteorder='big'))
    dns_request_packet.extend(QDCOUNT.to_bytes(2, byteorder='big'))
    dns_request_packet.extend(ANCOUNT.to_bytes(2, byteorder='big'))
    dns_request_packet.extend(NSCOUNT.to_bytes(2, byteorder='big'))
    dns_request_packet.extend(ARCOUNT.to_bytes(2, byteorder='big'))
    # Construct the rest of the DNS request packet
    dns_request_packet.extend(qname)
    dns_request_packet.extend(qtype_bytes)
    dns_request_packet.extend(qclass_bytes)

    return dns_request_packet


