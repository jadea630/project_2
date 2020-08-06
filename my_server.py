#Abraham Gale 2020
#feel free to add functions to this part of the project, just make sure that the get_dns_response function works
from resolver_backround import DnsResolver
import threading
import socket
import struct
import argparse
from sys import argv
from time import sleep
from helper_funcs import DNSQuery
import copy
import binascii

import typing

# b'\xac\xd9\x06N' =>


def send_udp_message(message, address, port):
    """send_udp_message sends a message to UDP server

    message should be a hexadecimal encoded string
    """

    server_address = (address, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message, server_address)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()
    return data

def QueryRootNS(raw_query):
	origin_query = DNSQuery(raw_query)

	query = DNSQuery()
	query.header["ID"] = origin_query.header["ID"]
	query.header["QDCOUNT"] = 1
	query.header["ARCOUNT"] = 1

	query.answers = copy.deepcopy(origin_query.answers)

	# Requests the NS record(s) for the domain name
	query.question = {'NAME': bytearray(b'.'), 'QTYPE': 2, 'QCLASS': 1}


	raw_response = send_udp_message(query.to_bytes(), "8.8.8.8", 53)

	response = DNSQuery(raw_response)

	ns_server_list = [x["RDATA"][0] for x in response.answers if x["RDLENGTH"] > 0]
	return ns_server_list
# query abc.xyz.edu.com
# 1. .com
# 2. .edu.com
# 3. .xyz.edu.com
def QueryNextNS(curr_addr, ns_list: typing.List[bytearray], id):

	next_ns_list = []

	for ns in ns_list:
		query = DNSQuery()

		query.header["ID"] = id

		query.header["QDCOUNT"] = 1
		query.header["ARCOUNT"] = 1

		query.answers = [{'NAME': bytearray(b'.'), 'TYPE': 41, 'CLASS': 4096, 'TTL': 32768, 'RDLENGTH': 0, 'RDATA': [b'']}]

		query.question["NAME"] = curr_addr + b"."
		query.question["QTYPE"] = 2
		query.question["QCLASS"] = 1


		raw_response = send_udp_message(query.to_bytes(), ns, 53)
		response = DNSQuery(raw_response)
		ns_server_list = [x["RDATA"][0] for x in response.answers if x["RDLENGTH"] > 0]
		next_ns_list.extend(ns_server_list)


	return next_ns_list

# dig @localhost -p 8081 google.com
class MyResolver(DnsResolver):
	def __init__(self, port):
		self.port = port
		#define variables and locks you will need here
		self.cache_lock = threading.Lock()
	def get_dns_response(self, query):

		# return send_udp_message(query, "8.8.8.8", 53)
		print(f"query:{query}")
		#input: A query and any state in self
		#returns: the correct response to the query obtained by asking DNS name servers
		#Your code goes here, when you change any 'self' variables make sure to use a lock

		raw_query = DNSQuery(query)
		whole_addr = raw_query.question["NAME"]

		addr_splits_list = whole_addr.split(b".")[0:-1]



		ns_server_list = QueryRootNS(query)

		next_ns_list = QueryNextNS(addr_splits_list[-1], ns_server_list, raw_query.header["ID"])



		# a = DNSQuery()
		# a.header['ID'] = q.header['ID']
		# a.header['QR'] = 1
		# a.header['RCODE'] = 2
		# print(a)
		# return a.to_bytes()
parser = argparse.ArgumentParser(description="""This is a DNS resolver""")
parser.add_argument('port', type=int, help='This is the port to connect to the resolver on',action='store')
args = parser.parse_args(argv[1:])
resolver = MyResolver(args.port)
resolver.wait_for_requests()

"""
1. 
msg0
"what's ip of google.com"

server => [root server] 8.8.8.8

a. 8.8.8.8 finds the answer; return to the client
b. if not, 
rsp0 
["9.9.9.9", "10.10.10.10"]

2.
msg1 
google.com
server => 8.8.8.8 ["9.9.9.9", "10.10.10.10"]

msg2
google.com

3. 
...

n.
=>
client

"""