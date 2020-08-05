#Abraham Gale 2020
#feel free to add functions to this part of the project, just make sure that the get_dns_response function works
"""
labels      63 octets or less
names       255 octets or less
TTL         pos value of signed 32 bit a number (how long to live in cache before removing from cache)
UDP msg     512 octets or less

NAME        compressed or uncompressed (variable length, must parse to see how long)
RDATA       (variable legnth not a fixed size)

So a query has 3 fields:
    QNAME
    QTYPE
    QCLASS

These 3 fields are your KEY, meaning you need to find a query with these matching keys. However you need to account for
some special cases such as * in the fields QTYPE and QCLASS which means any type (aka meaning it must match just the name)

Compressed names are only used for the query, when storing and sending to others it must be uncompressed

Import time to check the time for a request that way you can implement TTL

if Truncated bit is 1 then you need to resend as TCP because the message is too long for UDP

***
Break down each part of the query using a function so its cleaner and easier, it will probably
be 5 functions total and 5 to build it back up

Here are two good nameservers for your SBELT:      172.16.7.7     128.6.1.1
As per the RFC it should also include two of the root name servers whose ip address can be found here https://en.wikipedia.org/wiki/Root_name_server
Before I advised you to use the nameservers from the grep command, these are the ones I got from my grep command, but since yours may differ just use these.

"""
from resolver_backround import DnsResolver
import threading
import socket
import struct
import argparse
from sys import argv
from time import sleep
from helper_funcs import DNSQuery
import typing
import copy


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

		
		# yahoo.com.
		# ns1.yahoo.com.
		# com. not work
		# check dig how to send .com request
 		# let DIG send dig nan-zhou.com @localhost -p 8081 +trace first
		# return a RESPONSE of ROOT SERVER
		# then，DIG will ask your SERVER，this time he will ask .com，
		# comparing your .com with .com from dig send, what difference they have
		
		raw_response = send_udp_message(query.to_bytes(), ns, 53)
		response = DNSQuery(raw_response)
		ns_server_list = [x["RDATA"][0] for x in response.answers if x["RDLENGTH"] > 0]
		next_ns_list.extend(ns_server_list)
		print(next_ns_list)



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
