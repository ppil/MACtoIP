#!/usr/bin/python
#
# ARP-less MAC to IP mapper
# Peter Pilarski

# https://dpkt.readthedocs.org/en/latest/index.html
import dpkt
import sys # exit, argv
from getopt import getopt, GetoptError # Option parsing
from os.path import isfile, abspath
from binascii import unhexlify # hex to binary
# Binary to ASCII IP, address family types (ip4, ip6)
from socket import inet_ntop, AF_INET, AF_INET6

srcOnly=0 # Ignore destination fields
verbose=0 # Print all the things, don't summarize

class App:
	def usage(self):
		print """Usage:
	-f <file>, --file <file>
		Specify pcap file to read from. (Required)
	-m <MAC>, --mac <MAC>
		MAC address to resolve. (Required)
	-s, --src-only
		Ignore destination addresses.
	-v, --verbose
		Print the IP found for every occurrence, instead of a list of 
		what IP addresses were seen.
	-h, --help
		I knew I shoulda taken that left turn at Albuquerque.
	"""

	def main(self):
		pcap, mac = self.readArgs() # Get CLI args
		self.parseCap(pcap, mac) 	# Do work
		
	def readArgs(self):
		global srcOnly, verbose
		try: # Don't die if this fails
			opts, args = getopt(sys.argv[1:], 'shvf:m:', ['file=','mac=','help','src-only','verbose'])
		except GetoptError as err:
			print str(err) 	# Print the error
			self.usage() 	# Print usage info
			sys.exit(2) 	# Now die

		for o, a in opts:	# For each option and argument
			if o in ("-f", "--file"):
				# Test if this is actually a file
				if isfile(a):
					# Store the absolute path
					pcap = abspath(a)
				else:
					print "Error: %s is not a valid file!" % a
					self.usage()
					sys.exit(1)
			elif o in ("-m", "--mac"):
				# Strip colons and convert to binary
				mac=unhexlify(a.replace(":",""))
			elif o in ("-s", "--src-only"):
				srcOnly=1
			elif o in ("-v", "--verbose"):
				verbose=1
			elif o in ("-h", "--help"):
				self.usage()
				sys.exit(1)
		# Require that user specifies a .pcap and MAC
		if (("-f" not in sys.argv[1:]) and ("--file" not in sys.argv[1:])):
			print "Error: no .pcap specified!"
			self.usage()
			sys.exit(1)
		elif (("-m" not in sys.argv[1:]) and ("--mac" not in sys.argv[1:])):
			print "Error: no MAC addr specified!"
			self.usage()
			sys.exit(1)
		return (pcap, mac)
	
	def parseCap(self, pcap, mac):
		global srcOnly, verbose
		addrs=[]					# List of IPs found
		fh = open(pcap)				# Open the pcap
		pcap=dpkt.pcap.Reader(fh)	# Read the pcap
		for ts, buf in pcap:		# For each timestamp, packet in pcap
			pos=0					# 0=none, 1=src, 2=dst
			dstMAC=0
			ip=""

			# Read Ethernet frame's source
			srcMAC = dpkt.ethernet.Ethernet(buf).src
			# Read Ethernet frame's destination
			if not srcOnly: dstMAC = dpkt.ethernet.Ethernet(buf).dst
			# Compare MACs, note positions
			if srcMAC == mac:
				pos=1
			elif dstMAC == mac:
				pos=2
			else:# No match
				continue# Skip this packet

			# Determine encapsulated protocol
			if dpkt.ethernet.Ethernet(buf).type==2048:# IPv4 ethertype (0x0800)
				addrFam=AF_INET
			elif dpkt.ethernet.Ethernet(buf).type==34525:# IPv6 ethertype (0x08DD)
				addrFam=AF_INET6
			else:# Not IP frame, skip packet
				continue
				
			# Get IP
			if pos==1:
				# Read IP source and convert to ACSII
				ip=inet_ntop(addrFam, dpkt.ethernet.Ethernet(buf).data.src)
			elif pos==2 and srcOnly==0:
				# Read IP dest and convert to ACSII
				ip=inet_ntop(addrFam, dpkt.ethernet.Ethernet(buf).data.dst)
			if ip:
				if verbose: print ip
				if ip not in addrs:# If this is a new ip
					addrs.append(ip)# Add it to the list
			# End of loop
		if verbose==0:
			for i in addrs:# For each IP addr found
				if i != "0.0.0.0" and i != "::":
					print i# Print the IP

App().main()
