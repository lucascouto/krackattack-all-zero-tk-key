#!/bin/bash
set -e

REPEATER=$1

tcpdump -i $REPEATER -w rogue_ap_capture.pcap