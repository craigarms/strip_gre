import argparse
import sys
import os
from scapy.all import *

def strip_gre_layer(packet):
    if packet.haslayer(GRE):
        packet = packet[GRE].payload
    return packet

def main(input_file, output_file):
    packets = rdpcap(input_file)
    stripped_packets = [strip_gre_layer(pkt) for pkt in packets if pkt.haslayer(GRE)]
    wrpcap(output_file, stripped_packets)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Remove the GRE layer from a PCAP file.")
    parser.add_argument("input_file", help="The name of the input PCAP file.")
    parser.add_argument("output_file", help="The name of the output PCAP file.")
    args = parser.parse_args()

    if not os.path.isfile(args.input_file):
        print("Error: Input file '%s' does not exist." % args.input_file)
        sys.exit(1)

    main(args.input_file, args.output_file)

