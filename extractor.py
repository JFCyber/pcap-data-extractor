from scapy.all import rdpcap

def extract_data_from_pcap(file_path, output_file):
    """
    Extracts IP addresses from a pcap file and saves them to a text file.

    Parameters:
    file_path (str): The path to the pcap file.
    output_file (str): The path to the output text file.
    """
    packets = rdpcap(file_path)
    ip_addresses = set()

    for packet in packets:
        if packet.haslayer('IP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            ip_addresses.add(ip_src)
            ip_addresses.add(ip_dst)

    with open(output_file, 'w') as f:
        for ip in ip_addresses:
            f.write(ip + '\n')

if __name__ == "__main__":
    file_path = r'C:/Users/jf_do/Desktop/Projects/pcap-data-extractor/my_capture.pcap'  # Replace with the actual path to your pcap file
    output_file = r'C:/Users/jf_do/Desktop/Projects/pcap-data-extractor/extracted_ips.txt'  # Replace with the desired output file path
    extract_data_from_pcap(file_path, output_file)
