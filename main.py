import socket
from scapy.all import sr1, IP, TCP, send
import json
import sqlite3
from flask import Flask, request, jsonify
import ipaddress

# Function to scan an IP for specified ports using SYN scan
def scan_ip(ip, ports):
    open_ports = []  # List to store open ports
    for port in ports:  # Loop through the specified ports
        syn_packet = IP(dst=ip) / TCP(dport=port, flags='S')  # Create a SYN packet
        response = sr1(syn_packet, timeout=1, verbose=False)  # Send the packet and wait for a response
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:  # Check if SYN-ACK received
            open_ports.append(port)  # Add port to the list of open ports
            rst_packet = IP(dst=ip) / TCP(dport=port, flags='R')  # Create a RST packet to close connection
            send(rst_packet, verbose=False)  # Send the RST packet
    return open_ports

# Function to get the banner from an open port
def get_banner(ip, port):
    try:
        s = socket.socket()  # Create a socket
        s.settimeout(2)  # Set a timeout of 2 seconds
        s.connect((ip, port))  # Connect to the port
        banner = s.recv(1024)  # Receive the banner
        return banner.decode().strip()  # Decode and return the banner
    except:
        return None  # Return None if unable to get the banner

# Function to scan a network range
def scan_network(ip_list, ports):
    results = []  # List to store scan results
    for ip in ip_list:  # Loop through the IP list
        open_ports = scan_ip(ip, ports)  # Scan the IP for open ports
        banners = {port: get_banner(ip, port) for port in open_ports}  # Get banners for open ports
        results.append({
            'ip': ip,
            'open_ports': open_ports,
            'banners': banners
        })
        print(ip,ports)
    return results

# Function to store scan results in a SQLite database
def store_results_in_db(results):
    conn = sqlite3.connect('scan_results.db')  # Connect to the SQLite database
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS scan_results 
                 (ip TEXT, port INTEGER, banner TEXT)''')  # Create table if it doesn't exist
    for result in results:
        ip = result['ip']
        for port, banner in result['banners'].items():
            c.execute("INSERT INTO scan_results (ip, port, banner) VALUES (?, ?, ?)",
                      (ip, port, banner))  # Insert scan results into the table
    conn.commit()  # Commit the transaction
    conn.close()  # Close the connection

# Function to query the database
def query_db(query, args=(), one=False):
    conn = sqlite3.connect('scan_results.db')  # Connect to the SQLite database
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute(query, args)  # Execute the query
    rv = cur.fetchall()  # Fetch all results
    conn.close()  # Close the connection
    return (rv[0] if rv else None) if one else rv

# Flask app for search API
app = Flask(__name__)

@app.route('/search', methods=['GET'])
def search():
    ip = request.args.get('ip')  # Get IP parameter from request
    port = request.args.get('port')  # Get port parameter from request
    query = "SELECT * FROM scan_results WHERE 1=1"
    if ip:
        query += f" AND ip = '{ip}'"  # Add IP filter to query
    if port:
        query += f" AND port = {port}"  # Add port filter to query
    results = query_db(query)  # Query the database
    return jsonify([dict(ix) for ix in results])  # Return results as JSON

# Function to parse IP ranges from a file
def parse_ip_ranges(file_path):
    ip_list = []  # List to store individual IP addresses
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if '-' in line:  # Handle IP range notation
                start_ip, end_ip = line.split('-')
                start_ip = ipaddress.IPv4Address(start_ip)
                end_ip = ipaddress.IPv4Address(end_ip)
                for ip_int in range(int(start_ip), int(end_ip) + 1):
                    ip_list.append(str(ipaddress.IPv4Address(ip_int)))
            elif '/' in line:  # Handle CIDR notation
                network = ipaddress.ip_network(line, strict=False)
                for ip in network:
                    ip_list.append(str(ip))
            else:
                ip_list.append(line)  # Add individual IP
    return ip_list

if __name__ == "__main__":
    # Step 1: Parse IP ranges from a file
    ip_list = parse_ip_ranges("ip_ranges.txt")  # Replace with your IP ranges file path
    print(len(ip_list))
    # Step 2: Get user input for ports to scan
    ports_input = input("Enter the ports to scan (separate multiple ports by commas): ")
    ports = [int(port.strip()) for port in ports_input.split(",")]

    # Step 3: Scan the network
    scan_results = scan_network(ip_list, ports)  # Perform the scan
    with open("scan_results.json", "w") as f:
        json.dump(scan_results, f, indent=4)  # Save scan results to a JSON file

    # Step 4: Store results in the database
    with open("scan_results.json", "r") as f:
        scan_results = json.load(f)
    store_results_in_db(scan_results)  # Store results in SQLite database