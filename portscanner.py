import argparse
import ipaddress
# importing the logging module, and the line just below it have the purpose of suppressing the Scapy warning message (or something analogous) of "WARNING: Mac address to reach destination not found. Using broadcast." Makes the output cleaner. 
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import scapy.layers.inet

# colorama is for coloring some of the output shown on the screen - specifically, the ports
# Red for closed ports, green for open ports, and yellow for unknown ports
from colorama import init as colorama_init
from colorama import Fore
from colorama import Style

colorama_init()

parser = argparse.ArgumentParser(
    description="This is a CLI-based port scanner. Takes an IPv4 address/range, a port/port range, and scans the port(s) to determine if it/they are open."
)


protocolsToScanGroup = parser.add_mutually_exclusive_group(required=True)

parser.add_argument("-a", "--address", metavar="<IP address/range>", type=str,
                          help="An individual IP address or range of IP addresses to scan. Use a comma to separate individual IPv4 addresses (no spaces, you have to write out both IPs in full); use a hyphen (-) to specify an arbitrary range of addresses; use a forward slash (/) to specify a CIDR subnet to be scanned.", required=True)

parser.add_argument("-p", "--port", metavar="<port number/range>", type=str,
                    help="Port/port range, to scan. Use a comma to separate individual ports (no spaces); use a hyphen (-) to get a range of ports", required=True)

protocolsToScanGroup.add_argument(
    "-t", "--tcp", action="store_true", help="Carry out a TCP SYN Scan for the given port/range of ports")
protocolsToScanGroup.add_argument(
    "-u", "--udp", action="store_true", help="Carry out a UDP Ping Scan for the given port/range of ports")
protocolsToScanGroup.add_argument(
    "-b", "--both", action="store_true", help="Carry out both a TCP SYN and UDP Ping Scan")


def printPortScanResults(scanType: str, portScanResults: list):
    print(f"\n{Style.BRIGHT}{scanType}Scan Results{Style.RESET_ALL}")
    for individualResult in portScanResults:
        print(f"--------\nResults for IP address {individualResult[0]}")
        print(f"🟢 {Style.BRIGHT}Open port(s): {Fore.GREEN}{individualResult[1]}{Style.RESET_ALL}")
        print(f"🔴 {Style.BRIGHT}Closed port(s): {Fore.RED}{individualResult[2]}{Style.RESET_ALL}")
        if len(individualResult) == 4 and scanType == "UDP":
            print(f"🟡 {Style.BRIGHT}Status unknown port(s): {Fore.YELLOW}{individualResult[3]}{Style.RESET_ALL}")


def udpPortScan(hostsList: list, portList: list):
    print("\nBeginning UDP Ping Scan...")
    udpScanResults = []
    for address in hostsList:
        openPortsList = []
        closedPortsList = []
        unkownStatusPortsList = []

        print(f"\nRunning UDP Ping Scan of IP Address: {address}")

        for port in portList:
            print(f"Scanning port: {port}")
            portScanResult = sr1(scapy.layers.inet.IP(dst=f"{address}")/scapy.layers.inet.UDP(
                sport=RandShort(), dport=port), timeout=1, verbose=0, chainCC=True, threaded=True)
            if portScanResult is not None and portScanResult.haslayer(scapy.layers.inet.ICMP):
                closedPortsList.append(port)

            elif portScanResult is not None and portScanResult.haslayer(scapy.layers.inet.UDP):
                openPortsList.append(port)

            else:
                unkownStatusPortsList.append(port)

        udpScanResults.append([str(address), str(openPortsList), str(
            closedPortsList), str(unkownStatusPortsList)])
    printPortScanResults("UDP", udpScanResults)


def synScanIPAddress(hostsList: list, portList: list):
    print("\nBeginning TCP SYN Scan...")
    synScanResults = []
    for address in hostsList:
        openPortsList = []
        closedPortsList = []

        print(f"\nRunning TCP SYN Scan of IP address: {address}")

        for port in portList:
            print(f"Scanning port: {port}")
            portScanResult = sr1(scapy.layers.inet.IP(dst=f"{address}")/scapy.layers.inet.TCP(
                sport=RandShort(), dport=port, flags="S"), timeout=1, verbose=0, chainCC=True, threaded=True)
            if portScanResult is not None and portScanResult[scapy.layers.inet.TCP].flags == "SA":
                openPortsList.append(port)
            else:
                closedPortsList.append(port)

        synScanResults.append(
            [str(address), str(openPortsList), str(closedPortsList)])
    printPortScanResults("TCP", synScanResults)

# Function to handle the port number(s) that a user may pass to the program
# The values could be comma-separated, like 53,80,443, and this function would split and return the list [53, 80, 443]
# Alternatively, when a user uses a hyphen, as in 120-124, the function looks for the hyphen to split the list, and returns the range [120-124]


def convertToNumber(userInput: str) -> list:
    rangeOfPorts = []
    if userInput.find(",") >= 1:
        portRange = userInput.split(",")
        for value in portRange:
            rangeOfPorts.append(int(value))
        print(f"{Style.BRIGHT}---Port(s) to scan: {rangeOfPorts}{Style.RESET_ALL}")
        return rangeOfPorts

    elif userInput.find("-") >= 1:
        portRange = userInput.split("-", 1)
        for value in portRange:
            rangeOfPorts.append(int(value))
        print(f"{Style.BRIGHT}---Port(s) to scan: {list(range(rangeOfPorts[0], rangeOfPorts[1]+1))}{Style.RESET_ALL}")
        return list(range(rangeOfPorts[0], rangeOfPorts[1]+1))

    else:
        rangeOfPorts.append(int(userInput.strip()))
        return rangeOfPorts


def processIPAddressInput(userInput: str) -> list:
    ipAddressList = []
    if userInput.find(",") >= 1:
        ipRange = userInput.split(",")
        for value in ipRange:
            ipAddressList.append(ipaddress.ip_address(value))
        print(
            f"\n{Style.BRIGHT}---IP Address(es) to scan: {[str(ipaddress) for ipaddress in ipAddressList]}{Style.RESET_ALL}")
        return ipAddressList

    elif userInput.find("/") >= 1:
        ipRange = userInput.split("/")
        ipAddressRange = ipaddress.ip_network(f'{ipRange[0]}/{ipRange[1]}', strict=False)
        for address in ipAddressRange.hosts():
            ipAddressList.append(address)
        print(
            f"\n{Style.BRIGHT}---IP Address(es) to scan: {[str(ipaddress) for ipaddress in ipAddressList]}{Style.RESET_ALL}")
        return ipAddressList
    
    # This section is meant to allow for users to enter values like 10.10.10.4-7, and the program is to divide that input and return the corresponding list of IP addresses
    elif userInput.find("-") >= 1:
        ipRange = userInput.split("-")
        networkAndHostValues = userInput.rsplit(".", 1)
        rangeOfHosts = networkAndHostValues[1].split("-")
        for value in range(int(rangeOfHosts[0]), (int(rangeOfHosts[1])+1)):
            ipAddressList.append(ipaddress.ip_address(f"{networkAndHostValues[0]}.{value}"))
        print(
            f"\n{Style.BRIGHT}---IP Address(es) to scan: {[str(ipaddress) for ipaddress in ipAddressList]}{Style.RESET_ALL}")
        return ipAddressList
    
    else:
        ipAddressList.append(ipaddress.ip_address(userInput))
        return ipAddressList


def processReceivedArguments():
    receivedArguments = parser.parse_args()

    address = receivedArguments.address
    portRange = receivedArguments.port
    tcpFlag = receivedArguments.tcp
    udpFlag = receivedArguments.udp
    bothFlag = receivedArguments.both

    try:
        if tcpFlag and address:
            synScanIPAddress(processIPAddressInput(
                address), convertToNumber(portRange))
        if udpFlag and address:
            udpPortScan(processIPAddressInput(address),
                        convertToNumber(portRange))
        if bothFlag and address:
            synScanIPAddress(processIPAddressInput(
                address), convertToNumber(portRange))
            udpPortScan(processIPAddressInput(address),
                        convertToNumber(portRange))
    except:
        print("Error: Incorrect flags set.")

if __name__ == "__main__":
    processReceivedArguments()


