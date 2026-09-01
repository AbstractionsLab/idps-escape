#!/bin/bash

# Parse named parameters
for arg in "$@"; do
    case $arg in
        source_interface=*)
            source_interface="${arg#*=}"
            shift
            ;;
        source_ip=*)
            source_ip="${arg#*=}"
            shift
            ;;
        destination_interface=*)
            destination_interface="${arg#*=}"
            shift
            ;;
        destination_ip=*)
            destination_ip="${arg#*=}"
            shift
            ;;
        tunnel_ip=*)
            tunnel_ip="${arg#*=}"
            shift
            ;;
        tunnel_name=*)
            tunnel_name="${arg#*=}"
            shift
            ;;
        *)
            # Unknown parameter
            echo "Unknown parameter: $arg"
            exit 1
            ;;
    esac
done

# Check if all required parameters are provided
if [ -z "$source_interface" ] || [ -z "$source_ip" ] || [ -z "$destination_interface" ] || [ -z "$destination_ip" ] || [ -z "$tunnel_ip" ] || [ -z "$tunnel_name" ]; then
    echo "Usage: $0 source_interface=<Source_Interface> source_ip=<Source_IP> destination_interface=<Destination_Interface> destination_ip=<Destination_IP> tunnel_ip=<Tunnel_IP> tunnel_name=<Tunnel_Name>"
    exit 1
fi

# Print out the parameters
echo "Source Interface: $source_interface"
echo "Source IP: $source_ip"
echo "Destination Interface: $destination_interface"
echo "Destination IP: $destination_ip"
echo "Tunnel IP: $tunnel_ip"
echo "Tunnel Name: $tunnel_name"

# Add commands

# Create GRE tunnel interface with specified name
sudo ip link add "$tunnel_name" type gretap remote "$destination_ip" local "$source_ip" dev "$source_interface"

# Add IP address to the tunnel interface
sudo ip addr add "$tunnel_ip" dev "$tunnel_name"

# Set the tunnel interface up
sudo ip link set "$tunnel_name" up

# Add ingress qdisc to the source interface
sudo tc qdisc add dev "$source_interface" handle ffff: ingress

# Add filters to mirror traffic to the tunnel interface based on IP protocols 1 (ICMP), 6 (TCP), and 17 (UDP)
sudo tc filter add dev "$source_interface" parent ffff: protocol ip u32 match ip protocol 1 0xff action mirred egress mirror dev "$tunnel_name"
sudo tc filter add dev "$source_interface" parent ffff: protocol ip u32 match ip protocol 6 0xff action mirred egress mirror dev "$tunnel_name"
sudo tc filter add dev "$source_interface" parent ffff: protocol ip u32 match ip protocol 17 0xff action mirred egress mirror dev "$tunnel_name"

# Add root qdisc to the source interface
sudo tc qdisc add dev "$source_interface" handle 1: root prio

# Add ingress qdisc to the loopback interface
sudo tc qdisc add dev lo handle ffff: ingress

# Add filters to mirror traffic from the loopback interface to the source interface based on IP protocols 1 (ICMP), 6 (TCP), and 17 (UDP)
sudo tc filter add dev "$source_interface" parent 1: protocol ip u32 match ip protocol 1 0xff action mirred egress mirror dev lo
sudo tc filter add dev "$source_interface" parent 1: protocol ip u32 match ip protocol 6 0xff action mirred egress mirror dev lo
sudo tc filter add dev "$source_interface" parent 1: protocol ip u32 match ip protocol 17 0xff action mirred egress mirror dev lo

# Add filters to mirror traffic from the loopback interface to the tunnel interface based on IP protocols 1 (ICMP), 6 (TCP), and 17 (UDP)
sudo tc filter add dev lo parent ffff: protocol ip u32 match ip protocol 1 0xff action mirred egress mirror dev "$tunnel_name"
sudo tc filter add dev lo parent ffff: protocol ip u32 match ip protocol 6 0xff action mirred egress mirror dev "$tunnel_name"
sudo tc filter add dev lo parent ffff: protocol ip u32 match ip protocol 17 0xff action mirred egress mirror dev "$tunnel_name"

# End of script