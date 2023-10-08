extern crate pcap;
extern crate pnet;

use std::collections::HashMap;
use std::io;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use colored::*;

#[derive(Hash, PartialEq, Eq, Debug)]
struct Flow {
    src_ip: String,
    dst_ip: String,
    src_port: u16,
    dst_port: u16,
    protocol: IpNextHeaderProtocol,
}

struct FlowStats {
    packets: u64,
    bytes: u64,
}

fn main() {
    // Dynamic interface selection
    let devices = pcap::Device::list().expect("Error retrieving device list");

    if devices.is_empty() {
        println!("No available network devices found.");
        return;
    }

    println!("Available network devices:");
    for (index, device) in devices.iter().enumerate() {
        println!("{}. {}", index + 1, device.name);
    }

    let mut choice = String::new();
    println!("Enter the number of the device you want to monitor:");
    io::stdin().read_line(&mut choice).expect("Failed to read line");

    let choice: usize = choice.trim().parse().expect("Please enter a valid number.");

    if choice < 1 || choice > devices.len() {
        println!("Invalid choice. Exiting.");
        return;
    }

    let chosen_device_name = &devices[choice - 1].name;

    let mut cap = pcap::Capture::from_device(chosen_device_name.as_str()).unwrap()
        .promisc(true)
        .snaplen(5000)
        .open().unwrap();

    let mut flow_map: HashMap<Flow, FlowStats> = HashMap::new();

    while let Ok(packet) = cap.next() {

        if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
            match ethernet_packet.get_ethertype() {
                EtherTypes::Ipv4 => {
                    let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                    match ipv4_packet.get_next_level_protocol() {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {

                                println!("{}", format!("TCP Packet: {}:{} -> {}:{}; Len: {}",
                                                       ipv4_packet.get_source(),
                                                       tcp_packet.get_source(),
                                                       ipv4_packet.get_destination(),
                                                       tcp_packet.get_destination(),
                                                       packet.header.len
                                ).bright_blue());

                                let flow = Flow {
                                    src_ip: ipv4_packet.get_source().to_string(),
                                    dst_ip: ipv4_packet.get_destination().to_string(),
                                    src_port: tcp_packet.get_source(),
                                    dst_port: tcp_packet.get_destination(),
                                    protocol: IpNextHeaderProtocols::Tcp,
                                };
                                update_flow_stats(&mut flow_map, flow, packet.header.len);
                            }
                        },
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {

                                println!("{}", format!("UDP Packet: {}:{} -> {}:{}; Len: {}",
                                                       ipv4_packet.get_source(),
                                                       udp_packet.get_source(),
                                                       ipv4_packet.get_destination(),
                                                       udp_packet.get_destination(),
                                                       packet.header.len
                                ).green());

                                let flow = Flow {
                                    src_ip: ipv4_packet.get_source().to_string(),
                                    dst_ip: ipv4_packet.get_destination().to_string(),
                                    src_port: udp_packet.get_source(),
                                    dst_port: udp_packet.get_destination(),
                                    protocol: IpNextHeaderProtocols::Udp,
                                };
                                update_flow_stats(&mut flow_map, flow, packet.header.len);
                            }
                        },
                        _ => {}
                    }
                },
                _ => {}
            }
        }
    }

}

fn update_flow_stats(flow_map: &mut HashMap<Flow, FlowStats>, flow: Flow, packet_size: u32) {
    let stat = flow_map.entry(flow).or_insert(FlowStats { packets: 0, bytes: 0 });
    stat.packets += 1;
    stat.bytes += packet_size as u64;
}
