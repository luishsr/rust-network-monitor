extern crate pcap;
extern crate pnet;
extern crate toml;
extern crate notify_rust;
extern crate crossterm;

use crossterm::{terminal, execute};
use crossterm::cursor::MoveTo;
use crossterm::terminal::ClearType;
use std::collections::HashMap;
use std::{fs, io, thread};
use std::io::stdout;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ip::{IpNextHeaderProtocols};
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use colored::*;
use notify_rust::Notification;
use serde::Deserialize;

struct IpStats {
    sent: u64,
    received: u64,
}

#[derive(Deserialize)]
struct Config {
    general: GeneralConfig,
    alert: AlertConfig,
}

#[derive(Deserialize)]
struct GeneralConfig {
    mode: String,
}

#[derive(Deserialize)]
struct AlertConfig {
    ip: String,
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

    // Load and parse the config
    let config_content = fs::read_to_string("config.toml").unwrap();
    let config: Config = toml::from_str(&config_content).unwrap();

    let chosen_device_name = &devices[choice - 1].name;

    let mut cap = pcap::Capture::from_device(chosen_device_name.as_str()).unwrap()
        .promisc(true)
        .snaplen(5000)
        .open().unwrap();


    let shared_ip_map = Arc::new(Mutex::new(HashMap::<String, IpStats>::new()));
    let ip_map_for_thread = Arc::clone(&shared_ip_map);

    if config.general.mode == "summary" {
        // Spawn a thread to handle the display
        thread::spawn(move || {
            loop {
                display_summary(&ip_map_for_thread.lock().unwrap());
                thread::sleep(Duration::from_millis(500));
            }
        });

        loop {
            if let Ok(packet) = cap.next() {
                if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
                    match ethernet_packet.get_ethertype() {
                        EtherTypes::Ipv4 => {
                            let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                            let src_ip = ipv4_packet.get_source().to_string();
                            let dst_ip = ipv4_packet.get_destination().to_string();
                            update_ip_stats(&mut shared_ip_map.lock().unwrap(), src_ip, true, packet.header.len);
                            update_ip_stats(&mut shared_ip_map.lock().unwrap(), dst_ip, false, packet.header.len);

                            // For alerts:
                            if ipv4_packet.get_source().to_string() == config.alert.ip {
                                send_alert(&config.alert.ip);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    while let Ok(packet) = cap.next() {


            if let Some(ethernet_packet) = EthernetPacket::new(&packet.data) {
                match ethernet_packet.get_ethertype() {
                    EtherTypes::Ipv4 => {
                        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                        match ipv4_packet.get_next_level_protocol() {
                            IpNextHeaderProtocols::Tcp => {
                                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {

                                    // Detailed mode: Log each packet
                                    if config.general.mode == "detailed" {
                                        println!("{}", format!("TCP Packet: {}:{} -> {}:{}; Len: {}",
                                                               ipv4_packet.get_source(),
                                                               tcp_packet.get_source(),
                                                               ipv4_packet.get_destination(),
                                                               tcp_packet.get_destination(),
                                                               packet.header.len
                                        ).bright_blue());
                                    }

                                    // For alerts:
                                    if ipv4_packet.get_source().to_string() == config.alert.ip {
                                        send_alert(&config.alert.ip);
                                    }
                                }
                            },
                            IpNextHeaderProtocols::Udp => {
                                if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {

                                    // Detailed mode: Log each packet
                                    if config.general.mode == "detailed" {
                                        println!("{}", format!("UDP Packet: {}:{} -> {}:{}; Len: {}",
                                                               ipv4_packet.get_source(),
                                                               udp_packet.get_source(),
                                                               ipv4_packet.get_destination(),
                                                               udp_packet.get_destination(),
                                                               packet.header.len
                                        ).green());
                                    }

                                    // For alerts:
                                    if ipv4_packet.get_source().to_string() == config.alert.ip {
                                        send_alert(&config.alert.ip);
                                    }
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

fn send_alert(ip: &str) {
    println!("ALERT! Traffic from IP {} ", ip);

    let _ = Notification::new()
        .summary("Network Monitoring Alert")
        .body(&format!("Traffic from IP {} ", ip))
        .show();//.unwrap();

}

fn update_ip_stats(ip_map: &mut HashMap<String, IpStats>, ip: String, is_source: bool, packet_size: u32) {
    let stats = ip_map.entry(ip).or_insert(IpStats { sent: 0, received: 0 });
    if is_source {
        stats.sent += packet_size as u64;
    } else {
        stats.received += packet_size as u64;
    }
}

fn display_summary(ip_map: &HashMap<String, IpStats>) {
    let mut stdout = stdout();
    execute!(stdout, terminal::Clear(ClearType::All), MoveTo(0, 0)).unwrap();

    println!("IP Address        | Packets Sent | Packets Received");
    println!("------------------+--------------+-----------------");
    for (ip, stats) in ip_map.iter() {
        println!("{:<18} | {:<12} | {}", ip, stats.sent, stats.received);
    }
}
