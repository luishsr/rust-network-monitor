# rust-network-monitor
A Network Traffic Monitor built in Rust (work in progress) for learning purposes

Network Monitoring Tool in Rust

Network monitoring is crucial for understanding and optimizing network behavior. Using Rust, we've developed a network monitoring tool that offers both safety and performance. 
This document provides an overview and instructions on how to use this tool.

You can read the complete implementation guide here: 

Overview

The tool captures packets, analyzes them, and offers various features like filtering, alerting, and flow analysis. It's built using Rust, leveraging libraries such as pcap, pnet, and notify-rust.
Features

    Packet Capturing: Capture and analyze packets on any network interface.
    Flow Analysis: Understand broader network traffic patterns.
    Alerts: Receive notifications based on specific network events.
    Filters: Capture specific types of traffic based on predefined criteria.

Getting Started

Prerequisites

- Rust (latest stable version recommended)
- libpcap installed on your system
- Network interface for packet capturing (e.g., eth0)

Installation

- Clone the repository:

      git clone https://github.com/luishsr/rust-network-monitor.git

- Navigate to the directory:

      cd network-monitoring-rust

Build the project:

    cargo build --release

The executable will be available in the target/release directory.

Usage

- Run the tool:

      ./target/release/network-monitoring-rust

By default, it will capture packets on the eth0 interface. You can configure various aspects, such as the network interface, filters, and alert criteria, by modifying the configuration in the main application.

Advanced Features

Flow Analysis

Group packets into flows based on source/destination IPs, ports, and protocol, and maintain statistics like the number of packets and bytes for each flow.

Alerts

Get alerted when specific network conditions are met. This can be an essential source of information during network threats or malfunctions.
Filters

Apply filters to capture only specific types of traffic. This helps in narrowing down the traffic to be analyzed, especially in busy networks.

