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

Note: You might need root access to run the application properly. If permission denied errors occur, grant access by doing:

      sudo setcap cap_net_raw=eip ./target/debug/{your_project_name}

Usage

- Run the tool:

      ./target/release/{your_project_name}

- Optional configurations:

  Use the config.toml within the root directory, as shown below, to customize a few parameters:

      [general]
      mode = "summary" # or "detailed"
  
      [alert]
      ip = "10.0.0.0"
     
  Mode: defines the level of logging shown in the console
  Alert: defines an alert to be shown whenever a packet arrives from a given IP address
  

