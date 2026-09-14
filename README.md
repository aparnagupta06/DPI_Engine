# DPI Engine --- Packet Inspection and Traffic Filtering

## Overview

DPI Engine is a C++17 application for examining packets stored in PCAP
captures. It reads captured traffic, decodes the relevant network
headers, associates packets with flows, identifies applications or
domains from visible protocol information, applies configurable blocking
rules, and writes permitted packets into a new PCAP file.

The project contains two implementations:

-   **Single-threaded implementation:** `src/main_working.cpp`
-   **Parallel implementation:** `src/dpi_mt.cpp`

The first is intended to make the processing pipeline easier to
understand, while the second divides the work among multiple processing
threads for larger captures.

------------------------------------------------------------------------

## Contents

-   [DPI in a Nutshell](#dpi-in-a-nutshell)
-   [Networking Concepts Used by the
    Engine](#networking-concepts-used-by-the-engine)
    -   [Protocol Layers](#protocol-layers)
    -   [Packet Encapsulation](#packet-encapsulation)
    -   [Five-Tuple](#five-tuple)
    -   [SNI and HTTPS](#sni-and-https)
-   [System at a Glance](#system-at-a-glance)
-   [Repository Layout](#repository-layout)
-   [Single-Thread Processing
    Pipeline](#single-thread-processing-pipeline)
-   [Parallel Processing Pipeline](#parallel-processing-pipeline)
-   [Component Reference](#component-reference)
-   [TLS SNI Inspection](#tls-sni-inspection)
-   [Traffic Blocking](#traffic-blocking)
-   [Compilation and Execution](#compilation-and-execution)
-   [Reading the Program Output](#reading-the-program-output)
-   [Possible Extensions](#possible-extensions)
-   [Project Takeaways](#project-takeaways)

------------------------------------------------------------------------

# DPI in a Nutshell

**Deep Packet Inspection (DPI)** means examining network traffic beyond
the basic addressing information in packet headers. A conventional
firewall may make a decision using source/destination IP addresses and
ports, whereas a DPI system can inspect application-level information
carried by the packet.

Typical applications include:

-   **Internet service providers:** identifying and controlling
    particular applications such as BitTorrent.
-   **Corporate networks:** restricting services such as social-media
    platforms.
-   **Parental-control systems:** preventing access to selected
    websites.
-   **Security systems:** detecting suspicious traffic, malware, or
    intrusion attempts.

In this project, a saved network capture follows this general path:

``` text
                 +----------------------+
                 |      DPI Engine      |
                 |----------------------|
 PCAP ---------->| Parse packet         |----------> Output PCAP
                 | Track connection     |    allowed traffic
                 | Identify application |
                 | Apply filtering rules|
                 | Produce statistics   |
                 +----------------------+
```

The engine can therefore use information such as an IP address,
application classification, or detected domain when deciding whether
traffic should be retained.

------------------------------------------------------------------------

# Networking Concepts Used by the Engine

## Protocol Layers

A packet processed by the application contains information from several
networking layers:

``` text
+-----------------------------------------------------------+
| Application Layer  | HTTP, TLS, DNS                       |
+-----------------------------------------------------------+
| Transport Layer    | TCP, UDP                             |
+-----------------------------------------------------------+
| Network Layer      | IPv4 addressing and routing          |
+-----------------------------------------------------------+
| Data Link Layer    | Ethernet / MAC addressing             |
+-----------------------------------------------------------+
```

The DPI program moves upward through these layers. Ethernet information
is decoded first, followed by IPv4 information, then TCP or UDP details,
and finally application-related payload information where applicable.

------------------------------------------------------------------------

## Packet Encapsulation

Network protocols are nested. A typical Ethernet/IPv4/TCP packet can be
visualized as:

``` text
+----------------------------------------------------------------+
| Ethernet Header                                                |
|  +----------------------------------------------------------+  |
|  | IPv4 Header                                               |  |
|  |  +-----------------------------------------------------+ |  |
|  |  | TCP Header                                          | |  |
|  |  |  +-----------------------------------------------+  | |  |
|  |  |  | Application Payload                           |  | |  |
|  |  |  | e.g. TLS Client Hello containing SNI          |  | |  |
|  |  |  +-----------------------------------------------+  | |  |
|  |  +-----------------------------------------------------+ |  |
|  +----------------------------------------------------------+  |
+----------------------------------------------------------------+
```

For the common Ethernet/IPv4/TCP case, the minimum header sizes are:

-   Ethernet: **14 bytes**
-   IPv4: **20 bytes**, excluding optional fields
-   TCP: **20 bytes**, excluding optional fields
-   Payload: variable length

These offsets are not universally fixed because IP and TCP headers can
contain optional fields, so the parser determines the appropriate header
lengths.

------------------------------------------------------------------------

## Five-Tuple

The engine represents a network flow using five values:

  Attribute          Example            Role
  ------------------ ------------------ --------------------------------------
  Source IP          `192.168.1.100`    Origin of the traffic
  Destination IP     `172.217.14.206`   Remote endpoint
  Source Port        `54321`            Originating service/application port
  Destination Port   `443`              Destination service
  Protocol           `TCP (6)`          Transport protocol

The combination is called the **five-tuple**.

It is important because:

1.  Packets carrying the same five-tuple are treated as belonging to one
    flow.
2.  The flow table can retain state between packets.
3.  Once a flow is classified as blocked, later packets belonging to
    that flow can also be rejected.
4.  In the parallel implementation, the tuple determines which
    processing path handles the packet.

------------------------------------------------------------------------

## SNI and HTTPS

**Server Name Indication (SNI)** is a TLS extension sent as part of the
Client Hello. For a conventional TLS connection, the browser can send
the requested hostname in this part of the handshake before the
encrypted application data begins.

For example:

``` text
TLS Client Hello
 |
 +-- TLS version
 +-- Random value
 +-- Cipher suites
 +-- Other extensions
 +-- SNI
      |
      +-- Hostname: www.youtube.com
```

The engine uses this visible hostname to associate HTTPS flows with
applications such as YouTube, Facebook, or Google.

The important limitation is that this mechanism depends on finding the
hostname in the TLS Client Hello. The application payload exchanged
later in the encrypted session is not inspected or decrypted by this
project.

------------------------------------------------------------------------

# System at a Glance

The complete offline processing model is:

``` text
                  Wireshark / capture source
                              |
                              v
                       input.pcap
                              |
                              v
                  +-----------------------+
                  |      PCAP Reader      |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  |    Packet Parser      |
                  | Ethernet / IPv4 / TCP |
                  |          / UDP         |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  |    Flow Association   |
                  |      Five-Tuple       |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  | Application / SNI     |
                  | Classification        |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  |     Rule Checking     |
                  | IP / App / Domain     |
                  +-----------+-----------+
                              |
                    +---------+---------+
                    |                   |
                  blocked             allowed
                    |                   |
                  discard               v
                                    output.pcap
```

The multi-threaded implementation inserts load-balancing and fast-path
stages between packet reading and final output.

------------------------------------------------------------------------

# Repository Layout

``` text
packet_analyzer/
|
+-- include/
|   +-- pcap_reader.h
|   +-- packet_parser.h
|   +-- sni_extractor.h
|   +-- types.h
|   +-- rule_manager.h
|   +-- connection_tracker.h
|   +-- load_balancer.h
|   +-- fast_path.h
|   +-- thread_safe_queue.h
|   +-- dpi_engine.h
|
+-- src/
|   +-- pcap_reader.cpp
|   +-- packet_parser.cpp
|   +-- sni_extractor.cpp
|   +-- types.cpp
|   +-- main_working.cpp
|   +-- dpi_mt.cpp
|   +-- other supporting implementation files
|
+-- generate_test_pcap.py
+-- test_dpi.pcap
+-- README.md
```

### Responsibilities of the main files

  -----------------------------------------------------------------------
  File                                Responsibility
  ----------------------------------- -----------------------------------
  `pcap_reader.*`                     Opening and reading PCAP captures

  `packet_parser.*`                   Decoding Ethernet, IP, TCP, and UDP
                                      information

  `sni_extractor.*`                   Looking for TLS SNI and HTTP Host
                                      information

  `types.*`                           Common structures, application
                                      types, and classification helpers

  `rule_manager.*`                    Blocking-rule management for the
                                      parallel implementation

  `connection_tracker.*`              Maintaining flow state

  `load_balancer.*`                   Distributing packets to fast-path
                                      workers

  `fast_path.*`                       Performing the main DPI processing

  `thread_safe_queue.*`               Synchronizing producer/consumer
                                      communication

  `dpi_engine.*`                      Main orchestration support

  `main_working.cpp`                  Easier-to-follow sequential
                                      implementation

  `dpi_mt.cpp`                        Multi-threaded implementation

  `generate_test_pcap.py`             Produces sample capture data
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# Single-Thread Processing Pipeline

The sequential version in `main_working.cpp` processes one packet at a
time. The stages below describe what happens to a packet.

## 1. Open and Validate the Capture

The PCAP reader is initialized approximately as follows:

``` cpp
PcapReader reader;
reader.open("capture.pcap");
```

Opening the capture involves reading the global PCAP header and checking
that the file has a valid format.

A traditional PCAP contains:

``` text
+-----------------------------+
| Global Header (24 bytes)    |
+-----------------------------+
| Packet Header (16 bytes)    |
| Packet Data                 |
+-----------------------------+
| Packet Header (16 bytes)    |
| Packet Data                 |
+-----------------------------+
|             ...             |
+-----------------------------+
```

The global header appears once. Every captured packet then has its own
packet header followed by the saved bytes.

------------------------------------------------------------------------

## 2. Obtain the Next Packet

The reader repeatedly requests packets:

``` cpp
while (reader.readNextPacket(raw)) {
    // raw.data  -> packet bytes
    // raw.header -> timestamp and packet lengths
}
```

For every packet:

1.  A 16-byte packet header is read.
2.  The number of bytes specified by `incl_len` is read.
3.  The resulting data is stored in the raw-packet representation.
4.  The loop ends when there are no more packets.

------------------------------------------------------------------------

## 3. Decode the Protocol Headers

The raw packet is passed to the parser:

``` cpp
PacketParser::parse(raw, parsed);
```

For an ordinary Ethernet/IPv4/TCP packet, the parser obtains information
corresponding to:

``` text
Raw bytes
+------------------------------------------------+
| Ethernet | IPv4 | TCP | Payload                |
+------------------------------------------------+
     |         |      |
     |         |      +-- ports, sequence, flags
     |         +--------- addresses, protocol, TTL
     +------------------- MAC addresses, EtherType
```

A parsed result can contain values such as:

``` text
source MAC       = 00:11:22:33:44:55
destination MAC  = aa:bb:cc:dd:ee:ff
source IP        = 192.168.1.100
destination IP   = 172.217.14.206
source port      = 54321
destination port = 443
protocol         = 6 (TCP)
has_tcp          = true
```

### Ethernet fields

The Ethernet header contains:

``` text
Bytes 0-5   : Destination MAC
Bytes 6-11  : Source MAC
Bytes 12-13 : EtherType
```

For IPv4, the EtherType is `0x0800`.

### IPv4 fields

Relevant IPv4 positions include:

``` text
Byte 0       : Version + IHL
Byte 8       : TTL
Byte 9       : Protocol
Bytes 12-15  : Source address
Bytes 16-19  : Destination address
```

Protocol number `6` denotes TCP and `17` denotes UDP.

### TCP fields

The parser reads fields such as:

``` text
Bytes 0-1    : Source port
Bytes 2-3    : Destination port
Bytes 4-7    : Sequence number
Bytes 8-11   : Acknowledgment number
Byte 12      : Data offset
Byte 13      : TCP flags
```

The parser also handles UDP when the packet's transport protocol
indicates UDP.

------------------------------------------------------------------------

## 4. Associate the Packet with a Flow

A five-tuple is constructed from the parsed packet:

``` cpp
FiveTuple tuple;

tuple.src_ip    = parseIP(parsed.src_ip);
tuple.dst_ip    = parseIP(parsed.dest_ip);
tuple.src_port  = parsed.src_port;
tuple.dst_port  = parsed.dest_port;
tuple.protocol  = parsed.protocol;

Flow& flow = flows[tuple];
```

The flow table is effectively a mapping:

``` text
FiveTuple  --->  Flow state
```

If the tuple is already present, the existing flow is reused. Otherwise
a new entry is created.

This lets information discovered in one packet, such as an SNI value,
remain associated with subsequent packets from the same connection.

------------------------------------------------------------------------

## 5. Inspect the Application Information

HTTPS traffic on port 443 is examined for a TLS Client Hello:

``` cpp
if (pkt.tuple.dst_port == 443 && pkt.payload_length > 5) {
    auto sni = SNIExtractor::extract(
        payload,
        payload_length
    );

    if (sni) {
        flow.sni = *sni;
        flow.app_type = sniToAppType(*sni);
    }
}
```

The extractor checks the TLS record and handshake structure, finds the
extension area, searches for extension type `0x0000`, and obtains the
hostname from the SNI extension.

For example:

``` text
www.youtube.com
        |
        v
sniToAppType(...)
        |
        v
AppType::YOUTUBE
```

------------------------------------------------------------------------

## 6. Evaluate the Filtering Rules

After classification, the flow is checked against configured rules:

``` cpp
if (rules.isBlocked(
        tuple.src_ip,
        flow.app_type,
        flow.sni)) {

    flow.blocked = true;
}
```

The rules can test:

-   source IP address
-   classified application
-   detected domain/SNI

Domain rules use substring matching in the described implementation.

------------------------------------------------------------------------

## 7. Decide Whether to Preserve the Packet

A blocked flow is not written to the output capture:

``` cpp
if (flow.blocked) {
    dropped++;
} else {
    forwarded++;

    output.write(packet_header);
    output.write(packet_data);
}
```

Thus:

``` text
blocked packet  -> discarded
allowed packet  -> copied into output.pcap
```

------------------------------------------------------------------------

## 8. Build the Final Statistics

After all packets have been processed, flow information can be used to
build application statistics.

For example:

``` cpp
for (const auto& [tuple, flow] : flows) {
    app_stats[flow.app_type]++;
}
```

The program can then report classifications such as:

``` text
YouTube: 150 packets (15%)
Facebook: 80 packets (8%)
...
```

------------------------------------------------------------------------

# Parallel Processing Pipeline

The implementation in `dpi_mt.cpp` separates the work into multiple
stages.

## Architecture

``` text
                         +------------------+
                         |  Reader Thread   |
                         |    PCAP input    |
                         +--------+---------+
                                  |
                         hash(five-tuple)
                                  |
                    +-------------+-------------+
                    |                           |
                    v                           v
             +-------------+             +-------------+
             |    LB0      |             |    LB1      |
             | Load Bal.   |             | Load Bal.   |
             +------+------+             +------+------+
                    |                           |
                 hash % N                    hash % N
                    |                           |
          +---------+---------+       +---------+---------+
          |         |         |       |         |         |
          v         v         v       v         v         v
        FP0       FP1       ...     FP2       FP3       ...
          \         |                 |         /
           \        |                 |        /
            +-------+-----------------+-------+
                            |
                            v
                     Output Queue
                            |
                            v
                    Writer Thread
                            |
                            v
                       output.pcap
```

The exact number of load balancers and fast paths is configurable.

------------------------------------------------------------------------

## Why Hash the Five-Tuple?

The same connection should be handled by the same fast-path worker.

For example:

``` text
Flow:
192.168.1.100:54321 -> 142.250.185.206:443

SYN          -> FP2
SYN-ACK      -> FP2
Client Hello -> FP2
Application  -> FP2
More data    -> FP2
```

This consistency is important because the worker maintains the flow
state. Sending packets from one connection to unrelated workers would
make that state difficult to maintain correctly.

------------------------------------------------------------------------

## Reader Stage

The reader creates packet objects and selects a load balancer:

``` cpp
while (reader.readNextPacket(raw)) {
    Packet pkt = createPacket(raw);

    size_t lb_idx =
        hash(pkt.tuple) % num_lbs;

    lbs_[lb_idx]->queue().push(pkt);
}
```

The reader therefore performs two basic tasks:

1.  Read packets from the PCAP.
2.  Place each packet onto the appropriate load-balancer queue.

------------------------------------------------------------------------

## Load-Balancer Stage

Each load balancer receives packets from its input queue and chooses a
fast path:

``` cpp
void LoadBalancer::run() {
    while (running_) {
        auto pkt = input_queue_.pop();

        size_t fp_idx =
            hash(pkt.tuple) % num_fps_;

        fps_[fp_idx]->queue().push(pkt);
    }
}
```

The tuple-based hash keeps packets belonging to the same flow together.

------------------------------------------------------------------------

## Fast-Path Stage

Fast paths perform the actual DPI work:

``` cpp
void FastPath::run() {
    while (running_) {
        auto pkt = input_queue_.pop();

        Flow& flow = flows_[pkt.tuple];

        classifyFlow(pkt, flow);

        if (rules_->isBlocked(
                pkt.tuple.src_ip,
                flow.app_type,
                flow.sni)) {

            stats_->dropped++;
        } else {
            output_queue_->push(pkt);
        }
    }
}
```

Each worker can maintain its own flow table because the tuple hashing
ensures that packets for a particular flow are directed consistently.

------------------------------------------------------------------------

## Output Stage

The writer consumes permitted packets from the output queue:

``` cpp
void outputThread() {
    while (running_ || output_queue_.size() > 0) {
        auto pkt = output_queue_.pop();

        output_file.write(packet_header);
        output_file.write(pkt.data);
    }
}
```

The writer is separate from the DPI workers so that packet-file output
does not have to be performed directly by every processing thread.

------------------------------------------------------------------------

# Thread-Safe Queues

The workers communicate using synchronized queues.

A simplified representation is:

``` cpp
template<typename T>
class TSQueue {
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable not_empty_;
    std::condition_variable not_full_;

    void push(T item) {
        std::lock_guard<std::mutex> lock(mutex_);
        queue_.push(item);
        not_empty_.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);

        not_empty_.wait(
            lock,
            [&]{ return !queue_.empty(); }
        );

        T item = queue_.front();
        queue_.pop();

        return item;
    }
};
```

The important roles are:

  -----------------------------------------------------------------------
  Mechanism                           Purpose
  ----------------------------------- -----------------------------------
  `mutex`                             Protects the queue from
                                      simultaneous access

  `push()`                            Adds an item and wakes a consumer

  `pop()`                             Waits until an item exists, then
                                      removes it

  `condition_variable`                Prevents consumers from
                                      continuously polling an empty queue
  -----------------------------------------------------------------------

This is the producer-consumer mechanism used to connect the processing
stages safely.

------------------------------------------------------------------------

# Component Reference

## `pcap_reader.h` / `pcap_reader.cpp`

### Purpose

Handles the binary PCAP input/output process used by the DPI engine.

The main structures include:

``` cpp
struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t snaplen;
    uint32_t network;
};

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
```

The global header's magic value identifies the PCAP format. The packet
header records the timestamp and captured/original lengths.

Important operations include:

-   `open(filename)` --- open and validate the capture
-   `readNextPacket(raw)` --- obtain the next packet
-   `close()` --- release the file

------------------------------------------------------------------------

## `packet_parser.h` / `packet_parser.cpp`

### Purpose

Converts raw bytes into useful network-layer fields.

The main parsing sequence is conceptually:

``` cpp
bool PacketParser::parse(
    const RawPacket& raw,
    ParsedPacket& parsed) {

    parseEthernet(...);
    parseIPv4(...);
    parseTCP(...);
    // or parseUDP(...)
}
```

The parser must account for **network byte order**. Network protocols
use big-endian representation, while a host machine may use
little-endian representation.

The implementation therefore uses conversions such as:

``` cpp
uint16_t port =
    ntohs(*(uint16_t*)(data + offset));

uint32_t seq =
    ntohl(*(uint32_t*)(data + offset));
```

Here:

-   `ntohs()` converts a 16-bit network-order value to host order.
-   `ntohl()` performs the equivalent conversion for a 32-bit value.

------------------------------------------------------------------------

## `sni_extractor.h` / `sni_extractor.cpp`

### Purpose

Looks for application-layer host information in TLS and HTTP traffic.

### TLS

The TLS extractor follows this general process:

``` text
1. Validate TLS record
2. Confirm Client Hello
3. Move through the Client Hello fields
4. Locate the extension block
5. Search for extension 0x0000
6. Read the hostname
```

The relevant function has the form:

``` cpp
std::optional<std::string>
SNIExtractor::extract(
    const uint8_t* payload,
    size_t length);
```

### HTTP

For HTTP traffic, the corresponding logic searches the request for the
`Host:` header:

``` text
HTTP request
    |
    +-- GET /...
    +-- Host: example.com
             |
             v
       extracted hostname
```

The extractor checks for an HTTP request, searches for `Host:`, and
returns its value.

------------------------------------------------------------------------

## `types.h` / `types.cpp`

This module contains common data definitions used by the rest of the
engine.

### FiveTuple

``` cpp
struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    bool operator==(const FiveTuple& other) const;
};
```

### Application Types

The project uses an application classification enum containing values
such as:

``` cpp
enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    GOOGLE,
    YOUTUBE,
    FACEBOOK,
    // additional application types
};
```

### Mapping a Hostname to an Application

Classification is signature-based. For example:

``` cpp
AppType sniToAppType(const std::string& sni) {
    if (sni.find("youtube") != std::string::npos)
        return AppType::YOUTUBE;

    if (sni.find("facebook") != std::string::npos)
        return AppType::FACEBOOK;

    // additional patterns
}
```

In other words, the detected hostname becomes the input to the
application-signature logic.

------------------------------------------------------------------------

# TLS SNI Inspection

## Where SNI Appears

For a traditional TLS connection, the early handshake can be represented
as:

``` text
Browser                                      Server
   |                                           |
   | -------- Client Hello ------------------> |
   |          SNI: www.youtube.com             |
   |                                           |
   | <------- Server Hello ------------------- |
   |          certificate                      |
   |                                           |
   | -------- key-exchange messages --------> |
   |                                           |
   | <==== encrypted application data =======> |
```

The DPI implementation is interested in the Client Hello. Once the
connection proceeds to encrypted application traffic, this project does
not decrypt that content.

------------------------------------------------------------------------

## Client Hello Layout

The extractor navigates through the Client Hello structure approximately
as follows:

``` text
TLS Record
+----------------------------------------------+
| Content Type = 0x16                          |
| Version                                      |
| Record Length                                |
+----------------------------------------------+
| Handshake Type = 0x01                        |
| Handshake Length                             |
+----------------------------------------------+
| Client Version                               |
| Random (32 bytes)                            |
| Session ID                                   |
| Cipher Suites                                |
| Compression Methods                          |
| Extensions                                   |
|   +----------------------------------------+ |
|   | Extension Type                         | |
|   | Extension Length                       | |
|   | Extension Data                         | |
|   +----------------------------------------+ |
|                                              |
| SNI Extension (0x0000)                      |
|   SNI list length                            |
|   Name type = 0x00                          |
|   Name length                               |
|   Hostname                                  |
+----------------------------------------------+
```

The SNI extension contains the hostname the client is requesting.

------------------------------------------------------------------------

## Simplified Extraction Logic

A simplified version of the project's extraction procedure looks like:

``` cpp
std::optional<std::string>
SNIExtractor::extract(
    const uint8_t* payload,
    size_t length) {

    if (payload[0] != 0x16)
        return std::nullopt;

    if (payload[5] != 0x01)
        return std::nullopt;

    size_t offset = 43;

    uint8_t session_len = payload[offset];
    offset += 1 + session_len;

    uint16_t cipher_len =
        readUint16BE(payload + offset);
    offset += 2 + cipher_len;

    uint8_t comp_len = payload[offset];
    offset += 1 + comp_len;

    uint16_t ext_len =
        readUint16BE(payload + offset);
    offset += 2;

    size_t ext_end = offset + ext_len;

    while (offset + 4 <= ext_end) {
        uint16_t ext_type =
            readUint16BE(payload + offset);

        uint16_t ext_data_len =
            readUint16BE(payload + offset + 2);

        offset += 4;

        if (ext_type == 0x0000) {
            uint16_t sni_len =
                readUint16BE(payload + offset + 3);

            return std::string(
                (char*)(payload + offset + 5),
                sni_len
            );
        }

        offset += ext_data_len;
    }

    return std::nullopt;
}
```

The essential idea is not to decrypt TLS. Instead, the extractor
navigates through the publicly visible handshake structure until it
reaches the SNI extension.

------------------------------------------------------------------------

# Traffic Blocking

## Supported Rule Categories

The filtering system supports three principal rule types:

  -----------------------------------------------------------------------
  Rule                    Example                 Effect
  ----------------------- ----------------------- -----------------------
  Source IP               `192.168.1.50`          Reject traffic
                                                  originating from that
                                                  address

  Application             `YouTube`               Reject flows classified
                                                  as YouTube

  Domain                  `tiktok`                Reject flows whose
                                                  detected SNI contains
                                                  `tiktok`
  -----------------------------------------------------------------------

The domain check described by the project is a substring comparison.

------------------------------------------------------------------------

## Decision Process

The rule evaluation can be viewed as:

``` text
                     Packet
                       |
                       v
             +---------------------+
             | Source IP blocked?  |
             +----------+----------+
                        |
                    yes | no
                        | 
                       DROP
                        |
                       no
                        v
             +---------------------+
             | Application blocked?|
             +----------+----------+
                        |
                    yes | no
                        |
                       DROP
                        |
                       no
                        v
             +---------------------+
             | Domain/SNI matches? |
             +----------+----------+
                        |
                    yes | no
                        |
                       DROP
                        |
                       no
                        v
                     FORWARD
```

The actual rule-checking operation is conceptually:

``` cpp
if (blocked_ips.count(src_ip))
    return true;

if (blocked_apps.count(app))
    return true;

for (const auto& domain : blocked_domains) {
    if (sni.find(domain) != std::string::npos)
        return true;
}

return false;
```

------------------------------------------------------------------------

## Blocking Happens at Flow Level

A significant part of the design is that classification is associated
with the **flow**, rather than treating every packet as an independent
decision.

For example:

``` text
TCP connection to YouTube

SYN                 -> no SNI -> forward
SYN-ACK             -> no SNI -> forward
ACK                 -> no SNI -> forward
Client Hello        -> SNI found
                     -> YOUTUBE
                     -> flow becomes BLOCKED
                     -> drop
subsequent packets  -> flow already blocked
                     -> drop
```

The reason is straightforward: the application may not be identifiable
until the Client Hello arrives. Once the flow has been classified, its
stored state lets the engine make the same blocking decision for
subsequent packets.

As a result, the connection can fail or eventually time out from the
client's perspective.

------------------------------------------------------------------------

# Compilation and Execution

## Requirements

The documented implementation requires:

-   macOS or Linux
-   A C++17-capable compiler
-   `g++` or `clang++`
-   No additional external libraries for the listed build commands

------------------------------------------------------------------------

## Build the Sequential Version

``` bash
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

This produces the executable:

``` text
dpi_simple
```

------------------------------------------------------------------------

## Build the Multi-Threaded Version

The parallel implementation additionally requires pthread support:

``` bash
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp \
    src/pcap_reader.cpp \
    src/packet_parser.cpp \
    src/sni_extractor.cpp \
    src/types.cpp
```

The resulting executable is:

``` text
dpi_engine
```

------------------------------------------------------------------------

## Basic Execution

For the multi-threaded program:

``` bash
./dpi_engine test_dpi.pcap output.pcap
```

The first argument is the input capture and the second is the output
capture.

------------------------------------------------------------------------

## Supplying Blocking Rules

Multiple rule types can be supplied together:

``` bash
./dpi_engine test_dpi.pcap output.pcap \
    --block-app YouTube \
    --block-app TikTok \
    --block-ip 192.168.1.50 \
    --block-domain facebook
```

This example requests blocking for:

-   YouTube traffic
-   TikTok traffic
-   Traffic from `192.168.1.50`
-   SNI values containing `facebook`

------------------------------------------------------------------------

## Choosing the Parallelism

For the multi-threaded version, load-balancer and fast-path counts can
be specified:

``` bash
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4
```

With these settings, the configuration creates:

``` text
4 load-balancer threads
x
4 fast-path threads
=
16 processing threads
```

------------------------------------------------------------------------

## Generate a Test Capture

The repository includes a Python script for generating sample traffic:

``` bash
python3 generate_test_pcap.py
```

It creates:

``` text
test_dpi.pcap
```

which can be used as input when testing the engine.

------------------------------------------------------------------------

# Reading the Program Output

A typical multi-threaded run reports several categories of information.

Example:

``` text
+--------------------------------------------------------------+
|                  DPI ENGINE v2.0 (Multi-threaded)            |
+--------------------------------------------------------------+
| Load Balancers: 2    FPs per LB: 2    Total FPs: 4           |
+--------------------------------------------------------------+

[Rules] Blocked app: YouTube
[Rules] Blocked IP: 192.168.1.50

[Reader] Processing packets...
[Reader] Done reading 77 packets

+--------------------------------------------------------------+
|                       PROCESSING REPORT                      |
+--------------------------------------------------------------+
| Total Packets:                  77                           |
| Total Bytes:                  5738                           |
| TCP Packets:                    73                           |
| UDP Packets:                     4                           |
+--------------------------------------------------------------+
| Forwarded:                      69                           |
| Dropped:                         8                           |
+--------------------------------------------------------------+
| THREAD STATISTICS                                             |
|   LB0 dispatched:               53                           |
|   LB1 dispatched:               24                           |
|   FP0 processed:                53                           |
|   FP1 processed:                 0                           |
|   FP2 processed:                 0                           |
|   FP3 processed:                24                           |
+--------------------------------------------------------------+
| APPLICATION BREAKDOWN                                         |
+--------------------------------------------------------------+
| HTTPS                39  50.6%                               |
| Unknown              16  20.8%                               |
| YouTube               4   5.2%  (BLOCKED)                    |
| DNS                   4   5.2%                               |
| Facebook              3   3.9%                               |
| ...                                                          |
+--------------------------------------------------------------+

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - www.google.com -> Google
  - github.com -> GitHub
```

The values above are an example of the format and are not a promise that
every capture will produce the same numbers.

------------------------------------------------------------------------

## Meaning of the Report Sections

  Output area             Interpretation
  ----------------------- -------------------------------------------------
  Configuration           Number of load balancers and fast-path workers
  Rules                   Active IP/application/domain filters
  Total Packets           Number of packets read from the source PCAP
  Forwarded               Packets written into the resulting PCAP
  Dropped                 Packets excluded because their flow was blocked
  Thread Statistics       Distribution of work between workers
  Application Breakdown   Classification counts
  Detected SNIs           Hostnames discovered during inspection

------------------------------------------------------------------------

# Possible Extensions

The current design can be expanded in several directions without
changing its basic architecture.

## 1. More Application Signatures

New hostname patterns can be added to the application classifier.

For example:

``` cpp
if (sni.find("twitch") != std::string::npos)
    return AppType::TWITCH;
```

This would allow Twitch traffic to receive its own application
classification.

------------------------------------------------------------------------

## 2. Bandwidth Throttling

Instead of immediately dropping a packet, a future implementation could
delay selected flows:

``` cpp
if (shouldThrottle(flow)) {
    std::this_thread::sleep_for(10ms);
}
```

This would provide a throttling mechanism rather than an all-or-nothing
block.

------------------------------------------------------------------------

## 3. Live Statistics

A separate reporting worker could periodically print current statistics:

``` cpp
void statsThread() {
    while (running) {
        printStats();
        sleep(1);
    }
}
```

This would make the program's activity visible while a capture is being
processed.

------------------------------------------------------------------------

## 4. QUIC / HTTP/3

QUIC and HTTP/3 traffic would require additional handling because QUIC
uses UDP, including UDP port 443.

The project could be extended to inspect the information available in a
QUIC Initial packet, where hostname information is handled differently
from the conventional TLS-over-TCP path used by the existing extractor.

------------------------------------------------------------------------

## 5. Persistent Filtering Rules

Rules could be stored externally and loaded when the application starts:

``` text
rules file
    |
    v
application startup
    |
    v
rule manager
```

This would remove the need to provide every rule manually on the command
line.

------------------------------------------------------------------------

# Project Takeaways

This project brings together several networking and systems-programming
concepts:

1.  **Packet decoding** --- interpreting Ethernet, IPv4, TCP, and UDP
    headers.
2.  **Deep packet inspection** --- examining application-level
    information available in packet payloads.
3.  **TLS SNI inspection** --- obtaining a requested hostname from the
    TLS Client Hello when it is available.
4.  **Flow state** --- associating packets through a five-tuple and
    retaining classification information.
5.  **Traffic filtering** --- making IP-, application-, and domain-based
    blocking decisions.
6.  **Parallel processing** --- distributing packet work across load
    balancers and fast-path workers.
7.  **Producer-consumer synchronization** --- connecting worker stages
    through thread-safe queues.
8.  **PCAP processing** --- reading captures and creating a filtered
    output capture.

The central idea behind the application is that application
identification does not necessarily require decrypting an HTTPS session.
In the TLS handshake model supported here, the Client Hello can expose
the requested server name, allowing the engine to associate a flow with
a domain or application before the later application data becomes
encrypted.

------------------------------------------------------------------------

# Where to Start in the Code

If you are learning the project for the first time, the recommended
order is:

``` text
main_working.cpp
       |
       v
packet_parser.cpp
       |
       v
sni_extractor.cpp
       |
       v
types.cpp
       |
       v
dpi_mt.cpp
       |
       v
load balancer / fast path / queue components
```

The sequential implementation provides the clearest view of the basic
packet lifecycle. After that, `dpi_mt.cpp` demonstrates how the same
core processing model is divided into concurrent stages.
