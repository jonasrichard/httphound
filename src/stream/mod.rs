use std::{collections::HashMap, net::IpAddr};

use bytes::BytesMut;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::PacketHeader;

use crate::{
    http::{self, Req, Resp},
    Args,
};

#[derive(Clone, Debug, PartialEq)]
pub struct Endpoint {
    pub address: IpAddr,
    pub port: u16,
}

pub struct MyPacket {
    pub header: PacketHeader,
    pub data: Vec<u8>,
}

pub struct EnrichedPacket {
    // TODO tv sec and usec
    pub ts: i64,
    pub packet: MyPacket,
    pub source: Endpoint,
    pub dest: Endpoint,
    pub fin: bool,
}

// TODO collect packets to streams
// TODO manage streams, save them, delete them from the data structure

impl std::fmt::Debug for EnrichedPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrichedPacket")
            .field("ts", &self.ts)
            .field("source", &self.source)
            .field("dest", &self.dest)
            .field("fin", &self.fin)
            .finish()
    }
}

pub struct HttpStream {
    pub id: i32,
    pub source: Endpoint,
    pub dest: Endpoint,
    pub packets: Vec<EnrichedPacket>,
    pub souce_fin: bool,
    pub dest_fin: bool,
    pub request: Option<Req>,
    pub response: Option<Resp>,
}

pub struct Store {
    pub streams: HashMap<i32, HttpStream>,
    pub next_id: i32,
}

impl EnrichedPacket {
    pub fn enrich_packet(packet: MyPacket) -> Option<EnrichedPacket> {
        let sliced = SlicedPacket::from_ethernet(&packet.data)
            .expect("Packet cannot be parsed by etherparse");

        let (src_port, dst_port) = match &sliced.transport {
            Some(TransportSlice::Tcp(tcp)) => (tcp.source_port(), tcp.destination_port()),
            _ => return None,
        };

        let (src_addr, dst_addr) = match &sliced.net {
            Some(InternetSlice::Ipv4(ip4)) => (
                IpAddr::V4(ip4.header().source_addr()),
                IpAddr::V4(ip4.header().destination_addr()),
            ),
            Some(InternetSlice::Ipv6(ip6)) => (
                IpAddr::V6(ip6.header().source_addr()),
                IpAddr::V6(ip6.header().destination_addr()),
            ),
            _ => return None,
        };

        let fin = sliced.transport.is_some_and(|t| {
            if let TransportSlice::Tcp(tcp) = t {
                tcp.fin()
            } else {
                false
            }
        });

        Some(EnrichedPacket {
            ts: packet.header.ts.tv_sec,
            packet,
            source: Endpoint {
                address: src_addr,
                port: src_port,
            },
            dest: Endpoint {
                address: dst_addr,
                port: dst_port,
            },
            fin,
        })
    }
}

impl HttpStream {
    pub fn new(id: i32, source: Endpoint, dest: Endpoint) -> Self {
        HttpStream {
            id,
            source,
            dest,
            packets: vec![],
            souce_fin: false,
            dest_fin: false,
            request: None,
            response: None,
        }
    }

    pub fn append_request_packet(&mut self, packet: EnrichedPacket) {
        if packet.fin {
            self.souce_fin = true;
        }

        self.packets.push(packet);
    }

    pub fn append_response_packet(&mut self, packet: EnrichedPacket) {
        if packet.fin {
            self.dest_fin = true;
        }

        self.packets.push(packet);
    }

    pub fn is_complete(&self) -> bool {
        self.souce_fin && self.dest_fin
    }

    pub fn collect_request(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        for packet in &self.packets {
            if packet.source == self.source {
                let sliced = SlicedPacket::from_ethernet(&packet.packet.data)
                    .expect("Cannot parse ethernet packet");
                let transport = sliced.transport.expect("This should be a TCP packet");

                if let TransportSlice::Tcp(tcp) = transport {
                    buf.extend_from_slice(tcp.payload());
                }
            }
        }

        buf
    }

    pub fn collect_response(&self) -> BytesMut {
        let mut buf = BytesMut::new();

        for packet in &self.packets {
            if packet.source == self.dest {
                let sliced = SlicedPacket::from_ethernet(&packet.packet.data)
                    .expect("Cannot parse ethernet packet");
                let transport = sliced.transport.expect("This should be a TCP packet");

                if let TransportSlice::Tcp(tcp) = transport {
                    buf.extend_from_slice(tcp.payload());
                }
            }
        }

        buf
    }

    pub fn parse(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.request = Some(http::parse_request(&mut self.collect_request())?);
        self.response = Some(http::parse_response(&mut self.collect_response())?);

        Ok(())
    }

    pub fn is_matching(&self, args: &Args) -> bool {
        if let Some(ref req) = self.request {
            if let Some(ref path_match) = args.path {
                if req.path.contains(path_match) {
                    return true;
                }
            } else {
                return true;
            }
        }

        false
    }

    pub fn print(&self) {
        println!("--- HTTP request/response ---");

        if let Some(ref req) = self.request {
            println!("HTTP 1.{} {} {}", req.version, req.method, req.path);

            for (header_name, header_value) in &req.headers {
                println!("{}: {}", header_name, header_value);
            }

            if let Some(ref req_body) = req.body {
                println!("{}\n", req_body);
            }

            println!();
        }

        if let Some(ref resp) = self.response {
            print!("HTTP 1.{} {}", resp.version, resp.code);

            match &resp.reason {
                Some(r) => {
                    println!(" ({})", r);
                }
                None => {
                    println!();
                }
            }

            for (header_name, header_value) in &resp.headers {
                println!("{}: {}", header_name, header_value);
            }

            if let Some(ref resp_body) = resp.body {
                println!("{}\n", resp_body);
            }

            println!();
        }
    }
}

impl Store {
    pub fn new() -> Self {
        Store {
            streams: HashMap::new(),
            next_id: 0,
        }
    }

    pub fn lookup_stream_id(&self, source: &Endpoint, dest: &Endpoint) -> Option<i32> {
        for (id, stream) in &self.streams {
            if (&stream.source == source && &stream.dest == dest)
                || (&stream.source == dest && &stream.dest == source)
            {
                return Some(*id);
            }
        }

        None
    }

    pub fn add_stream(&mut self, stream: HttpStream) {
        self.streams.insert(stream.id, stream);
    }

    pub fn get_next_id(&mut self) -> i32 {
        let id = self.next_id;

        self.next_id += 1;

        id
    }

    /// Add next packet to the store and return the id of the http stream to which that packet has
    /// been added and also true if the stream is complete.
    pub fn append_packet(&mut self, packet: EnrichedPacket) -> Option<(i32, bool)> {
        if let Some(id) = self.lookup_stream_id(&packet.source, &packet.dest) {
            if let Some(stream) = self.streams.get_mut(&id) {
                if stream.source == packet.source {
                    stream.append_request_packet(packet);
                } else {
                    stream.append_response_packet(packet);
                }

                Some((id, stream.is_complete()))
            } else {
                None
            }
        } else {
            None
        }
    }
}
