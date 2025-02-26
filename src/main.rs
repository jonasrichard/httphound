mod http;
mod stream;

use std::{io, os::fd::AsRawFd};

use clap::{command, Parser};
use pcap::Capture;
use stream::MyPacket;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Pattern of path to match
    #[arg(short, long)]
    pub path: Option<String>,
}

fn main() {
    let args = Args::parse();
    let mut capture =
        unsafe { Capture::from_raw_fd(io::stdin().as_raw_fd()).expect("Cannot open stdin") };

    let mut store = stream::Store::new();

    while let Ok(packet) = capture.next_packet() {
        let mypacket = MyPacket {
            header: *packet.header,
            data: packet.data.to_owned(),
        };

        if let Some(enriched) = stream::EnrichedPacket::enrich_packet(mypacket) {
            if store
                .lookup_stream_id(&enriched.source, &enriched.dest)
                .is_none()
            {
                let id = store.get_next_id();
                let http_stream =
                    stream::HttpStream::new(id, enriched.source.clone(), enriched.dest.clone());

                store.add_stream(http_stream);
            }

            if let Some((id, complete)) = store.append_packet(enriched) {
                if complete {
                    match store.streams.get_mut(&id) {
                        Some(stream) => match stream.parse() {
                            Ok(_) => {
                                if stream.is_matching(&args) {
                                    stream.print();
                                }
                                // TODO remove stream to save memory
                            }
                            Err(e) => {
                                eprintln!("Parse error: {e}");
                            }
                        },
                        None => {
                            eprintln!("Cannot append packet to stream, stream cannot be found with id: {id}");
                        }
                    }
                }
            }
        }
    }
}
