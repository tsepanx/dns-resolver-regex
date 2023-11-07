use bytes::Bytes;
use dns_message_parser::question::Question;
use dns_message_parser::rr::A;
use dns_message_parser::{Dns, Flags, Opcode, RCode};
use regex::Regex;
use std::fmt::{Debug, Display};
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
use std::str::FromStr;

const BUF_SIZE: usize = 1024;
const AUTO_BIND_ADDR: &str = "0.0.0.0:0";

type Table = Vec<(IpAddr, String)>;
type Error = Box<dyn std::error::Error>;

fn post_process_regex(r: String) -> String {
    let r = r.replace(".", r"\.");
    let r = r.replace("*", ".*");
    let r = format!(r"^{:}\.$", r);

    return r;
}

fn print_bytes(input: &[u8]) {
    println!("Bytes: {:}, {:02X?}", input.len(), input);
}

fn build_a_reply(id: u16, question: Question, addr: Ipv4Addr) -> Vec<u8> {
    let flags = Flags {
        qr: true,
        opcode: Opcode::Query,
        aa: true,
        tc: false,
        rd: true,
        ra: true,
        ad: false,
        cd: false,
        rcode: RCode::NoError,
    };

    let answer = {
        let a = A {
            domain_name: question.domain_name.clone(),
            ttl: 3600,
            ipv4_addr: addr,
        };

        dns_message_parser::rr::RR::A(a)
    };

    let dns = Dns {
        id,
        flags,
        questions: vec![question],
        answers: vec![answer],
        authorities: vec![],
        additionals: vec![],
    };
    let bytes = dns.encode().unwrap();

    bytes.to_vec()
}

fn read_table(path: &str) -> Result<Box<Table>, Error> {
    let mut result = Box::new(vec![]);

    let data = fs::read_to_string(path).unwrap();
    let lines = data.split('\n');

    for line in lines {
        if line.starts_with("#") { continue; }
        if line.is_empty() { continue; }

        let mut split = line.splitn(2, ' ');

        let addr_string = split.next().ok_or("Error parsing")?;
        let addr_string = String::from(addr_string);
        let addr: IpAddr = IpAddr::from_str(&*addr_string)?;
        let regex_str = split.next().ok_or("Error parsing")?;
        let regex_str = String::from(regex_str);
        let regex_str = post_process_regex(regex_str);

        // Ensure only 2 words in a line TODO
        // assert!(regex.matches(' '));

        result.push((addr, regex_str));
    }

    Ok(result)
}

fn match_regex_table(name: &str, table: &Table) -> Option<IpAddr> {
    for (addr, regex) in table {
        let r = Regex::new(regex).unwrap();

        if r.find(name).map_or(false, |_| true) {
            println!("\tMatched: {:?}", (addr, regex));
            return Some(*addr);
        }
    }

    None
}

fn handle_request(input: Vec<u8>, table: &Table) -> Option<Vec<u8>> {
    let dns_packet = Dns::decode(Bytes::from(input)).unwrap();

    let q0 = &dns_packet.questions[0];
    println!("DNS Query[0]: {:}", q0);

    let matched_entry = match_regex_table(&*q0.domain_name.to_string(), table);
    return match matched_entry {
        Some(addr) => match addr {
            IpAddr::V4(ipv4) => Some(build_a_reply(dns_packet.id, q0.clone(), ipv4)),
            IpAddr::V6(_) => panic!("IPv6 is not yet supported"),
        },
        None => None,
    };
}

fn forward_to_resolver(addr: SocketAddr, packet_buf: &[u8]) -> Result<Vec<u8>, Error> {
    println!("\tRequesting default resolver: {:?}", addr);

    let mut buf = [0u8; BUF_SIZE];

    let sock = UdpSocket::bind(AUTO_BIND_ADDR).unwrap();
    let _ = sock.send_to(packet_buf, addr);
    let (size, addr_recv) = sock.recv_from(&mut buf)?;
    let buf = &buf[..size];

    println!("\t\tGot from: {:}", addr_recv);

    let buf_bytes = Bytes::from(buf.to_vec());
    let packet = Dns::decode(buf_bytes).unwrap();
    println!("\t\tPacket: {:}", packet);

    return if addr_recv == addr {
        Ok(buf.to_vec())
    } else {
        Err(Error::from(format!("send & recv addrs mismatch: {:} - {:}", addr_recv, addr)))
    }
}

fn main() {
    let host = IpAddr::V4(Ipv4Addr::from_str("127.0.0.1").unwrap());
    let port = 3333;

    let default_resolver: SocketAddr = SocketAddr::V4(SocketAddrV4::from_str("9.9.9.9:53").unwrap());

    let addr = SocketAddr::new(host, port);
    println!("=== ADDR: {} ===", addr);

    let hosts_table = read_table("./hosts.txt").unwrap();
    println!("=== Table ===\n{:?}", hosts_table);

    let udp_socket = UdpSocket::bind(&addr).unwrap();

    loop {
        let mut buf = [0u8; BUF_SIZE];
        let (size, addr) = udp_socket.recv_from(&mut buf).unwrap();

        let buf = &buf[0..size];
        let reply = match handle_request(buf.to_vec(), &hosts_table) {
            Some(val) => val,
            None =>
                forward_to_resolver(
                    default_resolver,
                    buf
                ).unwrap()
        };
        udp_socket.send_to(reply.as_slice(), addr).unwrap();
    }
}
