use libc::*;
use std::{io, mem, ptr, ops::{Shr, Shl}, fmt};

fn main() {
    let socket_protocol = libc::IPPROTO_ICMP;

    let sniffer: i32;
    unsafe {
        sniffer = libc::socket(libc::AF_INET, libc::SOCK_RAW, socket_protocol);
        if sniffer == -1 {
            panic!("{}", io::Error::last_os_error());
        }
        let mut s = libc::sockaddr {
            sa_family: libc::AF_INET as u16,
            sa_data: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        };

        let result = libc::bind(
            sniffer,
            &s as *const libc::sockaddr,
            mem::size_of_val(&s) as u32,
        );
        if result == -1 {
            panic!("{}", io::Error::last_os_error());
        }

        let result = libc::setsockopt(
            sniffer,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            1 as *const libc::c_void,
            0,
        );
        if result == -1 {
            panic!("{}", io::Error::last_os_error());
        }

        let mut buf = [0_u8; 20];
        let addr: *mut libc::sockaddr = ptr::null_mut();
        let addrlen: *mut libc::socklen_t = ptr::null_mut();
        let bufptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buflen = buf.len() as libc::size_t;

        let n = libc::recvfrom(sniffer, bufptr, buflen, 0, addr, addrlen);
        if n == -1 {
            panic!("{}", io::Error::last_os_error());
        }
        
        println!("{:?}", buf);
        let ip = IpHeader::new(buf);
        println!("{:?}",ip);
    }
}

#[derive(Debug)]
enum IpVersion {
    IPV4,
    IPV6,
    Undefined,
}

#[derive(Debug)]
struct IpHeader {
    version:  IpVersion,
    header_length: u8,
    type_of_service: u8,
    length: u16,
    id: u16,
    offset: u16,
    ttl: u8,
    protocol: u8,
    sum: u16,
    src: String,
    dst: String,
}

impl IpHeader {
    pub fn new(socket_buffer: [u8;20]) -> Self {
        let ver = match (socket_buffer[0].shr(4)) as u8 {
            4 => IpVersion::IPV4,
            6 => IpVersion::IPV6,
            _ => IpVersion::Undefined,
        };

        let header_len = socket_buffer[0] & 0x0F;

        let mut src = String::from("");
        src.push_str(&socket_buffer[12].to_string());
        src.push('.');
        src.push_str(&socket_buffer[13].to_string());
        src.push('.');
        src.push_str(&socket_buffer[14].to_string());
        src.push('.');
        src.push_str(&socket_buffer[15].to_string());

        let mut dst = String::from("");
        dst.push_str(&socket_buffer[16].to_string());
        dst.push('.');
        dst.push_str(&socket_buffer[17].to_string());
        dst.push('.');
        dst.push_str(&socket_buffer[18].to_string());
        dst.push('.');
        dst.push_str(&socket_buffer[19].to_string());

        IpHeader { 
            version: ver,
            header_length: header_len,
            type_of_service: socket_buffer[1],
            length: (socket_buffer[2].shl(8) | socket_buffer[3]) as u16,
            id: (socket_buffer[4].shl(8) | socket_buffer[5]) as u16,
            offset: (socket_buffer[6].shl(8) | socket_buffer[7]) as u16,
            ttl: socket_buffer[8],
            protocol: socket_buffer[9],
            sum: (socket_buffer[10].shl(8) | socket_buffer[11]) as u16,
            src,
            dst,
        }

    }
}
