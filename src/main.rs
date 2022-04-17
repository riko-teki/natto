use libc::*;
use std::{mem, io, ptr};

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
            sa_data: [0,0,0,0,0,0,0,0,0,0,0,0,0,0],
        };

        let result = libc::bind(
            sniffer,
            &s as *const libc::sockaddr,
            mem::size_of_val(&s) as u32
        );
        if result == -1 {
            panic!("{}", io::Error::last_os_error());
        }

        let result = libc::setsockopt(sniffer, libc::IPPROTO_IP, libc::IP_HDRINCL, 1 as *const libc::c_void, 0);
        if result == -1 {
            panic!("{}", io::Error::last_os_error());
        }

        let mut buf = [0;64]; 
        let addr: *mut libc::sockaddr = ptr::null_mut();
        let addrlen: *mut libc::socklen_t = ptr::null_mut();
        let bufptr = buf.as_mut_ptr() as *mut libc::c_void;
        let buflen = buf.len() as libc::size_t;

        let n = libc::recvfrom(
            sniffer,
            bufptr,
            buflen,
            0,
            addr,
            addrlen
        );
        if n == -1 {
            panic!("{}", io::Error::last_os_error());
        }

        println!("{:?}",buf);
        
    }
}
