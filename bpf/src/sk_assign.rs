use core::ffi::{c_int, c_long, c_void};
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use core::num::NonZeroUsize;
use core::ptr::{addr_of_mut, NonNull};

use aya_ebpf::bindings::{
    bpf_sock, bpf_sock_tuple, BPF_F_CURRENT_NETNS, BPF_TCP_LISTEN, TC_ACT_OK, TC_ACT_SHOT,
};
use aya_ebpf::helpers::{
    bpf_map_lookup_elem, bpf_sk_assign, bpf_sk_lookup_udp, bpf_sk_release, bpf_skc_lookup_tcp,
};
use aya_ebpf::maps::lpm_trie::Key;
use aya_ebpf::programs::TcContext;
use aya_ebpf::EbpfContext;
use aya_log_ebpf::macro_support::IpFormatter;
use aya_log_ebpf::{debug, error, info, WriteToBuf};
use network_types::eth::{EthHdr, EtherType};
use network_types::ip::{IpProto, Ipv4Hdr, Ipv6Hdr};
use network_types::tcp::TcpHdr;
use network_types::udp::UdpHdr;
use share::route::FWMARK;

use crate::connect_directly;
use crate::map::{
    ASSIGN_SOCK_MAP, CONNECT_DIRECTLY_MODE, PROXY_IPV4_LIST, PROXY_IPV6_LIST, PROXY_LIST_MODE,
};

pub fn assign_ingress(mut ctx: TcContext) -> Result<c_int, c_int> {
    let tuple_with_addrs = get_tuple(&mut ctx);
    let mut tuple_with_addrs = match tuple_with_addrs {
        None => return Ok(TC_ACT_OK),
        Some(tuple_with_addrs) => tuple_with_addrs,
    };

    let tuple = unsafe { tuple_with_addrs.bpf_sock_tuple.as_mut() };

    match tuple_with_addrs.ip_proto {
        IpProto::Tcp => handle_tcp(
            &mut ctx,
            tuple_with_addrs.src,
            tuple_with_addrs.dst,
            tuple,
            tuple_with_addrs.ether_type,
        ),

        IpProto::Udp => handle_udp(
            &mut ctx,
            tuple_with_addrs.src,
            tuple_with_addrs.dst,
            tuple,
            tuple_with_addrs.ether_type,
        ),

        _ => {
            debug!(&ctx, "other ip proto: {}", tuple_with_addrs.ip_proto as u8);

            Ok(TC_ACT_OK)
        }
    }
}

fn get_tcp_ports(ctx: &mut TcContext, eth_type: EtherType) -> Option<(u16, u16)> {
    let tcp_hdr = match eth_type {
        EtherType::Ipv4 => {
            let tcp_hdr = ctx
                .void_data()
                .wrapping_byte_add(size_of::<EthHdr>() + size_of::<Ipv4Hdr>())
                as *mut TcpHdr;
            if tcp_hdr.wrapping_add(1) > ctx.void_data_end().cast() {
                return None;
            }

            tcp_hdr
        }

        EtherType::Ipv6 => {
            let tcp_hdr = ctx
                .void_data()
                .wrapping_byte_add(size_of::<EthHdr>() + size_of::<Ipv6Hdr>())
                as *mut TcpHdr;
            if tcp_hdr.wrapping_add(1) > ctx.void_data_end().cast() {
                return None;
            }

            tcp_hdr
        }

        _ => unreachable!(),
    };

    unsafe {
        Some((
            u16::from_be((*tcp_hdr).source),
            u16::from_be((*tcp_hdr).dest),
        ))
    }
}

fn get_udp_ports(ctx: &mut TcContext, eth_type: EtherType) -> Option<(u16, u16)> {
    let udp_hdr = match eth_type {
        EtherType::Ipv4 => {
            let udp_hdr = ctx
                .void_data()
                .wrapping_byte_add(size_of::<EthHdr>() + size_of::<Ipv4Hdr>())
                as *mut UdpHdr;
            if udp_hdr.wrapping_add(1) > ctx.void_data_end().cast() {
                return None;
            }

            udp_hdr
        }

        EtherType::Ipv6 => {
            let udp_hdr = ctx
                .void_data()
                .wrapping_byte_add(size_of::<EthHdr>() + size_of::<Ipv6Hdr>())
                as *mut UdpHdr;
            if udp_hdr.wrapping_add(1) > ctx.void_data_end().cast() {
                return None;
            }

            udp_hdr
        }

        _ => unreachable!(),
    };

    unsafe {
        Some((
            u16::from_be((*udp_hdr).source),
            u16::from_be((*udp_hdr).dest),
        ))
    }
}

fn handle_tcp(
    ctx: &mut TcContext,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    tuple: &mut bpf_sock_tuple,
    eth_type: EtherType,
) -> Result<c_int, c_int> {
    if !should_proxy(ctx, dst_ip)? {
        return Ok(TC_ACT_OK);
    }

    let tuple_len = match tuple.tuple_len(eth_type) {
        None => return Ok(TC_ACT_OK),
        Some(tuple_len) => tuple_len,
    };

    if (tuple as *mut bpf_sock_tuple).wrapping_byte_add(tuple_len) > ctx.void_data_end().cast() {
        return Err(TC_ACT_SHOT);
    }

    ctx.set_mark(FWMARK);

    let sk = unsafe {
        bpf_skc_lookup_tcp(
            ctx.as_ptr(),
            tuple,
            tuple_len as _,
            BPF_F_CURRENT_NETNS as _,
            0,
        )
    };
    if !sk.is_null() {
        unsafe {
            if (*sk).state != BPF_TCP_LISTEN {
                debug!(ctx, "tcp tuple sk is not listen, assign self");

                let ret = bpf_sk_assign(ctx.as_ptr(), sk as _, 0);
                bpf_sk_release(sk as _);

                return Ok(ret as _);
            }

            bpf_sk_release(sk as _);
        }
    }

    debug!(ctx, "tcp tuple sk is null");

    let (src_port, dst_port) = get_tcp_ports(ctx, eth_type).ok_or(TC_ACT_OK)?;
    let index = 0 as c_int;
    unsafe {
        let sk = bpf_map_lookup_elem(
            &ASSIGN_SOCK_MAP as *const _ as *mut _,
            &index as *const _ as *const _,
        )
        .cast::<bpf_sock>();
        if sk.is_null() {
            return Err(TC_ACT_SHOT);
        }

        if (*sk).state != BPF_TCP_LISTEN {
            error!(ctx, "map stored sk is not listened");

            bpf_sk_release(sk as _);

            return Err(TC_ACT_SHOT);
        }

        let ret = bpf_sk_assign(ctx.as_ptr(), sk as _, 0);
        bpf_sk_release(sk as _);

        info!(
            ctx,
            "assign skb (from {:i}:{}, to {:i}:{}) to tcp listening sk, ret {}",
            DisplayIpAddr(src_ip),
            src_port,
            DisplayIpAddr(dst_ip),
            dst_port,
            ret
        );

        Ok(ret as _)
    }
}

fn should_proxy(ctx: &mut TcContext, dst_ip: IpAddr) -> Result<bool, c_int> {
    match dst_ip {
        IpAddr::V4(ip) => {
            let key = Key::new(32, ip.to_bits().to_be_bytes());

            let in_list_connect_directly = match PROXY_LIST_MODE.get(0) {
                None => {
                    error!(ctx, "get proxy list mode failed");

                    return Err(0);
                }

                Some(mode) => *mode == CONNECT_DIRECTLY_MODE,
            };

            let in_list = PROXY_IPV4_LIST.get(&key).copied().unwrap_or(0) > 0;
            if connect_directly(in_list_connect_directly, in_list) {
                debug!(ctx, "{:i} is direct connect ip", ip.to_bits());

                return Ok(false);
            }
        }

        IpAddr::V6(ip) => {
            let key = Key::new(128, ip.segments());

            let in_list_connect_directly = match PROXY_LIST_MODE.get(0) {
                None => {
                    error!(ctx, "get proxy list mode failed");

                    return Err(0);
                }

                Some(mode) => *mode == CONNECT_DIRECTLY_MODE,
            };

            let in_list = PROXY_IPV6_LIST.get(&key).copied().unwrap_or(0) > 0;
            if connect_directly(in_list_connect_directly, in_list) {
                debug!(ctx, "{:i} is direct connect ip", ip.octets());

                return Ok(false);
            }
        }
    }

    Ok(true)
}

fn handle_udp(
    ctx: &mut TcContext,
    src_ip: IpAddr,
    dst_ip: IpAddr,
    tuple: &mut bpf_sock_tuple,
    eth_type: EtherType,
) -> Result<c_int, c_int> {
    if !should_proxy(ctx, dst_ip)? {
        return Ok(TC_ACT_OK);
    }

    let tuple_len = match tuple.tuple_len(eth_type) {
        None => return Ok(TC_ACT_OK),
        Some(tuple_len) => tuple_len,
    };

    if (tuple as *mut bpf_sock_tuple).wrapping_byte_add(tuple_len) > ctx.void_data_end().cast() {
        return Err(TC_ACT_SHOT);
    }

    ctx.set_mark(FWMARK);

    let sk = unsafe {
        bpf_sk_lookup_udp(
            ctx.as_ptr(),
            tuple,
            tuple_len as _,
            BPF_F_CURRENT_NETNS as _,
            0,
        )
    };

    if !sk.is_null() {
        unsafe {
            let ret = bpf_sk_assign(ctx.as_ptr(), sk as _, 0);
            bpf_sk_release(sk as _);

            return Ok(ret as _);
        }
    }

    debug!(ctx, "udp tuple sk is null");

    let (src_port, dst_port) = get_udp_ports(ctx, eth_type).ok_or(TC_ACT_OK)?;
    let index = 0 as c_int;
    unsafe {
        let sk = bpf_map_lookup_elem(
            &ASSIGN_SOCK_MAP as *const _ as *mut _,
            &index as *const _ as *const _,
        )
        .cast::<bpf_sock>();
        if sk.is_null() {
            return Err(TC_ACT_SHOT);
        }

        let ret = bpf_sk_assign(ctx.as_ptr(), sk as _, 0);
        bpf_sk_release(sk as _);

        info!(
            ctx,
            "assign skb (from {:i}:{}, to {:i}:{}) to udp sk, ret {}",
            DisplayIpAddr(src_ip),
            src_port,
            DisplayIpAddr(dst_ip),
            dst_port,
            ret
        );

        Ok(ret as _)
    }
}

struct TupleWithAddrs {
    bpf_sock_tuple: NonNull<bpf_sock_tuple>,
    ether_type: EtherType,
    ip_proto: IpProto,
    src: IpAddr,
    dst: IpAddr,
}

fn get_tuple(ctx: &mut TcContext) -> Option<TupleWithAddrs> {
    let data_end = ctx.void_data_end();
    let data = ctx.void_data();

    let eth_hdr = data.cast::<EthHdr>();
    if eth_hdr.wrapping_add(1) > data_end.cast() {
        return None;
    }
    let eth_hdr = unsafe { &mut *eth_hdr };
    let ether_type = eth_hdr.ether_type;

    match ether_type {
        EtherType::Ipv4 => {
            let ip_hdr = data
                .wrapping_byte_add(size_of::<EthHdr>())
                .cast::<Ipv4Hdr>();
            if ip_hdr.wrapping_add(1) > data_end.cast() {
                return None;
            }

            let ip_hdr = unsafe { &mut *ip_hdr };
            if ip_hdr.ihl() != 5 {
                // Options are not supported
                return None;
            }

            let tuple = addr_of_mut!(ip_hdr.src_addr) as _;

            Some(TupleWithAddrs {
                bpf_sock_tuple: NonNull::new(tuple).unwrap(),
                ether_type,
                ip_proto: ip_hdr.proto,
                src: IpAddr::V4(Ipv4Addr::from_bits(u32::from_be(ip_hdr.src_addr))),
                dst: IpAddr::V4(Ipv4Addr::from_bits(u32::from_be(ip_hdr.dst_addr))),
            })
        }

        EtherType::Ipv6 => {
            let ip_hdr = data
                .wrapping_byte_add(size_of::<EthHdr>())
                .cast::<Ipv6Hdr>();
            if ip_hdr.wrapping_add(1) > data_end.cast() {
                return None;
            }

            let ip_hdr = unsafe { &mut *ip_hdr };
            let tuple = addr_of_mut!(ip_hdr.src_addr) as _;

            unsafe {
                Some(TupleWithAddrs {
                    bpf_sock_tuple: NonNull::new(tuple).unwrap(),
                    ether_type,
                    ip_proto: ip_hdr.next_hdr,
                    src: IpAddr::V6(Ipv6Addr::from(ip_hdr.src_addr.in6_u.u6_addr8)),
                    dst: IpAddr::V6(Ipv6Addr::from(ip_hdr.dst_addr.in6_u.u6_addr8)),
                })
            }
        }

        _ => {
            let ether_type = u16::from_be(ether_type as u16);
            debug!(ctx, "other ether type {:x}", ether_type);

            None
        }
    }
}

trait TcContextExt {
    fn void_data(&mut self) -> *mut c_void;

    fn void_data_end(&mut self) -> *mut c_void;
}

impl TcContextExt for TcContext {
    #[inline]
    fn void_data(&mut self) -> *mut c_void {
        self.data() as c_long as _
    }

    #[inline]
    fn void_data_end(&mut self) -> *mut c_void {
        self.data_end() as c_long as _
    }
}

trait BpfSockTupleExt {
    fn tuple_len(&self, eth_type: EtherType) -> Option<usize>;
}

impl BpfSockTupleExt for bpf_sock_tuple {
    #[inline]
    fn tuple_len(&self, eth_type: EtherType) -> Option<usize> {
        unsafe {
            match eth_type {
                EtherType::Ipv4 => Some(size_of_val(&self.__bindgen_anon_1.ipv4)),

                EtherType::Ipv6 => Some(size_of_val(&self.__bindgen_anon_1.ipv6)),

                _ => None,
            }
        }
    }
}

#[repr(transparent)]
struct DisplayIpAddr(IpAddr);

impl IpFormatter for DisplayIpAddr {}

impl WriteToBuf for DisplayIpAddr {
    #[inline]
    fn write(self, buf: &mut [u8]) -> Option<NonZeroUsize> {
        match self.0 {
            IpAddr::V4(ip) => {
                let ip = ip.to_bits();
                ip.write(buf)
            }
            IpAddr::V6(ip) => {
                let ip = ip.octets();
                ip.write(buf)
            }
        }
    }
}
