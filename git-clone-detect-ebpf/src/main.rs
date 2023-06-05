#![no_std]
#![no_main]

use core::mem;

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_log_ebpf::info;

// use pnet_packet::ip::IpNextHeaderProtocols;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    tcp::TcpHdr,
    udp::UdpHdr,
};


#[xdp(name = "git_clone_detect")]
pub fn git_clone_detect(ctx: XdpContext) -> u32 {
    match try_git_clone_detect(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

fn try_git_clone_detect(ctx: XdpContext) -> Result<u32, ()> {
    // info!(&ctx, "received a packet");
    // Ok(xdp_action::XDP_PASS)
    let ethhdr: *const EthHdr = unsafe { ptr_at(&ctx, 0)? };
    match unsafe { *ethhdr }.ether_type {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *const Ipv4Hdr = unsafe { ptr_at(&ctx, EthHdr::LEN)? };
    let source_addr = u32::from_be(unsafe { *ipv4hdr }.src_addr);
    let dest_addr = u32::from_be(unsafe { *ipv4hdr }.dst_addr);

    let source_port = match unsafe { *ipv4hdr }.proto {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            u16::from_be(unsafe { *tcphdr }.source)
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr =
                unsafe { ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN) }?;
            u16::from_be(unsafe { *udphdr }.source)
        }
        _ => return Err(()),
    };

    info!(&ctx, "SRC IP: {}, SRC PORT: {}, DST IP: {}", source_addr, source_port, dest_addr);

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
