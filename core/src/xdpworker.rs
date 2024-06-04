use arraydeque::{ArrayDeque, Wrapping};
use rebpf::{interface, libbpf};
use std::cmp::{min, max};
use std::sync::{mpsc::Sender, Arc, Mutex};
use std::thread;
use num_cpus;

use afxdp::mmap_area::{MmapArea, MmapAreaOptions};
use afxdp::socket::{Socket, SocketOptions, SocketRx, SocketTx};
use afxdp::umem::{Umem, UmemCompletionQueue, UmemFillQueue};
use afxdp::PENDING_LEN;
use afxdp::{buf::Buf, buf_pool::BufPool};
use afxdp::{buf_mmap::BufMmap, buf_pool_vec::BufPoolVec};
use libbpf_sys::{XSK_RING_CONS__DEFAULT_NUM_DESCS, XSK_RING_PROD__DEFAULT_NUM_DESCS, XDP_OPTIONS_ZEROCOPY};
use pnet::packet::ethernet::EtherTypes;
use pnet::packet::ethernet::MutableEthernetPacket;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::{MutablePacket, Packet};

use libbpf_sys;
use libc;
use std::ffi::CString;

use super::alerts::AlertMsg;
use super::analyzer_t::Analyzer;
// use super::yara_helpers::compile_rules_from_dir;
// use super::packet_analysis::analyze_ethernet_frame;

const BUF_NUM: usize = 65536;
const BUF_LEN: usize = 4096;
const BATCH_SIZE: usize = 64;


#[derive(Default, Copy, Clone, Debug)]
pub struct BufCustom {}


pub struct XDPWorker<'a> {
    core: usize,
    interface: interface::Interface,

    rx: SocketRx<'a, BufCustom>,
    // cq: UmemCompletionQueue<'a, BufCustom>,
    fq: UmemFillQueue<'a, BufCustom>,

    buf_pool: Arc<Mutex<BufPoolVec<BufMmap<'a, BufCustom>, BufCustom>>>,
}


impl<'a>  XDPWorker<'a> {
    pub fn new(interface_name: String, xdp_flags: libbpf::XdpFlags, analysis_thread_n: usize) -> XDPWorker<'a>  {
        // Get and prepare xdp interface
        let interface = interface::get_interface(&interface_name).unwrap();
        //self.interface = interface;
        let _ = libbpf::bpf_set_link_xdp_fd(&interface, None, xdp_flags).unwrap();

        // Allocate user memory map
        let options = MmapAreaOptions { huge_tlb: false };
        let r = MmapArea::new(BUF_NUM, BUF_LEN, options);
        let (area, mut bufs) = match r {
            Ok((area, bufs)) => (area, bufs),
            Err(err) => panic!("Unable to create mmap for XDP: {:?}", err),
        };

        // Add all the Bufs to the global Buf pool
        let mut bp: BufPoolVec<BufMmap<BufCustom>, BufCustom> = BufPoolVec::new(bufs.len());
        let len = bufs.len();
        let r = bp.put(&mut bufs, len);
        assert!(r == len);

        // Prepare for multithreading (in case we want in a future to have multiple workers per interface (Requires multiple RX Queues))
        let bp = Arc::new(Mutex::new(bp));

        // Prepare user memory
        let r = Umem::new(
            area.clone(),
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            XSK_RING_PROD__DEFAULT_NUM_DESCS,
        );
        let (umem1, _, mut umem1fq) = match r {
            Ok(umem) => umem,
            Err(err) => panic!("Unable to create umem for XDP load balancing: {:?}", err),
        };

        // Create the AF_XDP socket
        let mut sock_opts = SocketOptions::default();
        sock_opts.copy_mode = true;
        //sock_opts.zero_copy_mode = true; TODO

        let sock_r = Socket::new_rx(
            umem1.clone(),
            &interface_name,
            0, // Currently hardcoded to RX Queue 0 TODO: Multithread with multiple queues
            XSK_RING_CONS__DEFAULT_NUM_DESCS,
            sock_opts,
        );
        let (_, socket_rx) = match sock_r {
            Ok(socket) => socket,
            Err(err) => {
                panic!(
                    "Unable to create XSK for XDP: {:?}", err
                );
                //continue;
            }
        };

        let threads = min(max(analysis_thread_n, 1), num_cpus::get());
        println!("XDPWorker initialized with {} threads", threads);
        XDPWorker {
            core: 0,

            interface: interface,

            rx: socket_rx,
            fq: umem1fq,

            buf_pool: bp,
        }
    }

    // This function is used to cleanly disconnect the XDP program from the interface
    pub fn disconnect(&mut self) {
        unsafe {
            libbpf_sys::bpf_set_link_xdp_fd(self.interface.ifindex() as i32, -1, 0);
        }
    }

    pub fn run(&mut self, frame_sender: crossbeam_channel::Sender<Vec<u8>>) {
        let mut v: ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping> = ArrayDeque::new();
        let mut fq_deficit = 0;

        let core = core_affinity::CoreId { id: self.core };
        core_affinity::set_for_current(core);

        const START_BUFS: usize = 8192;

        let mut bufs = Vec::with_capacity(START_BUFS);

        let r = self.buf_pool.lock().unwrap().get(&mut bufs, START_BUFS);
        if r != START_BUFS {
            println!(
                "Failed to get initial bufs. Wanted {} got {}",
                START_BUFS, r
            );
        }

        // Initial fill of the worker UMEM // Prepared for multiple threads...
        let r = self.fq.fill(
            &mut bufs,
            min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM),
        );
        match r {
            Ok(n) => {
                if n != min(XSK_RING_PROD__DEFAULT_NUM_DESCS as usize, BUF_NUM) {
                    panic!(
                        "Initial fill of umem incomplete. Wanted {} got {}.",
                        BUF_NUM, n
                    );
                }
            }
            Err(err) => panic!("error: {:?}", err),
        }

        println!("Starting XDP Loop");
        let custom = BufCustom {};
        loop {
            // Receive ring
            let r = self.rx.try_recv(&mut v, BATCH_SIZE, custom);
            match r {
                Ok(n_pkt) => {
                    if n_pkt > 0 {
                        println!("XDP worker {:?} Received {:?} packets", self.core, n_pkt);
                        
                        for frame in v.drain(0..) {
                            //let packet = EthernetPacket::new(frame).unwrap();
                            // println!("Packet 1: {:?}", frame.get_data());
                            let data_copy = frame.get_data().to_vec();
                            // println!("Packet 2: {:?}", data_copy);
                            frame_sender.send(data_copy).unwrap();
                        }

                        fq_deficit += n_pkt;
                    } else {
                        if self.fq.needs_wakeup() {
                            self.rx.wake();
                        }
                    }
                }
                Err(err) => {
                    println!("XDP: {:?}", err);
                }
            }

            // Fill the fill ring
            if fq_deficit > 0 {
                let r = self.fq.fill(&mut bufs, fq_deficit);
                match r {
                    Ok(n) => {
                        fq_deficit -= n;
                    }
                    Err(err) => panic!("error: {:?}", err),
                }
            }
        }
    }
}