use arraydeque::{ArrayDeque, Wrapping};
use afxdp::buf_mmap::BufMmap;
use afxdp::PENDING_LEN;
use super::xdpworker::BufCustom;

pub trait Analyzer: Send + Sync {
    fn analyze(&self, data: &mut ArrayDeque<[BufMmap<BufCustom>; PENDING_LEN], Wrapping>);
}