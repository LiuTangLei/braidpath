//! Internal packet I/O: direct legacy UDP or a demultiplexed flow on shared sockets.
use crate::{datagram::{Datagram,try_send_batch},multiplex::FlowIo};
use std::{io,net::SocketAddr,sync::Arc,time::Instant};
use tokio::net::UdpSocket;

#[derive(Clone)]
pub(crate) enum PacketSocket {Direct(Arc<UdpSocket>),Flow(Arc<FlowIo>)}
pub(crate) enum PacketSender {Direct(std::net::UdpSocket),Flow(Arc<FlowIo>)}
impl From<Arc<UdpSocket>> for PacketSocket{fn from(socket:Arc<UdpSocket>)->Self{Self::Direct(socket)}}
impl PacketSocket {
    pub fn mark_clean(&self){if let Self::Flow(flow)=self{flow.mark_clean();}}
    pub fn finish_clean(&self,session:u64,extent:u64)->io::Result<bool>{
        match self{Self::Direct(_)=>Ok(false),Self::Flow(flow)=>flow.finish_clean(session,extent)}
    }
    pub async fn recv_from(&self,buf:&mut[u8])->io::Result<(usize,SocketAddr)>{match self{Self::Direct(s)=>s.recv_from(buf).await,Self::Flow(s)=>s.recv_from(buf).await}}
    pub async fn send_to(&self,buf:&[u8],to:SocketAddr)->io::Result<usize>{match self{Self::Direct(s)=>s.send_to(buf,to).await,Self::Flow(s)=>s.send_to(buf,to).await}}
    pub fn sender(&self)->io::Result<PacketSender>{match self{Self::Direct(s)=>Ok(PacketSender::Direct(socket2::SockRef::from(&**s).try_clone()?.into())),Self::Flow(s)=>Ok(PacketSender::Flow(s.clone()))}}
    pub fn physical_peers(&self,peers:&[SocketAddr])->Vec<SocketAddr>{match self{Self::Direct(_)=>peers.to_vec(),Self::Flow(f)=>f.physical_peers()}}
    pub fn access_weights(&self)->Option<Vec<u32>>{match self{Self::Flow(f)=>Some(f.weights()),Self::Direct(_)=>None}}
}
impl PacketSender {
    pub fn wire_size(&self,packet:&Datagram)->io::Result<usize>{match self{Self::Direct(_)=>Ok(packet.payload.len()+if packet.destination.is_ipv6(){48}else{28}),Self::Flow(f)=>f.wire_size(packet)}}
    pub fn reserve(&self,packets:&[Datagram],base:Instant)->io::Result<Instant>{match self{Self::Direct(_)=>Ok(base),Self::Flow(f)=>f.reserve(packets,base)}}
    pub fn send_batch(&self,packets:&[Datagram])->io::Result<usize>{match self{Self::Direct(s)=>try_send_batch(s,packets),Self::Flow(f)=>f.send_batch(packets)}}
}
