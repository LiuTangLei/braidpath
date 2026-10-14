//! Managed multi-service TCP tunnel. Each TCP connection has independent FEC,
//! ACK/recovery and flow control. Physical sockets, WAN budgets and membership
//! are shared, so more TCP ports do not multiply the configured access capacity.
use crate::{control::{self,ConfigFile,MasterFile,NodeFile,Registry,Role,Snapshot},session,
    multiplex::{Hub,LinkSocket,Route,RelayTable,MAX_FLOWS,LANES,ENTRANCES},configuration::{self,LocalForward}};
use serde_json::json;
use std::{io,net::{IpAddr,SocketAddr},path::Path,sync::Arc,time::{Duration,Instant}};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::{TcpListener,TcpStream,UdpSocket},sync::{watch,mpsc},task::{AbortHandle,JoinHandle,JoinSet}};
fn error(v:impl std::fmt::Display)->io::Error{io::Error::other(v.to_string())}
fn emit(value:serde_json::Value){crate::cli_output::emit(value);}
struct Jobs(Vec<AbortHandle>);
impl Drop for Jobs{fn drop(&mut self){for task in &self.0{task.abort();}}}
impl Jobs{fn add<T>(&mut self,task:&JoinHandle<T>){self.0.push(task.abort_handle());}}

pub fn udp(bind:SocketAddr,ifindex:Option<u32>)->io::Result<Arc<UdpSocket>>{
    use socket2::{Domain,Protocol,Socket,Type};
    let sock=Socket::new(if bind.is_ipv4(){Domain::IPV4}else{Domain::IPV6},Type::DGRAM,Some(Protocol::UDP))?;
    sock.set_nonblocking(true)?;sock.set_recv_buffer_size(2*1024*1024)?;sock.set_send_buffer_size(256*1024)?;
    if bind.is_ipv6(){sock.set_only_v6(true)?;}
    configuration::bind_interface(&socket2::SockRef::from(&sock),bind.is_ipv6(),ifindex)?;
    sock.bind(&bind.into())?;Ok(Arc::new(UdpSocket::from_std(sock.into())?))
}
async fn transfer(tcp:&mut TcpStream,stream:&mut tokio::io::DuplexStream,client:bool)->io::Result<()> {
    if !client {tokio::io::copy_bidirectional(tcp,stream).await?;return Ok(());}
    let(mut tcp_read,mut tcp_write)=tcp.split();let(mut read,mut write)=tokio::io::split(stream);
    // Pipeline application upload with the service-open request. Only downstream
    // bytes wait for the status byte, avoiding one extra WAN RTT on every connect.
    let upload=async{tokio::io::copy(&mut tcp_read,&mut write).await?;write.shutdown().await};
    let download=async{
        let status=tokio::time::timeout(Duration::from_secs(10),read.read_u8()).await.map_err(error)??;
        if status!=0{return Err(error(format!("remote service unavailable (status {status})")));}
        tokio::io::copy(&mut read,&mut tcp_write).await?;tcp_write.shutdown().await
    };
    tokio::try_join!(upload,download)?;Ok(())
}
fn configure_tcp(tcp:&TcpStream,low_latency:bool)->io::Result<()> {
    tcp.set_nodelay(true)?;
    if low_latency {
        let socket=socket2::SockRef::from(tcp);
        socket.set_tcp_keepalive(&socket2::TcpKeepalive::new().with_time(Duration::from_secs(30)).with_interval(Duration::from_secs(10)))?;
        // Bound unsent TCP data without shrinking the in-flight congestion window.
        #[cfg(target_os="linux")]
        socket.set_tcp_notsent_lowat(16*1024)?;
    }
    Ok(())
}
async fn bridge(mut tcp:TcpStream,mut channel:session::Session,service:&str,client:bool,low_latency:bool)->io::Result<()> {
    configure_tcp(&tcp,low_latency)?;let _owned=Jobs(vec![channel.task.abort_handle()]);
    let copy=transfer(&mut tcp,&mut channel.stream,client);tokio::pin!(copy);
    let report=tokio::select!{
        completed=&mut channel.task=>{let report=completed.map_err(error)??;copy.await?;report},
        result=&mut copy=>{result?;channel.task.await.map_err(error)??},
    };
    let wan_sources=report.path_source_packets.chunks(ENTRANCES).map(|v|v.iter().sum::<u64>()).collect::<Vec<_>>();
    emit(json!({"event":"managed_session","service":service,"session":report.session_id,"tx_bytes":report.tx_payload_bytes,
        "rx_bytes":report.rx_payload_bytes,"retries":report.tx_retries,"max_stall_ms":report.max_ordered_stall_ms,
        "wire_bytes":report.tx_wire_bytes,"local_send_drops":report.tx_local_send_drops,
        "topology_updates":report.topology_updates,"path_addresses":report.path_addresses,
        "source_packets":report.path_source_packets,"wan_source_packets":wan_sources,"elapsed_s":report.elapsed_s}));Ok(())
}
fn admitted_clients(snapshot:&Snapshot)->Vec<IpAddr>{
    let online=snapshot.clients();
    if online.is_empty(){snapshot.members.iter().filter(|n|n.role==Role::Client&&!n.revoked)
        .flat_map(|n|std::iter::once(n.public_ip).chain(n.accesses.iter().map(|a|a.public_ip))).collect()}else{online}
}
fn rates(snapshot:&Snapshot)->Vec<u32>{
    let client=snapshot.members.iter().find(|n|n.role==Role::Client&&!n.revoked&&n.online)
        .or_else(||snapshot.members.iter().rev().find(|n|n.role==Role::Client&&!n.revoked));
    let mut rates=vec![snapshot.tuning.download_wire_mbps];
    if let Some(client)=client{for a in &client.accesses{if a.slot<4{
        rates.resize(rates.len().max(a.slot+1),snapshot.tuning.download_wire_mbps);rates[a.slot]=a.download_wire_mbps;
    }}}rates
}
async fn requested_service<R:AsyncReadExt+Unpin>(reader:&mut R)->io::Result<String>{
    let mut header=[0;5];reader.read_exact(&mut header).await?;
    if &header[..4]!=b"SVC2"||header[4]==0||header[4]>48{return Err(error("invalid service-open request"));}
    let mut name=vec![0;header[4]as usize];reader.read_exact(&mut name).await?;
    let name=String::from_utf8(name).map_err(error)?;
    if !configuration::name_valid(&name){return Err(error("invalid service name"));}Ok(name)
}
async fn master(settings:MasterFile,path:&Path)->io::Result<()> {
    let filename=path.file_name().ok_or_else(||error("state filename required"))?.to_string_lossy();let lock_path=path.with_file_name(format!("{filename}.lock"));
    if std::fs::symlink_metadata(&lock_path).is_ok_and(|m|!m.is_file()){return Err(error("nonregular lock file"));}
    let mut options=std::fs::OpenOptions::new();options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]{use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
    let lock=options.open(lock_path)?;lock.try_lock().map_err(error)?;
    let listener=TcpListener::bind(settings.control_bind).await?;let network=udp(settings.data_bind,None)?;
    let registry=Registry::new(settings.clone(),path.to_owned())?;let mut changes=registry.subscribe();
    let(hub,mut incoming)=Hub::server(network,settings.tuning.download_wire_mbps,vec![settings.tuning.download_wire_mbps])?;
    let mut jobs=Jobs(Vec::new());let control=tokio::spawn(control::serve(listener,registry));jobs.add(&control);
    let route_hub=hub.clone();let mapper=tokio::spawn(async move{loop{
        let snapshot=changes.borrow_and_update().clone();
        route_hub.set_admission(admitted_clients(&snapshot),snapshot.relays())?;
        route_hub.set_access_rates(rates(&snapshot),snapshot.tuning.download_wire_mbps)?;
        emit(json!({"event":"topology","side":"master","revision":snapshot.revision,"peers":snapshot.client_paths()}));
        if changes.changed().await.is_err(){return Ok::<(),io::Error>(());}
    }});jobs.add(&mapper);
    let services=Arc::new(settings.services());let cfg=settings.tuning.config(true)?;
    let allow_warm=settings.tuning.warm_sessions>0;
    emit(json!({"event":"ready","role":"managed-master","control":settings.control_bind,"udp_bind":settings.data_bind,
        "services":&*services,"one_active_stream":false,"max_connections":MAX_FLOWS,
        "profile":if cfg.low_latency{"latency"}else{"balanced"},"warm_sessions":settings.tuning.warm_sessions}));
    let service=async{
        let mut streams=JoinSet::new();loop{tokio::select!{
            flow=incoming.recv()=>{
                let flow=flow.ok_or_else(||error("incoming multiplexer closed"))?;let cfg=cfg.clone();let services=services.clone();
                streams.spawn(async move{
                    let result:io::Result<()>=async{
                        let low_latency=cfg.low_latency;
                        let mut channel=session::multiplexed(flow,cfg,false).await?;
                        let owned=Jobs(vec![channel.task.abort_handle()]);
                        // Unused warmed transports have no target socket and may
                        // remain idle indefinitely while peer heartbeats are live.
                        let requested=tokio::select! {
                            request=requested_service(&mut channel.stream)=>request?,
                            completed=&mut channel.task=>{
                                completed.map_err(error)??;
                                return Err(error("session closed before service selection"));
                            },
                            _=tokio::time::sleep(Duration::from_secs(10)),if !allow_warm=>{
                                return Err(error("service-open timeout"));
                            },
                        };
                        // Resolve a NAME on the master, never a stale list index.
                        // Reordering its target configuration cannot cross-connect services.
                        let Some(target)=services.iter().find(|s|s.service==requested)else{
                            channel.stream.write_all(&[1]).await?;channel.stream.shutdown().await?;return Err(error("unconfigured service requested"));
                        };
                        let connected=tokio::time::timeout(Duration::from_secs(5),TcpStream::connect(target.target)).await;
                        match connected{
                            Ok(Ok(tcp))=>{channel.stream.write_all(&[0]).await?;bridge(tcp,channel,&target.service,false,low_latency).await?;},
                            _=>{channel.stream.write_all(&[2]).await?;channel.stream.shutdown().await?;return Err(error("configured target unavailable"));}
                        }drop(owned);Ok(())
                    }.await;
                    if let Err(e)=result{emit(json!({"event":"session_error","error":e.to_string()}));}
                });
            },
            _=streams.join_next(),if !streams.is_empty()=>{},
        }}
    };
    tokio::select!{result=service=>result,result=control=>result.map_err(error)?,result=mapper=>result.map_err(error)?}
}
async fn first_snapshot(updates:&mut watch::Receiver<Option<Snapshot>>)->io::Result<Snapshot>{
    tokio::time::timeout(Duration::from_secs(15),async{loop{
        if let Some(snapshot)=updates.borrow_and_update().clone(){return Ok(snapshot);}
        updates.changed().await.map_err(error)?;
    }}).await.map_err(error)?
}
/// Stable entrance slots are never reassigned to a different endpoint while the
/// process lives. At most eight distinct entrances; further churn needs restart.
struct EntranceSlots{addresses:Vec<SocketAddr>}
impl EntranceSlots{
    fn routes(&mut self,wanted:&[SocketAddr],links:usize)->io::Result<Vec<Option<Route>>>{
        for address in wanted{if !self.addresses.contains(address){
            if self.addresses.len()==ENTRANCES{return Err(error("entrance history full; restart after excessive endpoint churn"));}
            self.addresses.push(*address);
        }}
        let mut routes=vec![None;LANES];for link in 0..links{for (entry,address)in self.addresses.iter().enumerate(){
            if wanted.contains(address){routes[link*ENTRANCES+entry]=Some(Route{socket:link,destination:*address});}
        }}Ok(routes)
    }
}
async fn client(node:NodeFile,mut updates:watch::Receiver<Option<Snapshot>>)->io::Result<()> {
    let initial=first_snapshot(&mut updates).await?;let cfg=initial.tuning.config(false)?;
    let count=node.uplinks.len().max(1);let mut sockets=Vec::new();
    for slot in 0..count{
        let access=node.on_access(slot)?;let rate=node.uplinks.get(slot).map_or(cfg.wire_mbps,|u|u.upload_wire_mbps);
        sockets.push(LinkSocket{socket:udp(access.data_bind,access.ifindex)?,wire_mbps:rate});
    }
    let hub=Hub::client(sockets,cfg.wire_mbps)?;let mut slots=EntranceSlots{addresses:Vec::new()};
    hub.set_routes(slots.routes(&initial.client_paths(),count)?)?;
    let pool=crate::warm::SessionPool::new(hub.clone(),cfg.clone(),initial.tuning.warm_sessions,initial.epoch);
    let local=if node.forwards.is_empty(){vec![LocalForward{service:initial.services.first().cloned().unwrap_or_else(||"default".into()),listen:node.listen}]}else{node.forwards.clone()};
    let mut listeners=Vec::new();let mut addresses=Vec::new();
    // Resolve and bind ALL forwards before accepting any connection. A typo or
    // occupied port cannot leave a half-configured forwarding service running.
    for forward in &local{
        if !initial.services.contains(&forward.service){return Err(error(format!("unknown service {}",forward.service)));}
        let listener=TcpListener::bind(forward.listen).await?;
        addresses.push(json!({"service":forward.service,"listen":listener.local_addr()?}));listeners.push((forward.service.clone(),listener));
    }
    let route_hub=hub.clone();let route_pool=pool.clone();let mapper=tokio::spawn(async move{loop{
        if let Some(snapshot)=updates.borrow_and_update().clone(){
            route_hub.set_routes(slots.routes(&snapshot.client_paths(),count)?)?;
            route_pool.set_epoch(snapshot.epoch);
            emit(json!({"event":"topology","side":"client","revision":snapshot.revision,"peers":snapshot.client_paths()}));
        }
        if updates.changed().await.is_err(){return Ok::<(),io::Error>(());}
    }});
    let mut jobs=Jobs(vec![mapper.abort_handle()]);let(tx,mut accepted)=mpsc::channel(MAX_FLOWS);
    let warm=pool.start();jobs.add(&warm);pool.prime().await?;
    for(name,listener)in listeners{
        let tx=tx.clone();let task=tokio::spawn(async move{loop{
            let Ok((tcp,_))=listener.accept().await else{break;};
            // Bounded overload: reject a new connection, never block other ports.
            let _=tx.try_send((name.clone(),tcp));
        }});jobs.add(&task);
    }drop(tx);
    emit(json!({"event":"ready","role":"managed-client","tcp_listen":addresses[0]["listen"],"forwards":addresses,
        "node_id":node.id,"one_active_stream":false,"uplinks":count,"max_connections":MAX_FLOWS,
        "profile":if cfg.low_latency{"latency"}else{"balanced"},"warm_sessions":initial.tuning.warm_sessions}));
    let mut streams=JoinSet::new();loop{tokio::select!{
        result=accepted.recv()=>{
            let(name,tcp)=result.ok_or_else(||error("forward listeners stopped"))?;
            let pool=pool.clone();let low_latency=cfg.low_latency;streams.spawn(async move{
                let result:io::Result<()>=async{
                    tcp.set_nodelay(true)?;let start=Instant::now();
                    let(mut channel,warmed)=pool.checkout().await?;let owned=Jobs(vec![channel.task.abort_handle()]);
                    emit(json!({"event":"session_open","service":name,"warm":warmed,"setup_ms":start.elapsed().as_secs_f64()*1000.0}));
                    let mut open=b"SVC2".to_vec();open.push(name.len()as u8);open.extend_from_slice(name.as_bytes());channel.stream.write_all(&open).await?;
                    bridge(tcp,channel,&name,true,low_latency).await?;drop(owned);Ok(())
                }.await;
                if let Err(e)=result{emit(json!({"event":"session_error","service":name,"error":e.to_string()}));}
            });
        },
        _=streams.join_next(),if !streams.is_empty()=>pool.wake(),
    }}
}
/// Mux flows and WAN lanes have independent return mappings, not one global
/// learned client tuple. Revoked addresses are removed on the next topology push.
pub async fn relay_loop(socket:Arc<UdpSocket>,mut updates:watch::Receiver<Option<Snapshot>>)->io::Result<()> {
    let mut snapshot=first_snapshot(&mut updates).await?;let mut table=RelayTable::default();
    table.set_low_latency(snapshot.tuning.low_latency);
    let mut timer=tokio::time::interval(Duration::from_secs(1));let mut buf=[0u8;1600];
    loop{tokio::select!{
        changed=updates.changed()=>{
            changed.map_err(error)?;if let Some(value)=updates.borrow_and_update().clone(){snapshot=value;}
            table.set_low_latency(snapshot.tuning.low_latency);
            table.prune(Instant::now(),&admitted_clients(&snapshot));
        },
        _=timer.tick()=>table.prune(Instant::now(),&admitted_clients(&snapshot)),
        packet=socket.recv_from(&mut buf)=>{
            let(n,from)=packet?;
            if let Some(to)=table.route(&buf[..n],from,snapshot.master,&admitted_clients(&snapshot),Instant::now()){
                socket.send_to(&buf[..n],to).await?;
            }
        },
    }}
}
async fn node(node:NodeFile)->io::Result<()> {
    let(updates,watch)=watch::channel(None);let mut jobs=Jobs(Vec::new());
    let count=if node.role==Role::Client{node.uplinks.len().max(1)}else{1};
    for slot in 0..count{let feed=tokio::spawn(control::follow(node.on_access(slot)?,updates.clone()));jobs.add(&feed);}
    match node.role{
        Role::Client=>client(node,watch).await,
        Role::Relay=>{
            let socket=udp(node.data_bind,node.ifindex)?;
            emit(json!({"event":"ready","role":"managed-relay","udp_bind":socket.local_addr()?,"node_id":node.id}));
            relay_loop(socket,watch).await
        }
    }
}
pub async fn run(path:&Path)->io::Result<()> {match ConfigFile::read(path)?{ConfigFile::Master(settings)=>master(settings,path).await,ConfigFile::Node(settings)=>node(settings).await}}

#[cfg(test)]
mod tests{
    use super::*;
    #[tokio::test]
    async fn service_open_is_a_bounded_name_and_keeps_pipelined_data(){
        let mut wire=&b"SVC2\x03sshGET / HTTP/1.1\r\n"[..];
        assert_eq!(requested_service(&mut wire).await.unwrap(),"ssh");
        assert_eq!(wire,b"GET / HTTP/1.1\r\n");
        for wire in [&b"SVC1\x03ssh"[..],&b"SVC2\x00"[..],&b"SVC2\xff"[..],&b"SVC2\x03a/b"[..],&b"SVC2\x03ss"[..]]{
            let mut wire=wire;assert!(requested_service(&mut wire).await.is_err());
        }
    }
    #[tokio::test]
    async fn named_service_does_not_change_when_master_list_is_reordered(){
        let mut wire=&b"SVC2\x04beta"[..];let wanted=requested_service(&mut wire).await.unwrap();
        let mut services=[control::Forward{service:"alpha".into(),target:"127.0.0.1:8001".parse().unwrap()},
            control::Forward{service:"beta".into(),target:"127.0.0.1:8002".parse().unwrap()}];
        services.reverse();assert_eq!(services.iter().find(|s|s.service==wanted).unwrap().target.port(),8002);
    }
}
