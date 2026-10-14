//! Experimental FEC tunnel. Managed mode supports named TCP services, independent
//! concurrent streams and client multi-WAN sockets. Raw diagnostic modes retain
//! single-stream behavior. Control TLS does not encrypt the UDP data plane.
use aggligator_fec::{Config,session::{self,SessionConfig,SessionReport}};
use clap::Parser;
#[path="support/help.rs"] mod help;
use serde_json::json;
use socket2::{Domain,Protocol,Socket,Type};
use std::{io,net::{IpAddr,SocketAddr},num::NonZeroU32,sync::Arc,time::Duration};
use tokio::{io::{AsyncReadExt,AsyncWriteExt},net::{TcpListener,TcpStream,UdpSocket}};

#[derive(Parser,Debug)]
#[command(version,about="Experimental fixed-peer FEC TCP tunnel (not encrypted; inner authentication required)")]
struct Args {
    /// init/join/run/status/invite/rotate/revoke (managed feature), or raw client/server/relay.
    role:String,
    #[arg(long)] json:bool,
    /// Owner-only JSON credential/config file. Never put it in a public repository.
    #[arg(long,default_value="agg-fec.json")] state:Option<std::path::PathBuf>,
    /// Advertised TLS control endpoint for init; numeric IPv4/IPv6 address.
    #[arg(long)] control:Option<SocketAddr>,
    /// Advertised UDP endpoint for a master or relay.
    #[arg(long)] advertise:Option<SocketAddr>,
    /// Enrollment role; the same invitation accepts client or relay.
    #[arg(long="as",default_value="client")] node_role:String,
    #[arg(long,default_value="node")] name:String,
    /// Prefer reading the invite from stdin rather than leaving it in shell history.
    #[arg(long,conflicts_with="invite_file")] invite:Option<String>,
    #[arg(long)] invite_file:Option<std::path::PathBuf>,
    #[arg(long,allow_hyphen_values=true)] node_id:Option<String>,
    #[arg(long,default_value="127.0.0.1:0")] bind:SocketAddr,
    #[arg(long)] peer:Vec<SocketAddr>,
    #[arg(long,default_value="127.0.0.1:0")] listen:SocketAddr,
    #[arg(long)] target:Option<SocketAddr>,
    /// Repeat on init: SERVICE=TARGET; repeat on join: SERVICE=LOCAL-LISTEN.
    #[arg(long)] forward:Vec<String>,
    /// latency: immediate path replication and warm sessions; balanced: prior RC comparison.
    #[arg(long,default_value="latency",value_parser=["latency","balanced"])] profile:String,
    /// Global unused session reserve, shared across all services (0..16).
    #[arg(long)] warm_sessions:Option<usize>,
    /// Client WAN: INTERFACE=UPLOAD/DOWNLOAD wire Mbps; repeat for independent links.
    /// For explicit-source labs: NAME@SOURCE_IP=UPLOAD/DOWNLOAD.
    #[arg(long,conflicts_with_all=["interface","ifindex"])] uplink:Vec<String>,
    /// Shared client upload cap across all concurrent TCP streams.
    #[arg(long,default_value_t=80)] upload_wire_mbps:u32,
    #[arg(long)] main:Option<SocketAddr>,
    #[arg(long)] client_ip:Option<IpAddr>,
    #[arg(long,visible_alias="download-wire-mbps",default_value_t=260)] wire_mbps:u32,
    #[arg(long,default_value_t=64)] data_shards:usize,
    #[arg(long,default_value_t=8)] repair_shards:usize,
    #[arg(long,default_value_t=8)] lanes:usize,
    #[arg(long,default_value_t=1300)] payload:usize,
    #[arg(long,default_value_t=40)] block_ms:u64,
    #[arg(long,default_value_t=30)] nack_ms:u64,
    /// Diagnostic comparison: disable payload-delivery quality in path weighting.
    #[arg(long)] rtt_only:bool,
    /// Experimental RTT-sized retry cooldown; off until it outperforms speculative recovery.
    #[arg(long)] adaptive_retry:bool,
    /// Optional bounded UDP reordering for TCP-inside-WG; zero is immediate unordered delivery.
    #[arg(long,default_value_t=0)] udp_reorder_ms:u64,
    /// macOS interface index. No routing or system configuration is changed.
    #[arg(long)] ifindex:Option<u32>,
    /// Physical interface name, e.g. en0; managed modes support macOS/Linux without route changes.
    #[arg(long,conflicts_with="ifindex")] interface:Option<String>,
    /// Stop when stdin reaches EOF or receives a line. Intended for an SSH owner.
    #[arg(long)] exit_on_stdin:bool,
    /// Independent process lifetime; zero means run until stopped.
    #[arg(long,default_value_t=0)] lifetime_seconds:u64,
    /// Diagnostic-only relay delay after this many seconds; no tc/system mutation.
    #[arg(long,hide=true,default_value_t=0)] test_delay_after:u64,
    #[arg(long,hide=true,default_value_t=0)] test_delay_ms:u64,
}
fn error(s:impl std::fmt::Display)->io::Error{io::Error::other(s.to_string())}
fn emit(v:serde_json::Value){aggligator_fec::cli_output::emit(v);}
fn config(a:&Args)->io::Result<SessionConfig> {
    let c=SessionConfig {fec:Config {data_shards:a.data_shards,repair_shards:a.repair_shards,
        max_payload:a.payload,max_decode_blocks:256,max_block_delay:Duration::from_millis(a.block_ms)},
        lanes:a.lanes,wire_mbps:a.wire_mbps,nack_delay:Duration::from_millis(a.nack_ms),
        idle_timeout:Duration::from_secs(20),delivery_aware:!a.rtt_only,adaptive_retries:a.adaptive_retry,
        low_latency:a.profile=="latency"};c.validate()?;Ok(c)
}
fn socket(a:&Args)->io::Result<Arc<UdpSocket>> {
    let raw=Socket::new(if a.bind.is_ipv6(){Domain::IPV6}else{Domain::IPV4},Type::DGRAM,Some(Protocol::UDP))?;
    raw.set_nonblocking(true)?;let _=raw.set_recv_buffer_size(2*1024*1024);let _=raw.set_send_buffer_size(256*1024);
    if a.bind.is_ipv6(){raw.set_only_v6(true)?;}
    #[cfg(target_os="macos")]
    if let Some(i)=a.ifindex.and_then(NonZeroU32::new) {
        if a.bind.is_ipv6(){raw.bind_device_by_index_v6(Some(i))?;}else{raw.bind_device_by_index_v4(Some(i))?;}
    }
    #[cfg(not(target_os="macos"))]
    {let _=NonZeroU32::new(0);if a.ifindex.is_some(){return Err(error("--ifindex currently supported only on macOS"));}}
    raw.bind(&a.bind.into())?;Ok(Arc::new(UdpSocket::from_std(raw.into())?))
}
fn report(r:SessionReport) {
    emit(json!({"event":"session_report","id":r.session_id,"tx_payload_bytes":r.tx_payload_bytes,
        "rx_payload_bytes":r.rx_payload_bytes,"tx_wire_bytes":r.tx_wire_bytes,"tx_retries":r.tx_retries,
        "tx_local_send_drops":r.tx_local_send_drops,
        "rx_fec_recovered":r.rx_fec_recovered,"max_send_history":r.max_send_history,
        "path_rx_source_datagrams":r.path_rx_source_datagrams,"path_rx_repair_datagrams":r.path_rx_repair_datagrams,
        "path_rx_retry_datagrams":r.path_rx_retry_datagrams,
        "max_receive_buffer":r.max_receive_buffer,"max_ordered_stall_ms":r.max_ordered_stall_ms,
        "path_source_packets":r.path_source_packets,"path_repair_packets":r.path_repair_packets,
        "path_retry_packets":r.path_retry_packets,"elapsed_s":r.elapsed_s,
        "path_samples":r.path_samples.iter().map(|s|json!({"at_s":s.at_s,"source_packets":s.source_packets})).collect::<Vec<_>>(),
        "paths":r.path_state.iter().map(|p|json!({"srtt_ms":p.srtt_ms,"jitter_ms":p.jitter_ms,
            "probe_loss":p.loss,"sampled_delivery_deficit":p.delivery_loss,
            "delivery_samples":p.delivery_samples,"weight":p.weight,"live":p.live})).collect::<Vec<_>>()}));
}
async fn bridge(mut tcp:TcpStream,mut channel:session::Session)->io::Result<()> {
    tcp.set_nodelay(true)?;
    let copy=tokio::io::copy_bidirectional(&mut tcp,&mut channel.stream);
    tokio::pin!(copy);
    // A broken pipe is often the consequence of a failed session. Preserve the
    // original runtime error rather than aborting/masking the already-failed task.
    tokio::select! {
        completion=&mut channel.task=>{
            let summary=completion.map_err(error)?.map_err(|e|error(format!("FEC session: {e}")))?;
            copy.await?;report(summary);Ok(())
        },
        copied=&mut copy=>{
            if let Err(copy_error)=copied {
                if channel.task.is_finished() {
                    let completion=channel.task.await.map_err(error)?;
                    if let Err(runtime_error)=completion {
                        return Err(error(format!("FEC session: {runtime_error}; local copy: {copy_error}")));
                    }
                } else { channel.task.abort(); }
                return Err(copy_error);
            }
            report(channel.task.await.map_err(error)??);Ok(())
        }
    }
}
async fn endpoint(a:&Args)->io::Result<()> {
    let udp=socket(a)?;let cfg=config(a)?;
    if a.peer.is_empty(){return Err(error("at least one --peer required"));}
    if a.role=="client" {
        let listener=TcpListener::bind(a.listen).await?;
        emit(json!({"event":"ready","role":"client","tcp_listen":listener.local_addr()?.to_string(),"udp_bind":udp.local_addr()?.to_string(),"one_active_stream":true}));
        loop {
            let(tcp,_)=listener.accept().await?;
            let result=match session::connect(udp.clone(),a.peer.clone(),cfg.clone()).await {
                Ok(channel)=>bridge(tcp,channel).await,Err(e)=>Err(e),
            };
            if let Err(e)=result{emit(json!({"event":"session_error","error":e.to_string()}));}
        }
    }else{
        let target=a.target.ok_or_else(||error("server requires fixed --target"))?;
        emit(json!({"event":"ready","role":"server","udp_bind":udp.local_addr()?.to_string(),"target":target.to_string(),"one_active_stream":true}));
        loop {
            let channel=match session::accept(udp.clone(),a.peer.clone(),cfg.clone()).await {
                Ok(c)=>c,Err(e) if e.kind()==io::ErrorKind::TimedOut=>continue,Err(e)=>return Err(e),
            };
            match tokio::time::timeout(Duration::from_secs(5),TcpStream::connect(target)).await {
                Ok(Ok(tcp))=>if let Err(e)=bridge(tcp,channel).await{emit(json!({"event":"session_error","error":e.to_string()}));},
                other=>{channel.task.abort();emit(json!({"event":"session_error","error":format!("fixed target connect: {other:?}")}));}
            }
        }
    }
}
async fn udp_endpoint(a:&Args)->io::Result<()> {
    let network=socket(a)?;let cfg=config(a)?;
    if !a.listen.ip().is_loopback(){return Err(error("UDP application listener must be loopback"));}
    let application=Arc::new(UdpSocket::bind(a.listen).await?);
    let initiator=a.role=="udp-client";
    let target=if initiator{None}else{Some(a.target.ok_or_else(||error("udp-server requires fixed --target"))?)};
    emit(json!({"event":"ready","role":a.role,"udp_bind":network.local_addr()?.to_string(),
        "udp_listen":application.local_addr()?.to_string(),"target":target.map(|a|a.to_string()),
        "delivery":"deadline-datagrams","reorder_ms":a.udp_reorder_ms,"arq":false,"encrypted":false}));
    use aggligator_fec::udp_tunnel::{UdpCounters,UdpEndpoint,run_observed};
    use std::sync::atomic::Ordering;
    let counters=Arc::new(UdpCounters::default());
    let work=run_observed(UdpEndpoint{network,peers:a.peer.clone(),application,target,config:cfg,initiator,reorder_delay:Duration::from_millis(a.udp_reorder_ms)},counters.clone());
    tokio::pin!(work);let mut timer=tokio::time::interval(Duration::from_secs(2));timer.tick().await;
    loop {tokio::select! {
        result=&mut work=>return result,
        _=timer.tick()=>emit(json!({"event":"udp_counters","app_rx":counters.app_rx.load(Ordering::Relaxed),
            "app_tx":counters.app_tx.load(Ordering::Relaxed),"app_rx_bytes":counters.app_rx_bytes.load(Ordering::Relaxed),
            "app_tx_bytes":counters.app_tx_bytes.load(Ordering::Relaxed),"net_tx":counters.net_tx.load(Ordering::Relaxed),
            "net_rx":counters.net_rx.load(Ordering::Relaxed),"queue_drops":counters.queue_drops.load(Ordering::Relaxed),
            "expired":counters.expired.load(Ordering::Relaxed),"recovered":counters.recovered.load(Ordering::Relaxed),
            "local_send_drops":counters.local_send_drops.load(Ordering::Relaxed)})),
    }}
}
async fn relay(a:&Args)->io::Result<()> {
    let udp=socket(a)?;let main=a.main.ok_or_else(||error("relay requires --main"))?;
    let client_ip=a.client_ip.ok_or_else(||error("relay requires --client-ip allowlist"))?;
    let mut client=None;let mut buf=[0u8;1600];let mut forwarded=0u64;let mut rejected=0u64;
    // Bounded diagnostic-delay queue only; normal operation forwards immediately.
    let start=tokio::time::Instant::now();let mut delayed=std::collections::VecDeque::new();
    let mut tick=tokio::time::interval(Duration::from_millis(1));
    emit(json!({"event":"ready","role":"relay","udp_bind":udp.local_addr()?.to_string(),"target":main.to_string()}));
    loop {
        tokio::select! {
            _=tick.tick(),if !delayed.is_empty()=>{
                while delayed.front().is_some_and(|(when,_,_):&(tokio::time::Instant,SocketAddr,Vec<u8>)|*when<=tokio::time::Instant::now()){
                    let(_,to,data)=delayed.pop_front().unwrap();udp.send_to(&data,to).await?;forwarded+=1;
                }
            },
            r=udp.recv_from(&mut buf)=>{
                let(n,from)=r?;
                // Forward the envelope transparently after fixed endpoint admission.
                // Kind 12 is delivery-quality feedback; rejecting newer kinds here
                // silently disabled it whenever both return paths were relayed.
                if n<13||&buf[..4]!=b"AFL1"{rejected+=1;continue;}
                if client.is_none()&&from.ip()==client_ip&&buf[4]==0&&buf[5..13]==[0;8]{client=Some(from);}
                let to=if from==main {client}else if Some(from)==client {Some(main)}else{None};
                let Some(to)=to else{rejected+=1;continue;};
                if buf[4]==0{continue;}
                if a.test_delay_ms>0&&start.elapsed()>=Duration::from_secs(a.test_delay_after) {
                    if delayed.len()==4096{rejected+=1;continue;}
                    delayed.push_back((tokio::time::Instant::now()+Duration::from_millis(a.test_delay_ms),to,buf[..n].to_vec()));
                }else{udp.send_to(&buf[..n],to).await?;forwarded+=1;}
                // Keep counters live for diagnostic debugger; no public status responder.
                let _=(forwarded,rejected);
            },
        }
    }
}
async fn http_test(a:&Args)->io::Result<()> {
    if a.name.len()>48||!a.name.bytes().all(|c|c.is_ascii_alphanumeric()||c==b'-'||c==b'_'){
        return Err(error("diagnostic label must contain only ASCII letters, digits, _ or -"));
    }
    if !a.listen.ip().is_loopback(){return Err(error("diagnostic HTTP server must bind loopback"));}
    let listener=TcpListener::bind(a.listen).await?;
    emit(json!({"event":"ready","role":"http-test","tcp_listen":listener.local_addr()?.to_string()}));
    loop {
        let(mut s,_)=listener.accept().await?;s.set_nodelay(true)?;
        // Serial diagnostic service, fixed bounded content; no filesystem or proxy access.
        let result=async {
            let mut request=Vec::new();let mut b=[0;1];
            while !request.ends_with(b"\r\n\r\n")&&request.len()<8192 {
                if s.read(&mut b).await?==0{return Ok::<_,io::Error>(());}request.push(b[0]);
            }
            let text=std::str::from_utf8(&request).map_err(error)?;
            let target=text.split_whitespace().nth(1).unwrap_or("");
            let size=target.strip_prefix("/bytes/").and_then(|v|v.parse::<usize>().ok()).filter(|n|*n<=1024*1024*1024).ok_or_else(||error("GET /bytes/0..1073741824 required"))?;
            let response=format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\nConnection: close\r\nContent-Type: application/octet-stream\r\nX-Agg-Test-Label: {}\r\n\r\n",a.name);
            s.write_all(response.as_bytes()).await?;
            let body:Vec<_>=(0..(251*256)).map(|i|(i%251)as u8).collect();let mut left=size;
            while left>0 {let n=left.min(body.len());s.write_all(&body[..n]).await?;left-=n;}
            s.shutdown().await?;Ok(())
        }.await;
        if let Err(e)=result{emit(json!({"event":"http_test_error","error":e.to_string()}));}
    }
}
#[cfg(feature="managed")]
async fn management(a:&Args)->io::Result<()> {
    use aggligator_fec::control::{self,AdminAction,ConfigFile,Invitation,MasterFile,NodeFile,Role};
    let path=a.state.as_ref().ok_or_else(||error("--state is required"))?;
    match a.role.as_str(){
        "init"=>{
            let forwards=a.forward.iter().map(|text|{
                let(service,target)=aggligator_fec::configuration::parse_forward(text)?;Ok(control::Forward{service,target})
            }).collect::<io::Result<Vec<_>>>()?;
            aggligator_fec::configuration::validate_forwards(&forwards)?;
            if a.target.is_some()&&!forwards.is_empty(){return Err(error("use either --target or named --forward services"));}
            let target=a.target.or_else(||forwards.first().map(|f|f.target)).ok_or_else(||error("init requires --target or at least one --forward SERVICE=IP:PORT"))?;
            let mut master=MasterFile::create(a.control.ok_or_else(||error("init requires --control IP:port"))?,
                a.advertise.ok_or_else(||error("init requires --advertise IP:UDP-port"))?,target)?;
            master.forwards=forwards;
            if a.bind.port()!=0 {master.data_bind=a.bind;}
            master.tuning=control::Tuning{data_shards:a.data_shards,repair_shards:a.repair_shards,lanes:a.lanes,
                payload:a.payload,block_ms:a.block_ms,nack_ms:a.nack_ms,download_wire_mbps:a.wire_mbps,upload_wire_mbps:a.upload_wire_mbps,
                low_latency:a.profile=="latency",warm_sessions:a.warm_sessions.unwrap_or(if a.profile=="latency"{8}else{0})};
            master.tuning.config(true)?;
            let invitation=master.invite().encode()?;
            ConfigFile::Master(master).save(path,false)?;
            emit(json!({"event":"initialized","state":path,"invitation":invitation}));Ok(())
        },
        "check"=>{
            let file=ConfigFile::read(path).map_err(|e|error(format!("无法读取配置 {}: {e}",path.display())))?;
            let summary=match file {
                ConfigFile::Master(m)=>json!({"event":"config_valid","role":"master","state":path,
                    "control_bind":m.control_bind,"udp_bind":m.data_bind,"forwards":m.services(),
                    "download_wire_mbps":m.tuning.download_wire_mbps,"upload_wire_mbps":m.tuning.upload_wire_mbps,
                    "profile":if m.tuning.low_latency{"latency"}else{"balanced"},"warm_sessions":m.tuning.warm_sessions,
                    "data_encrypted":false,"offline_check_only":true}),
                ConfigFile::Node(n)=>json!({"event":"config_valid","role":n.role,"state":path,
                    "control":n.control,"udp_bind":n.data_bind,"forwards":n.forwards,"legacy_listen":n.listen,
                    "uplinks":n.uplinks,"data_encrypted":false,"offline_check_only":true}),
            };
            emit(summary);Ok(())
        },
        "join"=>{
            if path.exists(){return Err(error("state already exists; use run to reconnect with its independent identity"));}
            let text=match (&a.invite,&a.invite_file) {
                (Some(text),_)=>text.clone(),
                (_,Some(file))=>{
                    let meta=std::fs::symlink_metadata(file)?;
                    if !meta.is_file()||meta.len()>16_384{return Err(error("加入串文件须为不超过 16KiB 的普通文件"));}
                    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;
                        if meta.permissions().mode()&0o077!=0{return Err(error("加入串文件权限须为 600（chmod 600 文件名）"));}
                    }
                    std::fs::read_to_string(file)?
                },
                _=>{
                    use std::io::{BufRead,Read,IsTerminal};
                    if std::io::stdin().is_terminal(){eprintln!("请粘贴主服生成的 agg1:// 加入串，然后回车：");}
                    let mut line=String::new();std::io::stdin().lock().take(16385).read_line(&mut line)?;line
                }
            };
            let invite=Invitation::decode(&text)?;
            let role=match a.node_role.as_str(){"client"=>Role::Client,"relay"=>Role::Relay,_=>return Err(error("--as must be client or relay"))};
            let bind=if role==Role::Relay&&a.bind.port()==0 {a.advertise.ok_or_else(||error("relay requires --advertise"))?}
                else if role==Role::Client&&a.bind==SocketAddr::from(([127,0,0,1],0)) {
                    if invite.control.is_ipv4(){SocketAddr::from(([0,0,0,0],0))}else{SocketAddr::from(([0u16;8],0))}
                }else{a.bind};
            let mut node=NodeFile::new(&invite,a.name.clone(),role,bind,a.advertise,a.listen)?;node.ifindex=a.ifindex;
            if role==Role::Relay&&(!a.forward.is_empty()||!a.uplink.is_empty()){return Err(error("forward/uplink options belong to clients"));}
            node.forwards=a.forward.iter().map(|text|{
                let(service,listen)=aggligator_fec::configuration::parse_forward(text)?;Ok(control::LocalForward{service,listen})
            }).collect::<io::Result<Vec<_>>>()?;
            node.uplinks=a.uplink.iter().map(|text|control::Uplink::parse(text)).collect::<io::Result<Vec<_>>>()?;
            node.validate()?;
            let snapshot=control::enroll(&node.on_access(0)?,&invite.ticket).await?;
            if node.forwards.iter().any(|f|!snapshot.services.contains(&f.service)){return Err(error("unknown service name; no client configuration saved"));}
            ConfigFile::Node(node.clone()).save(path,false)?;
            emit(json!({"event":"joined","state":path,"id":node.id,"role":role,"master":snapshot.master,"relays":snapshot.relays(),"services":snapshot.services,"uplinks":node.uplinks.len().max(1)}));Ok(())
        },
        "invite"=>{
            let ConfigFile::Master(master)=ConfigFile::read(path)?else{return Err(error("invite needs master state"));};
            println!("{}",master.invite().encode()?);Ok(())
        },
        "status"|"rotate"|"revoke"=>{
            let ConfigFile::Master(master)=ConfigFile::read(path)?else{return Err(error("admin command needs master state"));};
            let action=match a.role.as_str(){"status"=>AdminAction::Status,"rotate"=>AdminAction::RotateInvitation,
                _=>AdminAction::Revoke{id:a.node_id.clone().ok_or_else(||error("revoke requires --node-id"))?}};
            let reply=control::admin(&master,action).await?;
            if let Some(invite)=reply.invitation{println!("{invite}");}else{
                aggligator_fec::cli_output::status(serde_json::to_value(&reply.snapshot).map_err(error)?);
            }
            Ok(())
        },
        _=>Err(error("unknown managed command")),
    }
}

fn interface_index(name:&str)->io::Result<u32> {
    #[cfg(unix)] {
        let name=std::ffi::CString::new(name).map_err(error)?;
        // if_nametoindex only reads the OS interface table; it changes no configuration.
        let index=unsafe{libc::if_nametoindex(name.as_ptr())};
        if index==0{Err(error("network interface not found"))}else{Ok(index)}
    }
    #[cfg(not(unix))] {let _=name;Err(error("--interface is supported on macOS/Linux"))}
}
async fn execute()->io::Result<()> {
    use std::io::IsTerminal;
    let mut a=help::parse();
    aggligator_fec::cli_output::configure(a.json||!std::io::stdout().is_terminal());
    if let Some(name)=&a.interface {a.ifindex=Some(interface_index(name)?);}
    #[cfg(feature="managed")]
    if matches!(a.role.as_str(),"init"|"join"|"check"|"status"|"invite"|"rotate"|"revoke"){return management(&a).await;}
    let (tx,mut rx)=mpsc_channel();
    if a.exit_on_stdin {
        std::thread::spawn(move||{use std::io::BufRead;let _=std::io::stdin().lock().lines().next();let _=tx.blocking_send(());});
    }
    let runtime=async {match a.role.as_str(){
        #[cfg(feature="managed")]
        "run"=>aggligator_fec::managed::run(a.state.as_deref().ok_or_else(||error("run requires --state"))?).await,
        "client"|"server"=>endpoint(&a).await,"udp-client"|"udp-server"=>udp_endpoint(&a).await,"relay"=>relay(&a).await,"http-test"=>http_test(&a).await,_=>Err(error("role must be client, server, udp-client, udp-server, relay or http-test"))}};
    let lifetime=async {
        if a.lifetime_seconds==0 {std::future::pending::<()>().await;}
        else {tokio::time::sleep(Duration::from_secs(a.lifetime_seconds)).await;}
    };
    tokio::select! {
        r=runtime=>r,
        _=shutdown_signal()=>Ok(()),
        _=rx.recv(),if a.exit_on_stdin=>Ok(()),
        _=lifetime=>Ok(()),
    }
}
async fn shutdown_signal() {
    #[cfg(unix)] {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut term)=>{tokio::select!{_=term.recv()=>{},_=tokio::signal::ctrl_c()=>{}}},
            Err(_)=>{let _=tokio::signal::ctrl_c().await;},
        }
    }
    #[cfg(not(unix))] {let _=tokio::signal::ctrl_c().await;}
}
#[tokio::main(flavor="multi_thread",worker_threads=4)]
async fn main()->std::process::ExitCode {
    match execute().await {
        Ok(())=>std::process::ExitCode::SUCCESS,
        Err(e)=>{eprintln!("错误 / error: {e}");std::process::ExitCode::FAILURE},
    }
}
fn mpsc_channel()->(tokio::sync::mpsc::Sender<()>,tokio::sync::mpsc::Receiver<()>) {tokio::sync::mpsc::channel(1)}
