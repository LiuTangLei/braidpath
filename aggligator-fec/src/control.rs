//! Small, pinned-TLS control plane for a trusted personal FEC tunnel.
//!
//! Enrollment grants membership management, NOT application authorization and
//! NOT encryption of the UDP data plane. Credentials never travel in cleartext.
//! One invitation can enroll a client or a relay. Enrolled nodes receive separate
//! locally generated identities, and revoking an invitation does not revoke them.
//! Registry mutation is durable/atomic; heartbeats and online state are ephemeral.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use ring::digest::{digest as sha256, SHA256};
use std::{
    collections::BTreeMap, fs::{self, OpenOptions}, io::{self, Read, Write},
    net::{IpAddr, SocketAddr}, path::{Path, PathBuf}, sync::Arc, time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream}, sync::{Mutex, Semaphore, watch},
    task::JoinSet, time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector, client::TlsStream};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer, ServerName};

const MAX_MESSAGE: usize = 64 * 1024;
const SERVER_NAME: &str = "agg-control.invalid";
const VERSION: u8 = 1;
pub use crate::configuration::{Forward,LocalForward,Uplink,AccessInfo};
pub const HEARTBEAT: Duration = Duration::from_secs(2);
pub const LEASE: Duration = Duration::from_secs(10);
fn error(message: impl std::fmt::Display) -> io::Error { io::Error::other(message.to_string()) }
fn secret() -> String { B64.encode(rand::random::<[u8; 32]>()) }
fn digest(value: &str) -> String { B64.encode(sha256(&SHA256,value.as_bytes()).as_ref()) }
fn equal_secret(a: &str, b: &str) -> bool {
    let a=sha256(&SHA256,a.as_bytes()); let b=sha256(&SHA256,b.as_bytes());
    a.as_ref().iter().zip(b.as_ref().iter()).fold(0u8, |d,(x,y)|d|(x^y))==0
}
fn valid_secret(value:&str)->bool { B64.decode(value).is_ok_and(|v|v.len()==32) }
fn endpoint(value:SocketAddr)->io::Result<()> {
    if value.port()==0||value.ip().is_unspecified()||value.ip().is_multicast() {
        return Err(error("advertised endpoint must be a unicast address with a nonzero port"));
    }
    Ok(())
}

// OpenSSL is needed only for the one-time `init`; runtime TLS uses rustls.
// Temporary credentials live in an owner-only directory and are always removed.
pub struct PrivateDirectory(PathBuf);
impl PrivateDirectory {
    pub fn create(prefix:&str)->io::Result<Self> {
        if !prefix.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'){return Err(error("invalid temporary prefix"));}
        let path=std::env::temp_dir().join(format!("{prefix}-{}",B64.encode(rand::random::<[u8;16]>() )));
        let mut builder=fs::DirBuilder::new();
        #[cfg(unix)] {use std::os::unix::fs::DirBuilderExt;builder.mode(0o700);}
        builder.create(&path)?;Ok(Self(path))
    }
    pub fn path(&self)->&Path {&self.0}
}
impl Drop for PrivateDirectory {fn drop(&mut self){let _=fs::remove_dir_all(&self.0);}}
fn certificate_start(now:std::time::SystemTime)->io::Result<String> {
    let seconds=now.duration_since(std::time::UNIX_EPOCH).map_err(error)?.as_secs().saturating_sub(300);
    // Gregorian UTC calendar conversion, independent of libc/TZ/platform date flags.
    // The certificate starts five minutes early; normal TLS validity checks remain intact.
    let days=i64::try_from(seconds/86_400).map_err(error)?;
    let z=days+719_468;let era=z/146_097;let doe=z-era*146_097;
    let yoe=(doe-doe/1460+doe/36_524-doe/146_096)/365;
    let mut year=yoe+era*400;let doy=doe-(365*yoe+yoe/4-yoe/100);
    let mp=(5*doy+2)/153;let day=doy-(153*mp+2)/5+1;
    let month=mp+if mp<10{3}else{-9};year+=i64::from(month<=2);
    if !(1970..=9999).contains(&year){return Err(error("system time outside certificate date range"));}
    let clock=seconds%86_400;
    Ok(format!("{year:04}{month:02}{day:02}{:02}{:02}{:02}Z",clock/3600,clock%3600/60,clock%60))
}
fn make_certificate()->io::Result<(Vec<u8>,Vec<u8>)> {
    let dir=PrivateDirectory::create("agg-init")?;
    fs::write(dir.path().join("cert.conf"),"[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=agg-control.invalid\n[ca]\ndefault_ca=local\n[local]\ndatabase=index.txt\nnew_certs_dir=.\nserial=serial\ndefault_md=sha256\ndefault_days=3650\npolicy=policy\nx509_extensions=ext\n[policy]\ncommonName=supplied\n[ext]\nsubjectAltName=DNS:agg-control.invalid\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n")?;
    fs::write(dir.path().join("index.txt"),b"")?;
    fs::write(dir.path().join("serial"),format!("{:016X}\n",rand::random::<u64>().max(1)))?;
    let invoke=|args:&[&str]|->io::Result<()> {
        let result=std::process::Command::new("openssl").current_dir(dir.path()).args(args).output()?;
        if !result.status.success(){return Err(error(format!("OpenSSL {} failed: {}",args[0],String::from_utf8_lossy(&result.stderr).chars().take(512).collect::<String>())));}
        Ok(())
    };
    invoke(&["req","-new","-sha256","-newkey","rsa:2048","-nodes","-keyout","key.pem","-out","request.pem","-config","cert.conf"])?;
    let start=certificate_start(std::time::SystemTime::now())?;
    invoke(&["ca","-batch","-selfsign","-keyfile","key.pem","-in","request.pem","-out","cert.pem","-config","cert.conf","-startdate",&start,"-notext"])?;
    invoke(&["x509","-in","cert.pem","-outform","DER","-out","cert.der"])?;
    invoke(&["pkcs8","-topk8","-nocrypt","-in","key.pem","-outform","DER","-out","key.der"])?;
    Ok((fs::read(dir.path().join("cert.der"))?,fs::read(dir.path().join("key.der"))?))
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all="snake_case")]
pub enum Role { Client, Relay }

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tuning {
    pub data_shards:usize, pub repair_shards:usize, pub lanes:usize,
    pub payload:usize, pub block_ms:u64, pub nack_ms:u64,
    pub download_wire_mbps:u32, pub upload_wire_mbps:u32,
    /// Latency branch: replicate immediately on every configured path.
    #[serde(default)]pub low_latency:bool,
    /// Unused, already-handshaken sessions shared by all local TCP ports.
    #[serde(default)]pub warm_sessions:usize,
}
impl Default for Tuning {
    fn default()->Self {Self{data_shards:64,repair_shards:8,lanes:8,payload:1300,
        block_ms:40,nack_ms:30,download_wire_mbps:260,upload_wire_mbps:80,low_latency:false,warm_sessions:0}}
}
impl Tuning {
    pub fn config(&self,server:bool)->io::Result<crate::session::SessionConfig> {
        if self.warm_sessions>16{return Err(error("warm_sessions must be between 0 and 16 (shared 32-flow limit)"));}
        let cfg=crate::session::SessionConfig {
            fec:crate::Config{data_shards:self.data_shards,repair_shards:self.repair_shards,
                max_payload:self.payload,max_decode_blocks:256,max_block_delay:Duration::from_millis(self.block_ms)},
            lanes:self.lanes,wire_mbps:if server{self.download_wire_mbps}else{self.upload_wire_mbps},
            nack_delay:Duration::from_millis(self.nack_ms),low_latency:self.low_latency,..Default::default()};
        cfg.validate()?;Ok(cfg)
    }
}

/// Sensitive bootstrap capability. The CA certificate is public; `ticket` is not.
/// No private server key or existing node credential is present.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invitation { pub version:u8, pub control:SocketAddr, pub certificate:String, pub ticket:String }
impl Invitation {
    pub fn encode(&self)->io::Result<String> {self.validate()?;Ok(format!("agg1://{}",B64.encode(serde_json::to_vec(self).map_err(error)?)))}
    pub fn decode(text:&str)->io::Result<Self> {
        if text.len()>16_384{return Err(error("invitation too long"));}
        let body=text.trim().strip_prefix("agg1://").ok_or_else(||error("unsupported invitation scheme"))?;
        let this:Self=serde_json::from_slice(&B64.decode(body).map_err(|_|error("invalid invitation encoding"))?).map_err(|_|error("invalid invitation document"))?;
        this.validate()?;Ok(this)
    }
    fn validate(&self)->io::Result<()> {
        endpoint(self.control)?;
        if self.version!=VERSION||!valid_secret(&self.ticket)||B64.decode(&self.certificate).is_err()||self.certificate.len()>8192 {
            return Err(error("unsupported or invalid invitation"));
        }
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Member {
    pub id:String,pub name:String,pub role:Role,pub credential_hash:String,
    pub public_ip:IpAddr,pub relay:Option<SocketAddr>,pub revoked:bool,
    #[serde(default)]pub accesses:Vec<AccessInfo>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasterFile {
    pub version:u8,pub control:SocketAddr,pub control_bind:SocketAddr,
    pub data:SocketAddr,pub data_bind:SocketAddr,pub target:SocketAddr,
    pub certificate:String,pub private_key:String,pub invitation:String,pub admin:String,
    pub tuning:Tuning,pub members:Vec<Member>,
    #[serde(default)]pub forwards:Vec<Forward>,
}
impl MasterFile {
    pub fn create(control:SocketAddr,data:SocketAddr,target:SocketAddr)->io::Result<Self> {
        endpoint(control)?;endpoint(data)?;endpoint(target)?;
        let (cert,key)=make_certificate()?;
        Ok(Self{version:VERSION,control,control_bind:control,data,data_bind:data,target,
            certificate:B64.encode(cert),private_key:B64.encode(key),
            invitation:secret(),admin:secret(),tuning:Tuning::default(),members:Vec::new(),forwards:Vec::new()})
    }
    pub fn invite(&self)->Invitation {Invitation{version:VERSION,control:self.control,certificate:self.certificate.clone(),ticket:self.invitation.clone()}}
    pub fn services(&self)->Vec<Forward>{if self.forwards.is_empty(){vec![Forward{service:"default".into(),target:self.target}]}else{self.forwards.clone()}}
    fn validate(&self)->io::Result<()> {
        self.invite().validate()?;endpoint(self.data)?;endpoint(self.target)?;
        crate::configuration::validate_forwards(&self.forwards)?;
        self.tuning.config(true)?;self.tuning.config(false)?;
        if self.version!=VERSION||self.members.len()>64||!valid_secret(&self.admin) {
            return Err(error("invalid master state"));
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeFile {
    pub version:u8,pub control:SocketAddr,pub certificate:String,
    pub id:String,pub credential:String,pub name:String,pub role:Role,
    pub data_bind:SocketAddr,pub advertise:Option<SocketAddr>,pub listen:SocketAddr,
    pub ifindex:Option<u32>,
    #[serde(default)]pub forwards:Vec<LocalForward>,
    #[serde(default)]pub uplinks:Vec<Uplink>,
    #[serde(skip)]pub access_slot:usize,
}
impl NodeFile {
    pub fn new(invite:&Invitation,name:String,role:Role,data_bind:SocketAddr,advertise:Option<SocketAddr>,listen:SocketAddr)->io::Result<Self> {
        invite.validate()?;
        let this=Self{version:VERSION,control:invite.control,certificate:invite.certificate.clone(),
            id:B64.encode(rand::random::<[u8;16]>()),credential:secret(),name,role,data_bind,advertise,listen,ifindex:None,forwards:Vec::new(),uplinks:Vec::new(),access_slot:0};
        this.validate()?;Ok(this)
    }
    pub fn on_access(&self,slot:usize)->io::Result<Self>{
        let mut node=self.clone();node.access_slot=slot;
        if let Some(link)=self.uplinks.get(slot){node.data_bind=link.bind;node.ifindex=link.ifindex()?;}
        else if slot!=0{return Err(error("unknown access link"));}Ok(node)
    }
    pub fn validate(&self)->io::Result<()> {
        endpoint(self.control)?;
        if self.uplinks.len()>4||self.access_slot>=4||self.forwards.len()>16{return Err(error("at most four uplinks and sixteen local listeners"));}
        if self.role==Role::Relay&&(!self.uplinks.is_empty()||!self.forwards.is_empty()){return Err(error("relay configurations cannot declare client forwards/uplinks"));}
        for(i,link)in self.uplinks.iter().enumerate(){link.validate()?;if self.uplinks[..i].iter().any(|v|v.name==link.name){return Err(error("duplicate uplink name"));}}
        for(i,f)in self.forwards.iter().enumerate(){
            if !crate::configuration::name_valid(&f.service)||!f.listen.ip().is_loopback()||self.forwards[..i].iter().any(|v|v.listen==f.listen&&f.listen.port()!=0){return Err(error("duplicate or invalid local forward"));}
        }
        if self.version!=VERSION||!valid_secret(&self.credential)||self.name.is_empty()||self.name.len()>64
            ||self.name.chars().any(char::is_control)||!B64.decode(&self.id).is_ok_and(|v|v.len()==16)
            ||self.certificate.len()>8192||!self.listen.ip().is_loopback() {
            return Err(error("invalid node settings"));
        }
        if self.role==Role::Relay {endpoint(self.advertise.ok_or_else(||error("relay requires advertised public UDP endpoint"))?)?;}
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag="kind",content="settings",rename_all="snake_case",deny_unknown_fields)]
pub enum ConfigFile { Master(MasterFile), Node(NodeFile) }
impl ConfigFile {
    pub fn read(path:&Path)->io::Result<Self> {
        let metadata=fs::symlink_metadata(path)?;
        if !metadata.is_file()||metadata.len()>1024*1024{return Err(error("state must be a regular file <=1MiB"));}
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            if metadata.permissions().mode()&0o077!=0{return Err(error("credential file must be owner-only (chmod 600)"));}
        }
        let mut bytes=Vec::new();fs::File::open(path)?.take(1024*1024+1).read_to_end(&mut bytes)?;
        let file:Self=serde_json::from_slice(&bytes).map_err(|_|error("invalid state document"))?;
        match &file{Self::Master(m)=>m.validate()?,Self::Node(n)=>n.validate()?};Ok(file)
    }
    pub fn save(&self,path:&Path,replace:bool)->io::Result<()> {
        if let Ok(meta)=fs::symlink_metadata(path) && (!replace||!meta.is_file()) {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists,"refusing to replace existing/nonregular state"));
        }
        let parent=path.parent().filter(|p|!p.as_os_str().is_empty()).unwrap_or(Path::new("."));
        if !parent.is_dir(){return Err(error("create the state parent directory first"));}
        let tmp=parent.join(format!(".agg-state-{}.tmp",B64.encode(rand::random::<[u8;12]>() )));
        let mut options=OpenOptions::new();options.create_new(true).write(true);
        #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
        let result=(|| {
            let mut f=options.open(&tmp)?;let data=serde_json::to_vec_pretty(self).map_err(error)?;
            f.write_all(&data)?;f.write_all(b"\n")?;f.sync_all()?;
            if replace {fs::rename(&tmp,path)?;}else{fs::hard_link(&tmp,path)?;fs::remove_file(&tmp)?;}
            #[cfg(unix)] fs::File::open(parent)?.sync_all()?;
            Ok(())
        })();
        if result.is_err(){let _=fs::remove_file(tmp);}
        result
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct NodeInfo {pub id:String,pub name:String,pub role:Role,pub public_ip:IpAddr,pub relay:Option<SocketAddr>,pub online:bool,pub revoked:bool,
    #[serde(default)]pub accesses:Vec<AccessInfo>}
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Snapshot {pub epoch:u64,pub revision:u64,pub master:SocketAddr,pub tuning:Tuning,pub members:Vec<NodeInfo>,
    #[serde(default)]pub services:Vec<String>}
impl Snapshot {
    pub fn relays(&self)->Vec<SocketAddr> {self.members.iter().filter(|n|n.role==Role::Relay&&n.online&&!n.revoked).filter_map(|n|n.relay).collect()}
    pub fn clients(&self)->Vec<IpAddr> {self.members.iter().filter(|n|n.role==Role::Client&&n.online&&!n.revoked).flat_map(|n|std::iter::once(n.public_ip).chain(n.accesses.iter().map(|a|a.public_ip))).collect()}
    pub fn client_paths(&self)->Vec<SocketAddr> {std::iter::once(self.master).chain(self.relays()).collect()}
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag="op",rename_all="snake_case",deny_unknown_fields)]
pub enum AdminAction {Status, RotateInvitation, Revoke{id:String}}
#[derive(Serialize, Deserialize)]
#[serde(tag="op",rename_all="snake_case",deny_unknown_fields)]
enum Request {
    Enroll {id:String,credential:String,name:String,role:Role,advertise:Option<SocketAddr>,invitation:Option<String>,
        #[serde(default)]access:Option<AccessInfo>},
    Heartbeat,
    Admin {credential:String,action:AdminAction},
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Reply {pub snapshot:Snapshot,pub invitation:Option<String>}

pub async fn write_message<W:AsyncWrite+Unpin,T:Serialize>(writer:&mut W,value:&T)->io::Result<()> {
    let data=serde_json::to_vec(value).map_err(error)?;
    if data.len()>MAX_MESSAGE{return Err(error("control message too large"));}
    writer.write_u32(data.len()as u32).await?;writer.write_all(&data).await?;writer.flush().await
}
pub async fn read_message<R:AsyncRead+Unpin,T:DeserializeOwned>(reader:&mut R)->io::Result<T> {
    let len=reader.read_u32().await? as usize;
    if len==0||len>MAX_MESSAGE{return Err(error("invalid control frame size"));}
    let mut bytes=vec![0;len];reader.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_|error("invalid control frame"))
}
struct ReadGuard(tokio::task::JoinHandle<()>);
impl Drop for ReadGuard {fn drop(&mut self){self.0.abort();}}
// Framed reads are not cancellation-safe: keep one read future alive while
// snapshots and heartbeats race, so a partial TLS frame cannot desynchronise JSON.
fn read_pump<R,T>(mut reader:R)->(tokio::sync::mpsc::Receiver<io::Result<T>>,ReadGuard)
where R:AsyncRead+Unpin+Send+'static,T:DeserializeOwned+Send+'static {
    let(tx,rx)=tokio::sync::mpsc::channel(8);
    let task=tokio::spawn(async move{loop{
        let frame=read_message(&mut reader).await;let failed=frame.is_err();
        if tx.send(frame).await.is_err()||failed{break;}
    }});(rx,ReadGuard(task))
}
fn provider()->Arc<rustls::crypto::CryptoProvider>{Arc::new(rustls::crypto::ring::default_provider())}
fn acceptor(master:&MasterFile)->io::Result<TlsAcceptor> {
    let cert=CertificateDer::from(B64.decode(&master.certificate).map_err(error)?);
    let key=PrivatePkcs8KeyDer::from(B64.decode(&master.private_key).map_err(error)?);
    let config=rustls::ServerConfig::builder_with_provider(provider()).with_protocol_versions(&[&rustls::version::TLS13]).map_err(error)?
        .with_no_client_auth().with_single_cert(vec![cert],key.into()).map_err(error)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}
async fn connect(control:SocketAddr,certificate:&str,ifindex:Option<u32>,source:Option<IpAddr>)->io::Result<TlsStream<TcpStream>> {
    let mut roots=rustls::RootCertStore::empty();roots.add(CertificateDer::from(B64.decode(certificate).map_err(error)?)).map_err(error)?;
    let config=rustls::ClientConfig::builder_with_provider(provider()).with_protocol_versions(&[&rustls::version::TLS13]).map_err(error)?
        .with_root_certificates(roots).with_no_client_auth();
    let raw=if control.is_ipv4(){TcpSocket::new_v4()?}else{TcpSocket::new_v6()?};
    crate::configuration::bind_interface(&socket2::SockRef::from(&raw),control.is_ipv6(),ifindex)?;
    if let Some(ip)=source.filter(|ip|!ip.is_unspecified()){raw.bind(SocketAddr::new(ip,0))?;}
    let tcp=timeout(Duration::from_secs(5),raw.connect(control)).await.map_err(error)??;
    tcp.set_nodelay(true)?;
    timeout(Duration::from_secs(5),TlsConnector::from(Arc::new(config)).connect(ServerName::try_from(SERVER_NAME).map_err(error)?,tcp)).await.map_err(error)?
}

struct Online {id:String,generation:u64,seen:Instant}
struct Inner {master:MasterFile,online:BTreeMap<String,Online>,epoch:u64,revision:u64}
/// State is serialised only on membership/admin changes; no disk write per heartbeat.
pub struct Registry {inner:Mutex<Inner>,file:PathBuf,updates:watch::Sender<Snapshot>}
impl Registry {
    pub fn new(master:MasterFile,file:PathBuf)->io::Result<Arc<Self>> {
        master.validate()?;
        let initial=Snapshot{epoch:rand::random(),revision:0,master:master.data,tuning:master.tuning.clone(),members:Vec::new(),services:master.services().iter().map(|s|s.service.clone()).collect()};
        let(updates,_)=watch::channel(initial.clone());
        let this=Arc::new(Self{inner:Mutex::new(Inner{master,online:BTreeMap::new(),epoch:initial.epoch,revision:0}),file,updates});
        Ok(this)
    }
    pub fn subscribe(&self)->watch::Receiver<Snapshot>{self.updates.subscribe()}
    fn snapshot(inner:&Inner)->Snapshot {
        Snapshot{epoch:inner.epoch,revision:inner.revision,master:inner.master.data,tuning:inner.master.tuning.clone(),
            services:inner.master.services().iter().map(|s|s.service.clone()).collect(),
            members:inner.master.members.iter().map(|n|NodeInfo{id:n.id.clone(),name:n.name.clone(),role:n.role,public_ip:n.public_ip,
                relay:n.relay,online:inner.online.values().any(|o|o.id==n.id),revoked:n.revoked,accesses:n.accesses.clone()}).collect()}
    }
    fn publish(&self,inner:&mut Inner){inner.revision=inner.revision.wrapping_add(1);self.updates.send_replace(Self::snapshot(inner));}
    async fn enrollment(&self,request:Request,from:IpAddr)->io::Result<(String,u64,Snapshot)> {
        let Request::Enroll{id,credential,name,role,advertise,invitation,mut access}=request else{return Err(error("enrollment required"));};
        if !valid_secret(&credential)||!B64.decode(&id).is_ok_and(|b|b.len()==16)||name.is_empty()||name.len()>64||name.chars().any(char::is_control){return Err(error("invalid enrollment"));}
        if let Some(link)=&mut access {
            if role!=Role::Client||link.slot>=4||!crate::configuration::name_valid(&link.name)
                ||!(1..=1000).contains(&link.upload_wire_mbps)||!(1..=1000).contains(&link.download_wire_mbps){return Err(error("invalid access registration"));}
            link.public_ip=from;
        }
        let slot=access.as_ref().map_or(0,|a|a.slot);
        if role==Role::Relay {
            let advertised=advertise.ok_or_else(||error("relay endpoint required"))?;endpoint(advertised)?;
            if advertised.ip()!=from{return Err(error("relay advertised IP must match its TLS connection source"));}
        } else if advertise.is_some(){return Err(error("client cannot advertise a relay"));}
        let mut inner=self.inner.lock().await;
        let mut candidate=inner.master.clone();
        if role==Role::Relay&&advertise.is_some_and(|endpoint|endpoint==candidate.data||candidate.members.iter().any(|n|n.id!=id&&!n.revoked&&n.relay==Some(endpoint))) {
            return Err(error("relay endpoint is already assigned"));
        }
        if let Some(member)=candidate.members.iter_mut().find(|m|m.id==id) {
            if member.revoked||member.role!=role||!equal_secret(&member.credential_hash,&digest(&credential)){return Err(error("node admission rejected"));}
            member.name=name;if slot==0{member.public_ip=from;}member.relay=advertise;
            if let Some(link)=access {member.accesses.retain(|a|a.slot!=slot);member.accesses.push(link);member.accesses.sort_by_key(|a|a.slot);}
        } else {
            if !invitation.as_ref().is_some_and(|v|equal_secret(v,&candidate.invitation)){return Err(error("invitation rejected"));}
            if candidate.members.len()>=64{return Err(error("member limit reached"));}
            if role==Role::Relay&&candidate.members.iter().filter(|n|n.role==Role::Relay&&!n.revoked).count()>=7{return Err(error("at most seven enrolled relays"));}
            candidate.members.push(Member{id:id.clone(),name,role,credential_hash:digest(&credential),public_ip:from,relay:advertise,revoked:false,accesses:access.into_iter().collect()});
        }
        // Multiple WAN control sockets use one client identity; TCP flows are independent.
        if role==Role::Client&&candidate.members.iter().any(|n|n.id!=id&&n.role==Role::Client&&inner.online.values().any(|o|o.id==n.id)) {
            return Err(error("one active client identity per managed tunnel; multiple ports/WANs are supported"));
        }
        ConfigFile::Master(candidate.clone()).save(&self.file,true)?;
        inner.master=candidate;
        let generation=rand::random();inner.online.insert(format!("{id}:{slot}"),Online{id:id.clone(),generation,seen:Instant::now()});
        self.publish(&mut inner);Ok((id,generation,Self::snapshot(&inner)))
    }
    async fn heartbeat(&self,id:&str,generation:u64)->io::Result<()> {
        let mut inner=self.inner.lock().await;
        if inner.master.members.iter().find(|n|n.id==id).is_none_or(|n|n.revoked){return Err(error("node revoked"));}
        let current=inner.online.values_mut().find(|o|o.id==id&&o.generation==generation).ok_or_else(||error("lease expired/superseded"))?;
        if current.generation!=generation{return Err(error("superseded control connection"));}
        current.seen=Instant::now();Ok(())
    }
    async fn disconnect(&self,id:&str,generation:u64) {
        let mut inner=self.inner.lock().await;
        // A broken control socket gets the lease grace period. Reconnection does
        // not flap data paths, and an old task cannot remove a newer registration.
        if let Some(current)=inner.online.values_mut().find(|o|o.id==id&&o.generation==generation) {
            current.seen=Instant::now();
        }
    }
    async fn expire(&self){let mut inner=self.inner.lock().await;let before=inner.online.len();inner.online.retain(|_,v|v.seen.elapsed()<LEASE);if before!=inner.online.len(){self.publish(&mut inner);}}
    async fn admin(&self,credential:&str,action:AdminAction)->io::Result<Reply> {
        let mut inner=self.inner.lock().await;
        if !equal_secret(credential,&inner.master.admin){return Err(error("admin rejected"));}
        let mut invitation=None;
        match action {
            AdminAction::Status=>{},
            AdminAction::RotateInvitation=>{
                let mut m=inner.master.clone();m.invitation=secret();ConfigFile::Master(m.clone()).save(&self.file,true)?;
                invitation=Some(m.invite().encode()?);inner.master=m;self.publish(&mut inner);
            },
            AdminAction::Revoke{id}=>{
                let mut m=inner.master.clone();let n=m.members.iter_mut().find(|n|n.id==id).ok_or_else(||error("unknown node"))?;n.revoked=true;
                ConfigFile::Master(m.clone()).save(&self.file,true)?;inner.master=m;inner.online.retain(|_,o|o.id!=id);self.publish(&mut inner);
            },
        }
        Ok(Reply{snapshot:Self::snapshot(&inner),invitation})
    }
}

pub async fn serve(listener:TcpListener,registry:Arc<Registry>)->io::Result<()> {
    let tls=acceptor(&registry.inner.lock().await.master)?;
    let semaphore=Arc::new(Semaphore::new(80));let mut tasks=JoinSet::new();
    let mut timer=tokio::time::interval(HEARTBEAT);
    loop {
        tokio::select! {
            accepted=listener.accept()=>{
                let(tcp,from)=accepted?;let Ok(permit)=semaphore.clone().try_acquire_owned()else{continue;};
                let tls=tls.clone();let registry=registry.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let Ok(Ok(mut stream))=timeout(Duration::from_secs(5),tls.accept(tcp)).await else{return;};
                    let Ok(Ok(request))=timeout(Duration::from_secs(5),read_message::<_,Request>(&mut stream)).await else{return;};
                    if let Request::Admin{credential,action}=request {
                        if let Ok(reply)=registry.admin(&credential,action).await {let _=timeout(Duration::from_secs(3),write_message(&mut stream,&reply)).await;}
                        return;
                    }
                    let mut updates=registry.subscribe();
                    let Ok((id,generation,snapshot))=registry.enrollment(request,from.ip()).await else{return;};
                    let result:io::Result<()>=async {
                        timeout(Duration::from_secs(3),write_message(&mut stream,&Reply{snapshot,invitation:None})).await.map_err(error)??;
                        let(read,mut write)=tokio::io::split(stream);
                        let(mut incoming,_reader)=read_pump::<_,Request>(read);
                        let mut heartbeat_deadline=tokio::time::Instant::now()+LEASE;
                        loop {
                            tokio::select! {
                                message=incoming.recv()=>{
                                    if !matches!(message.ok_or_else(||error("control closed"))??,Request::Heartbeat){return Err(error("unexpected control message"));}
                                    registry.heartbeat(&id,generation).await?;
                                    heartbeat_deadline=tokio::time::Instant::now()+LEASE;
                                    let snapshot=updates.borrow().clone();
                                    timeout(Duration::from_secs(3),write_message(&mut write,&Reply{snapshot,invitation:None})).await.map_err(error)??;
                                },
                                _=tokio::time::sleep_until(heartbeat_deadline)=>return Err(error("control heartbeat timeout")),
                                changed=updates.changed()=>{
                                    changed.map_err(error)?;let snapshot=updates.borrow_and_update().clone();
                                    if snapshot.members.iter().find(|n|n.id==id).is_none_or(|n|n.revoked){return Err(error("node removed"));}
                                    timeout(Duration::from_secs(3),write_message(&mut write,&Reply{snapshot,invitation:None})).await.map_err(error)??;
                                },
                            }
                        }
                    }.await;
                    let _=result;registry.disconnect(&id,generation).await;
                });
            },
            _=timer.tick()=>registry.expire().await,
            _=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
}
fn enrollment(node:&NodeFile,invitation:Option<String>)->Request {
    let access=node.uplinks.get(node.access_slot).map(|a|AccessInfo{slot:node.access_slot,name:a.name.clone(),public_ip:node.data_bind.ip(),upload_wire_mbps:a.upload_wire_mbps,download_wire_mbps:a.download_wire_mbps});
    Request::Enroll{id:node.id.clone(),credential:node.credential.clone(),name:node.name.clone(),role:node.role,advertise:node.advertise,invitation,access}
}
pub async fn enroll(node:&NodeFile,invitation:&str)->io::Result<Snapshot> {
    node.validate()?;let mut stream=connect(node.control,&node.certificate,node.ifindex,Some(node.data_bind.ip())).await?;
    timeout(Duration::from_secs(5),async{
        write_message(&mut stream,&enrollment(node,Some(invitation.to_owned()))).await?;
        let reply:Reply=read_message(&mut stream).await?;Ok(reply.snapshot)
    }).await.map_err(error)?
}
pub async fn admin(master:&MasterFile,action:AdminAction)->io::Result<Reply> {
    let mut stream=connect(master.control,&master.certificate,None,None).await?;
    timeout(Duration::from_secs(5),async{
        write_message(&mut stream,&Request::Admin{credential:master.admin.clone(),action}).await?;read_message(&mut stream).await
    }).await.map_err(error)?
}
/// Reconnects with its own identity, keeps the last known map during a temporary
/// control outage, and pushes validated updates without restarting the data task.
fn publish_snapshot(updates:&watch::Sender<Option<Snapshot>>,snapshot:Snapshot){
    updates.send_if_modified(|old|{
        // Different WAN control sockets may deliver the same revision out of order.
        if old.as_ref().is_some_and(|s|s.epoch==snapshot.epoch&&s.revision>snapshot.revision){return false;}
        if old.as_ref()!=Some(&snapshot){*old=Some(snapshot.clone());true}else{false}
    });
}
pub async fn follow(node:NodeFile,updates:watch::Sender<Option<Snapshot>>)->io::Result<()> {
    node.validate()?;let mut backoff=Duration::from_millis(250);
    loop {
        let result:io::Result<()>=async {
            let mut stream=connect(node.control,&node.certificate,node.ifindex,Some(node.data_bind.ip())).await?;
            write_message(&mut stream,&enrollment(&node,None)).await?;
            let initial:Reply=timeout(Duration::from_secs(5),read_message(&mut stream)).await.map_err(error)??;
            publish_snapshot(&updates,initial.snapshot);
            let(read,mut write)=tokio::io::split(stream);let mut timer=tokio::time::interval(HEARTBEAT);
            let(mut incoming,_reader)=read_pump::<_,Reply>(read);
            let mut deadline=tokio::time::Instant::now()+LEASE;
            loop {tokio::select! {
                message=incoming.recv()=>{
                    let snapshot=message.ok_or_else(||error("control closed"))??.snapshot;
                    deadline=tokio::time::Instant::now()+LEASE;
                    publish_snapshot(&updates,snapshot);
                },
                _=tokio::time::sleep_until(deadline)=>return Err(error("control response timeout")),
                _=timer.tick()=>{timeout(Duration::from_secs(3),write_message(&mut write,&Request::Heartbeat)).await.map_err(error)??;},
            }}
        }.await;
        let _:io::Result<()>=result;
        if updates.is_closed(){return Ok(());}
        tokio::time::sleep(backoff).await;backoff=(backoff*2).min(Duration::from_secs(3));
    }
}
