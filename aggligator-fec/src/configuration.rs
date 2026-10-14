//! Managed forwarding and independent access-link configuration.
use serde::{Deserialize,Serialize};
use std::{io,net::SocketAddr};
fn err(s:impl std::fmt::Display)->io::Error{io::Error::other(s.to_string())}
pub fn name_valid(name:&str)->bool{!name.is_empty()&&name.len()<=48&&name.bytes().all(|b|b.is_ascii_alphanumeric()||b==b'-'||b==b'_')}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Forward {pub service:String,pub target:SocketAddr}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalForward {pub service:String,pub listen:SocketAddr}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
#[serde(deny_unknown_fields)]
pub struct Uplink {
    pub name:String,pub bind:SocketAddr,
    #[serde(default)]pub interface:Option<String>,
    pub upload_wire_mbps:u32,pub download_wire_mbps:u32,
}
#[derive(Clone,Debug,Serialize,Deserialize,PartialEq,Eq)]
pub struct AccessInfo {pub slot:usize,pub name:String,pub public_ip:std::net::IpAddr,pub upload_wire_mbps:u32,pub download_wire_mbps:u32}
impl Uplink {
    /// en0=80/260 or test@127.0.0.1=20/40 (explicit source is useful in labs).
    pub fn parse(text:&str)->io::Result<Self>{
        let (link,rates)=text.split_once('=').ok_or_else(||err("uplink syntax: INTERFACE=UPLOAD/DOWNLOAD Mbps"))?;
        let(up,down)=rates.split_once('/').ok_or_else(||err("uplink needs upload/download wire limits"))?;
        let(name,bind,interface)=if let Some((name,address))=link.split_once('@'){
            (name.to_string(),SocketAddr::new(address.parse().map_err(err)?,0),None)
        }else{(link.to_string(),"0.0.0.0:0".parse().unwrap(),Some(link.to_string()))};
        let this=Self{name,bind,interface,upload_wire_mbps:up.parse().map_err(err)?,download_wire_mbps:down.parse().map_err(err)?};this.validate()?;Ok(this)
    }
    pub fn validate(&self)->io::Result<()> {
        if !name_valid(&self.name)||self.bind.ip().is_multicast()||!(1..=1000).contains(&self.upload_wire_mbps)||!(1..=1000).contains(&self.download_wire_mbps){return Err(err("invalid uplink name/address/rates"));}
        if let Some(name)=&self.interface{interface_index(name)?;}Ok(())
    }
    pub fn ifindex(&self)->io::Result<Option<u32>>{self.interface.as_ref().map(|n|interface_index(n)).transpose()}
}
pub fn interface_index(name:&str)->io::Result<u32>{
    #[cfg(unix)] {
        let name=std::ffi::CString::new(name).map_err(err)?;
        // Reads an OS interface index; no route/interface configuration change.
        let index=unsafe{libc::if_nametoindex(name.as_ptr())};
        if index==0{Err(err("network interface not found"))}else{Ok(index)}
    }
    #[cfg(not(unix))]{let _=name;Err(err("interface binding is supported on macOS/Linux"))}
}
pub fn bind_interface(socket:&socket2::SockRef<'_>,ipv6:bool,index:Option<u32>)->io::Result<()> {
    let Some(index)=index else{return Ok(());};if index==0{return Err(err("invalid interface index"));}
    #[cfg(target_os="macos")]{
        let index=std::num::NonZeroU32::new(index).unwrap();
        if ipv6{socket.bind_device_by_index_v6(Some(index))}else{socket.bind_device_by_index_v4(Some(index))}
    }
    #[cfg(target_os="linux")]{
        let _=ipv6;let mut name=[0i8;libc::IF_NAMESIZE];
        // Resolve only the selected interface; SO_BINDTODEVICE can require privilege.
        let result=unsafe{libc::if_indextoname(index,name.as_mut_ptr())};
        if result.is_null(){return Err(io::Error::last_os_error());}
        let name=unsafe{std::ffi::CStr::from_ptr(name.as_ptr())};socket.bind_device(Some(name.to_bytes()))
    }
    #[cfg(not(any(target_os="macos",target_os="linux")))]{let _=(socket,ipv6,index);Err(err("unsupported interface binding"))}
}
pub fn parse_forward(text:&str)->io::Result<(String,SocketAddr)>{
    let(name,address)=text.split_once('=').ok_or_else(||err("forward syntax: SERVICE=IP:PORT"))?;
    if !name_valid(name){return Err(err("service name must use letters, digits, _ or -"));}
    Ok((name.to_owned(),address.parse().map_err(err)?))
}
pub fn validate_forwards(forwards:&[Forward])->io::Result<()> {
    if forwards.len()>16{return Err(err("at most sixteen forwarded services"));}
    for(i,f)in forwards.iter().enumerate(){
        if !name_valid(&f.service)||f.target.port()==0||f.target.ip().is_multicast()||f.target.ip().is_unspecified()
            ||forwards[..i].iter().any(|v|v.service==f.service){return Err(err("duplicate/invalid forwarded service"));}
    }Ok(())
}
