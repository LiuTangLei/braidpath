#![cfg(feature="managed")]
use aggligator_fec::control::{self,AdminAction,ConfigFile,Invitation,MasterFile,NodeFile,PrivateDirectory,Registry,Role,Snapshot};
use std::{net::SocketAddr,sync::Arc,time::Duration};
use tokio::{net::TcpListener,sync::watch,task::JoinHandle,time::{timeout,sleep}};
struct Owned(Vec<JoinHandle<()>>);
impl Drop for Owned{fn drop(&mut self){for task in &self.0{task.abort();}}}
fn addr(port:u16)->SocketAddr{SocketAddr::from(([127,0,0,1],port))}
async fn start()->(PrivateDirectory,MasterFile,Arc<Registry>,Owned){
    let dir=PrivateDirectory::create("agg-control-test").unwrap();let listener=TcpListener::bind(addr(0)).await.unwrap();
    let master=MasterFile::create(listener.local_addr().unwrap(),addr(50020),addr(50021)).unwrap();
    let path=dir.path().join("master.json");ConfigFile::Master(master.clone()).save(&path,false).unwrap();
    let registry=Registry::new(master.clone(),path).unwrap();let r=registry.clone();
    let task=tokio::spawn(async move{control::serve(listener,r).await.unwrap();});
    (dir,master,registry,Owned(vec![task]))
}
fn node(master:&MasterFile,name:&str,role:Role,port:u16)->NodeFile{
    NodeFile::new(&master.invite(),name.into(),role,addr(port),(role==Role::Relay).then_some(addr(port)),addr(0)).unwrap()
}
async fn until(watch:&mut watch::Receiver<Option<Snapshot>>,predicate:impl Fn(&Snapshot)->bool)->Snapshot {
    timeout(Duration::from_secs(4),async{loop{
        if let Some(snapshot)=watch.borrow_and_update().clone()&&predicate(&snapshot){return snapshot;}
        watch.changed().await.unwrap();
    }}).await.unwrap()
}

#[test]
fn invitation_contains_no_private_key_and_state_is_owner_only(){
    let dir=PrivateDirectory::create("agg-state-test").unwrap();let master=MasterFile::create(addr(50001),addr(50002),addr(50003)).unwrap();
    let encoded=master.invite().encode().unwrap();let decoded=Invitation::decode(&encoded).unwrap();assert_eq!(decoded.ticket,master.invitation);
    let public=serde_json::to_value(&decoded).unwrap();assert!(public.get("private_key").is_none());assert!(public.get("admin").is_none());
    assert!(Invitation::decode("https://wrong").is_err());assert!(Invitation::decode(&"x".repeat(20_000)).is_err());
    let path=dir.path().join("master.json");ConfigFile::Master(master.clone()).save(&path,false).unwrap();
    assert!(ConfigFile::Master(master).save(&path,false).is_err());assert!(matches!(ConfigFile::read(&path).unwrap(),ConfigFile::Master(_)));
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode()&0o777,0o600);
        std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o644)).unwrap();assert!(ConfigFile::read(&path).is_err());
    }
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn enrollment_tls_push_revocation_rotation_and_reconnect_are_real(){
    let(dir,master,_registry,mut jobs)=start().await;
    let client=node(&master,"client",Role::Client,0);let relay=node(&master,"relay",Role::Relay,50120);
    let first=control::enroll(&client,&master.invitation).await.unwrap();assert!(first.relays().is_empty());
    let(tx,mut updates)=watch::channel(None);let c=client.clone();jobs.0.push(tokio::spawn(async move{control::follow(c,tx).await.unwrap();}));
    until(&mut updates,|s|s.clients().len()==1).await;
    control::enroll(&relay,&master.invitation).await.unwrap();let map=until(&mut updates,|s|s.relays().len()==1).await;
    assert_eq!(map.relays(),vec![addr(50120)]);
    let disk=ConfigFile::read(&dir.path().join("master.json")).unwrap();
    let ConfigFile::Master(saved)=disk else{panic!()};assert_eq!(saved.members.len(),2);
    assert!(saved.members.iter().all(|m|m.credential_hash!=client.credential&&m.credential_hash!=relay.credential));
    let new_invite=control::admin(&master,AdminAction::RotateInvitation).await.unwrap().invitation.unwrap();
    assert_ne!(Invitation::decode(&new_invite).unwrap().ticket,master.invitation);
    let new_node=node(&master,"fresh",Role::Relay,50121);
    assert!(control::enroll(&new_node,&master.invitation).await.is_err());
    // Already admitted identity reconnects without the bootstrap ticket.
    control::enroll(&relay,"not-the-current-invite").await.unwrap();
    control::admin(&master,AdminAction::Revoke{id:relay.id.clone()}).await.unwrap();
    until(&mut updates,|s|s.relays().is_empty()&&s.members.iter().any(|n|n.id==relay.id&&n.revoked)).await;
    assert!(control::enroll(&relay,&Invitation::decode(&new_invite).unwrap().ticket).await.is_err());
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn forged_endpoint_wrong_certificate_and_second_active_client_are_rejected(){
    let(_dir,master,_r,_jobs)=start().await;
    let mut relay=node(&master,"not-a-reflector",Role::Relay,50200);relay.advertise=Some("192.0.2.123:50200".parse().unwrap());
    assert!(control::enroll(&relay,&master.invitation).await.is_err());
    let other=MasterFile::create(addr(50300),addr(50301),addr(50302)).unwrap();
    let mut bad=node(&master,"wrong-pin",Role::Client,0);bad.certificate=other.certificate;
    assert!(control::enroll(&bad,&master.invitation).await.is_err());
    control::enroll(&node(&master,"first",Role::Client,0),&master.invitation).await.unwrap();
    assert!(control::enroll(&node(&master,"second",Role::Client,0),&master.invitation).await.is_err());
}
#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn offline_lease_is_removed_without_erasing_saved_identity(){
    let(_dir,master,registry,_jobs)=start().await;let relay=node(&master,"short-lived",Role::Relay,50400);
    control::enroll(&relay,&master.invitation).await.unwrap();assert_eq!(registry.subscribe().borrow().relays().len(),1);
    sleep(control::LEASE+Duration::from_millis(2500)).await;
    let snapshot=registry.subscribe().borrow().clone();assert!(snapshot.relays().is_empty());assert_eq!(snapshot.members.len(),1);
    control::enroll(&relay,"no-bootstrap-needed").await.unwrap();assert_eq!(registry.subscribe().borrow().relays().len(),1);
}
#[tokio::test]
async fn oversized_control_frames_are_rejected_before_allocating_body(){
    use tokio::io::AsyncWriteExt;
    let(mut a,mut b)=tokio::io::duplex(32);
    a.write_u32(0x7fff_ffff).await.unwrap();
    let result=control::read_message::<_,serde_json::Value>(&mut b).await;assert!(result.is_err());
}
