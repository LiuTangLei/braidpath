#![cfg(feature="managed")]
use aggligator_fec::control::MasterFile;
use base64::{Engine,engine::general_purpose::URL_SAFE_NO_PAD};
use rustls::{client::danger::ServerCertVerifier,pki_types::{CertificateDer,ServerName,UnixTime}};
use std::{sync::Arc,time::{Duration,SystemTime,UNIX_EPOCH}};

#[test]
fn new_pinned_certificate_tolerates_small_clock_skew_without_disabling_validity_checks() {
    let master=MasterFile::create("127.0.0.1:5706".parse().unwrap(),"127.0.0.1:5702".parse().unwrap(),"127.0.0.1:5704".parse().unwrap()).unwrap();
    let cert=CertificateDer::from(URL_SAFE_NO_PAD.decode(master.certificate).unwrap());
    let mut roots=rustls::RootCertStore::empty();roots.add(cert.clone()).unwrap();
    let verifier=rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots),Arc::new(rustls::crypto::ring::default_provider())).build().unwrap();
    let name=ServerName::try_from("agg-control.invalid").unwrap();
    let now=SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    for seconds_behind in [0,60,240] {
        let time=UnixTime::since_unix_epoch(now-Duration::from_secs(seconds_behind));
        assert!(verifier.verify_server_cert(&cert,&[],&name,&[],time).is_ok(),"clock behind by {seconds_behind}s");
    }
    let too_early=UnixTime::since_unix_epoch(now-Duration::from_secs(600));
    assert!(verifier.verify_server_cert(&cert,&[],&name,&[],too_early).is_err());
    let too_late=UnixTime::since_unix_epoch(now+Duration::from_secs(3651*86_400));
    assert!(verifier.verify_server_cert(&cert,&[],&name,&[],too_late).is_err());
    let wrong_name=ServerName::try_from("wrong.invalid").unwrap();
    assert!(verifier.verify_server_cert(&cert,&[],&wrong_name,&[],UnixTime::since_unix_epoch(now)).is_err());
}
