//! Human terminal output with a stable, unchanged JSON mode for scripts.
use serde_json::Value;
use std::sync::atomic::{AtomicBool,Ordering};
static JSON:AtomicBool=AtomicBool::new(true);
pub fn configure(json:bool){JSON.store(json,Ordering::Relaxed);}
fn text<'a>(value:&'a Value,key:&str)->&'a str{value[key].as_str().unwrap_or("-")}
fn command_path(value:&Value)->String {
    // Display paths only: never execute this string. Quote spaces for copy/paste.
    let path=text(value,"state");format!("'{}'",path.replace('\'',"'\\''"))
}
pub fn emit(value:Value){
    if JSON.load(Ordering::Relaxed){println!("{value}");return;}
    match text(&value,"event") {
        "initialized"=>{
            println!("主服配置已保存：{}",text(&value,"state"));
            println!("加入串（敏感，请私下交给中继/客户端）：\n{}",text(&value,"invitation"));
            println!("下一步：agg-fec-tunnel run --state {}",command_path(&value));
        },
        "joined"=>{
            println!("已注册 {} 节点，配置：{}",text(&value,"role"),text(&value,"state"));
            println!("节点 ID：{}",text(&value,"id"));
            if let Some(services)=value["services"].as_array(){println!("可用服务：{}",services.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "));}
            println!("下一步：agg-fec-tunnel run --state {}",command_path(&value));
        },
        "ready"=>{
            println!("已启动 {}",text(&value,"role"));
            for key in ["control","udp_bind","tcp_listen"] {if !value[key].is_null(){println!("  {key}: {}",value[key].as_str().unwrap_or("-"));}}
            if let Some(list)=value["forwards"].as_array(){for item in list {println!("  {} → {}",text(item,"listen"),text(item,"service"));}}
            if let Some(list)=value["services"].as_array(){for item in list {println!("  {} → {}",text(item,"service"),text(item,"target"));}}
            println!("按 Ctrl-C 退出。管理 TLS 不加密 UDP 业务数据；请使用受保护的内层协议。");
        },
        "managed_session"=>{
            let tx=value["tx_bytes"].as_u64().unwrap_or(0);let rx=value["rx_bytes"].as_u64().unwrap_or(0);
            println!("完成 [{}]：发送 {:.2} MiB，接收 {:.2} MiB，耗时 {:.2}s，重传 {} 次",
                text(&value,"service"),tx as f64/1_048_576.0,rx as f64/1_048_576.0,
                value["elapsed_s"].as_f64().unwrap_or(0.0),value["retries"]);
        },
        "topology"=>println!("线路列表已更新：revision={}，入口数={}",value["revision"],value["peers"].as_array().map_or(0,Vec::len)),
        "session_error"|"connection_rejected"=>eprintln!("连接 [{}]：{}",text(&value,"service"),text(&value,"error")),
        "config_valid"=>{
            println!("配置检查通过：{} ({})",text(&value,"state"),text(&value,"role"));
            for key in ["control","control_bind","udp_bind"]{if !value[key].is_null(){println!("  {key}: {}",value[key]);}}
            if let Some(list)=value["forwards"].as_array(){for item in list{println!("  {} → {}",text(item,"service"),item.get("target").or_else(||item.get("listen")).unwrap_or(&Value::Null));}}
            println!("仅离线检查；未探测网络、目标服务或端口占用。UDP 数据面没有加密。");
        },
        _=>println!("{value}"),
    }
}
pub fn status(value:Value){
    if JSON.load(Ordering::Relaxed){println!("{}",serde_json::to_string_pretty(&value).unwrap_or_else(|_|"{}".into()));return;}
    println!("主服：{}；配置修订：{}",value["master"],value["revision"]);
    if let Some(list)=value["services"].as_array(){println!("服务：{}",list.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(", "));}
    if let Some(list)=value["members"].as_array(){for member in list{
        let state=if member["revoked"].as_bool()==Some(true){"已吊销"}else if member["online"].as_bool()==Some(true){"在线"}else{"离线"};
        println!("{} [{} / {}] {}  ID={}",text(member,"name"),text(member,"role"),state,value_ip(member),text(member,"id"));
    }}
}
fn value_ip(value:&Value)->&str{value["public_ip"].as_str().unwrap_or("-")}
