//! Per-command help and validation, preserving the existing CLI argument spellings.
//! The public subcommand parser validates before the internal Args carrier parses
//! defaults. That prevents irrelevant flags from being silently ignored by `run`.
use clap::{Command, CommandFactory, Parser};
use super::Args;

const START: &str = "低延迟分支：init 默认 latency，预握手 8 条空闲会话，1+0 编码、单 lane、1100 字节分片，
缺口等待 5ms，上下行各 80Mbps 共享线路预算（含全部副本），不把业务硬限速为 10Mbps。
balanced 对照为 64+8、8 lanes、1300 字节、40ms 凑块、30ms 缺口、260/80Mbps，不预热。
预热会话与业务连接共用 32 个流名额；预热不提前连接后端，已用连接不回池、不重放请求。

快速开始（IP 为文档示例，请替换）：
  主服：agg-fec-tunnel init --control 198.51.100.10:5706 --advertise 198.51.100.10:5702 \\
          --forward web=127.0.0.1:8080 --forward ssh=127.0.0.1:22
        agg-fec-tunnel run
  中继：agg-fec-tunnel join --as relay --advertise 198.51.100.11:5702
  客户端：agg-fec-tunnel join --forward web=127.0.0.1:18080 --forward ssh=127.0.0.1:10022
  join 时粘贴主服生成的 agg1:// 加入串，回车；然后执行 agg-fec-tunnel run。

主服、中继和客户端是不同机器或不同配置文件。同一实例最多 16 个服务、32 条并发 TCP 流。
主服通常需要开放 5706/TCP（管理）和 5702/UDP（数据）；中继需要自己的 UDP 端口。
默认配置文件 ./agg-fec.json；用 --state 指定其他路径。
控制连接使用 TLS；UDP 数据面不加密。请承载 SSH/TLS 等受保护的内层业务。
RC 验收重点是单宽带多 TCP 端口；多宽带仅有模拟验证，UDP/WG 仍是实验功能。

查看命令示例：agg-fec-tunnel init --help / join --help / run --help
脚本调用：加 --json；输出重定向或管道环境也默认输出 JSON。加入串输出请勿存入公开日志。";

fn describe(id: &str) -> &'static str {
    match id {
        "state" => "配置/身份文件（含凭据，权限须为 600）；主服与节点使用各自文件",
        "control" => "主服对外的 TLS 管理 IP:端口；例如 198.51.100.10:5706",
        "advertise" => "主服或中继对外的 UDP IP:端口；例如 198.51.100.10:5702",
        "bind" => "本程序的 UDP 绑定地址；NAT/多网卡时可与对外地址不同",
        "target" => "兼容旧单端口模式：主服连接的固定目标 IP:端口；与 --forward 二选一",
        "forward" => "可重复。init: 名称=服务端目标；join: 相同名称=客户端本地监听",
        "profile" => "latency：低延迟专用；balanced：原 RC 对照。init 默认 latency，原始诊断默认 balanced；显式参数优先",
        "warm_sessions" => "全局预握手空闲会话数 0..16；latency 默认 8，balanced 默认 0；多个端口共用",
        "node_role" => "加入角色：client（客户端）或 relay（中继）；默认客户端",
        "name" => "便于 status 识别的节点名称（不是账号密码）",
        "invite" => "加入串；推荐从标准输入或 --invite-file 读取，避免进入命令历史",
        "invite_file" => "从文件读取加入串；文件须为仅所有者可读写的普通文件",
        "listen" => "旧单端口客户端监听（只允许回环）；多端口请重复 --forward",
        "interface" => "绑定指定接口，如 macOS en0、Linux eth0；不修改系统路由",
        "ifindex" => "接口编号（高级）；日常使用 --interface 接口名",
        "uplink" => "可重复：接口=上行/下行 Mbps，如 en0=40/150；仅模拟验收",
        "wire_mbps" => "下行总线路预算 Mbps，含校验及重传；多个端口共用，不是每连接限速",
        "upload_wire_mbps" => "上行总线路预算 Mbps；多个连接和宽带共用",
        "data_shards" => "每个完整纠错组的原包数；通常保持默认值",
        "repair_shards" => "每个完整纠错组的校验包数；64+8 表示约 12.5% 编码冗余",
        "lanes" => "FEC 时间交织组数；不是宽带或中继数量",
        "payload" => "单个源符号的最大字节数；还需给 UDP/IP 和外层头部留空间",
        "block_ms" => "生成短块校验前的最大凑块毫秒数；原包不会等待凑满",
        "nack_ms" => "报告缺口前的等待毫秒数；不是网络 RTT 或重传超时",
        "node_id" => "status 显示的节点 ID；吊销后禁止该身份继续加入",
        "exit_on_stdin" => "标准输入关闭或收到一行就退出（测试/SSH 托管使用）",
        "lifetime_seconds" => "进程最长运行秒数；0 表示持续运行",
        "peer" => "固定对端 UDP IP:端口，可重复（原始诊断模式）",
        "main" => "原始中继固定转发到的主服 UDP IP:端口",
        "client_ip" => "原始中继允许的客户端公网 IP；不接受任意目标转发",
        "rtt_only" => "仅用于对照：关闭原包到达质量评分",
        "adaptive_retry" => "实验 RTT 自适应补包间隔，默认关闭",
        "udp_reorder_ms" => "实验 UDP 有限重排等待毫秒数；0 为立即无序交付",
        "test_delay_after" => "故障注入开始秒数（仅诊断）",
        "test_delay_ms" => "故障注入单方向延迟毫秒数（仅诊断）",
        _ => "",
    }
}

fn command(name: &'static str, about: &'static str, ids: &[&str], examples: &'static str) -> Command {
    let source = Args::command();
    let mut cmd = Command::new(name).about(about).after_help(examples).next_line_help(false);
    for id in ids {
        let mut arg = source.get_arguments().find(|a| a.get_id().as_str() == *id)
            .expect("help references an existing Args field").clone().help(describe(id));
        arg = arg.help_heading(match *id {
            "data_shards"|"repair_shards"|"lanes"|"payload"|"block_ms"|"nack_ms" => "高级 FEC 参数（建议保留默认）",
            "wire_mbps"|"upload_wire_mbps" => "共享带宽预算",
            "uplink"|"ifindex" => "多宽带 / 高级选项",
            "exit_on_stdin"|"lifetime_seconds" => "进程管理",
            _ => "选项",
        });
        if *id == "forward" {arg=arg.value_name("NAME=IP:PORT");}
        if *id == "uplink" {arg=arg.value_name("IFACE=UP/DOWN");}
        if *id == "state" {arg=arg.value_name("FILE");}
        if matches!(*id,"data_shards"|"repair_shards"|"lanes"|"payload"|"block_ms"|"nack_ms"|"wire_mbps"|"upload_wire_mbps") {arg=arg.hide_default_value(true);}
        if *id == "profile" && name != "init" {arg=arg.default_value("balanced");}
        if *id == "bind" {arg=arg.hide_default_value(true).help("实际 UDP 绑定地址；主服/中继默认同对外地址，客户端默认任意本地地址的随机端口");}
        if name == "init" && matches!(*id, "control"|"advertise") { arg=arg.required(true); }
        if name == "init" && *id == "target" { arg=arg.required_unless_present("forward").conflicts_with("forward"); }
        if name == "join" && *id == "node_role" { arg=arg.value_parser(["client","relay"]); }
        if name == "join" && *id == "advertise" { arg=arg.required_if_eq("node_role","relay"); }
        if name == "revoke" && *id == "node_id" { arg=arg.required(true); }
        cmd=cmd.arg(arg);
    }
    cmd
}

pub fn definition() -> Command {
    let mut root=Command::new("agg-fec-tunnel").version(env!("CARGO_PKG_VERSION"))
        .about("低延迟多端口 TCP 中继：常驻预握手会话、多路径冗余、独立连接恢复")
        .subcommand_required(true).arg_required_else_help(true).after_help(START)
        .arg(clap::Arg::new("json").long("json").global(true).action(clap::ArgAction::SetTrue)
             .help("强制 JSON 输出，适合脚本和日志采集"));
    #[cfg(feature="managed")]
    {
        root=root
            .subcommand(command("init","初始化主服配置并生成加入串（不自动启动、不修改防火墙）",
                &["state","control","advertise","bind","target","forward","profile","warm_sessions","wire_mbps","upload_wire_mbps","data_shards","repair_shards","lanes","payload","block_ms","nack_ms"],
                "示例：\n  agg-fec-tunnel init --control 198.51.100.10:5706 --advertise 198.51.100.10:5702 \\\n    --forward web=127.0.0.1:8080 --forward ssh=127.0.0.1:22\n  agg-fec-tunnel check\n  agg-fec-tunnel run\n\n目标地址是主服务器能够访问的服务，不是客户端地址。只支持数字 IP；IPv6 写为 [::1]:8080。\n配置文件已存在时不会覆盖。init 需要 OpenSSL；run 不需要 OpenSSL。"))
            .subcommand(command("join","客户端或中继使用同一个加入串注册，保存独立身份（不自动启动）",
                &["state","node_role","name","advertise","bind","listen","forward","invite","invite_file","interface","ifindex","uplink"],
                "客户端示例：\n  agg-fec-tunnel join --name my-client --forward web=127.0.0.1:18080 \\\n    --forward ssh=127.0.0.1:10022 --interface en0\n中继示例：\n  agg-fec-tunnel join --as relay --name relay-1 --advertise 198.51.100.11:5702\n\n命令执行后粘贴 agg1:// 加入串并回车，然后执行 agg-fec-tunnel run。\n脚本可用：agg-fec-tunnel join ... --invite-file /安全目录/invite.txt\n服务名称须与主服一致；客户端端口可不同。例如 127.0.0.1:10022 → 主服 ssh 目标。\n客户端只监听回环地址，不直接向局域网/公网开放本地转发端口。\n多宽带属于实验能力：--uplink en0=40/150 --uplink en1=40/150。当前 RC 不承诺真实双宽带性能。"))
            .subcommand(command("run","读取配置启动主服/中继/客户端；自动重连并接收线路热更新",
                &["state","exit_on_stdin","lifetime_seconds"],
                "示例：\n  agg-fec-tunnel run --state master.json\n  agg-fec-tunnel run --state client.json\n\n角色与转发端口从配置文件读取，不要给 run 重复传 --forward 或 --target。\n中继名单热更新不重启 TCP 流；端口映射、编码参数和接口配置改变后需重启。\nCtrl-C 或 SIGTERM 退出会关闭本进程的活动连接；不会修改其他服务或系统路由。"))
            .subcommand(command("check","离线检查配置与接口，显示端口映射；不连接服务器、不启动监听",
                &["state"],"示例：agg-fec-tunnel check --state client.json\n本命令不探测公网可达性、不测试目标服务、不预留端口，也不会输出密钥或加入串。"))
            .subcommand(command("status","从主服查询服务列表、在线成员和接入线路",
                &["state"],"示例：agg-fec-tunnel status --state master.json\n需要主服正在运行，并使用主服配置中的管理员凭据；普通节点配置不能执行管理操作。"))
            .subcommand(command("invite","重新输出主服当前的加入串（敏感信息，请私下传递）",
                &["state"],"示例：agg-fec-tunnel invite --state master.json\n加入串不含主服私钥。已有节点使用独立身份重连，无须反复输入加入串。"))
            .subcommand(command("rotate","轮换加入串：旧串不再接纳新节点，已有身份不受影响",
                &["state"],"示例：agg-fec-tunnel rotate --state master.json\n需要主服在线。该操作会保存新注册凭据，不是轮换业务加密密钥。"))
            .subcommand(command("revoke","吊销指定节点，推送线路移除；不能用旧身份重新加入",
                &["state","node_id"],"示例：\n  agg-fec-tunnel status --state master.json\n  agg-fec-tunnel revoke --state master.json --node-id <节点ID>\n保留至少一条可用线路，才能让活动连接继续传输。"));
    }
    // Keep diagnostic spellings compatible with the existing laboratories, but
    // do not bury the supported managed TCP workflow under experimental options.
    let raw=&["bind","peer","listen","target","main","client_ip","name","interface","ifindex","wire_mbps","profile",
        "data_shards","repair_shards","lanes","payload","block_ms","nack_ms","rtt_only","adaptive_retry",
        "udp_reorder_ms","exit_on_stdin","lifetime_seconds","test_delay_after","test_delay_ms"];
    for name in ["client","server","relay","udp-client","udp-server","http-test"] {
        root=root.subcommand(command(name,"原始实验/诊断模式；多端口请使用 init/join/run",raw,
            "此模式不使用管理注册或 AFM3 多流协议。UDP/WG 尚不属于本次 RC 的性能承诺范围。").hide(true));
    }
    root
}

pub fn parse() -> Args {
    parse_input(std::env::args_os().collect())
}
fn parse_input(input:Vec<std::ffi::OsString>) -> Args {
    // Help/version/errors terminate here before any credential or network access.
    let matches=definition().get_matches_from(input.clone());
    let mut args=Args::parse_from(input);
    if let Some((_,sub))=matches.subcommand() {
        if let Ok(Some(profile))=sub.try_get_one::<String>("profile") {args.profile=profile.clone();}
        if args.profile=="latency" && (args.role=="init"||args.role=="client"||args.role=="server") {
            let explicit=|id|sub.value_source(id)==Some(clap::parser::ValueSource::CommandLine);
            if !explicit("wire_mbps"){args.wire_mbps=80;}
            if args.role=="init" && !explicit("upload_wire_mbps"){args.upload_wire_mbps=80;}
            if !explicit("data_shards"){args.data_shards=1;}
            if !explicit("repair_shards"){args.repair_shards=0;}
            if !explicit("lanes"){args.lanes=1;}
            if !explicit("payload"){args.payload=1100;}
            if !explicit("block_ms"){args.block_ms=1;}
            if !explicit("nack_ms"){args.nack_ms=5;}
        }
    }
    args
}

#[cfg(all(test,feature="managed"))]
mod tests {
    use super::*;
    #[test]
    fn help_definitions_are_consistent_and_command_specific() {
        definition().debug_assert();
        let mut root=definition();let text=root.render_long_help().to_string();
        assert!(text.contains("join"));assert!(!text.contains("--data-shards"));
        let text=root.find_subcommand_mut("join").unwrap().render_long_help().to_string();
        assert!(text.contains("--forward"));assert!(text.contains("客户端端口可不同"));
        assert!(!text.contains("--repair-shards"));
    }
    #[test]
    fn inappropriate_or_incomplete_commands_fail_before_any_io() {
        for args in [vec!["agg","run","--target","127.0.0.1:80"],vec!["agg","init"],
            vec!["agg","join","--as","relay"],vec!["agg","join","--as","mistake"],vec!["agg","revoke"]] {
            assert!(definition().try_get_matches_from(args).is_err());
        }
        assert!(definition().try_get_matches_from(["agg","run"]).is_ok());
        assert!(definition().try_get_matches_from(["agg","--json","check"]).is_ok());
    }
    #[test]
    fn latency_profile_and_explicit_overrides_resolve_before_io() {
        let base=["agg","init","--control","127.0.0.1:5706","--advertise","127.0.0.1:5702","--target","127.0.0.1:8080"];
        let parse=|extra:&[&str]|parse_input(base.iter().chain(extra).map(std::ffi::OsString::from).collect());
        let a=parse(&[]);
        assert_eq!((a.profile.as_str(),a.data_shards,a.repair_shards,a.lanes,a.payload,a.block_ms,a.nack_ms,a.wire_mbps),("latency",1,0,1,1100,1,5,80));
        let a=parse(&["--profile","balanced"]);
        assert_eq!((a.data_shards,a.repair_shards,a.lanes,a.payload,a.block_ms,a.nack_ms,a.wire_mbps),(64,8,8,1300,40,30,260));
        let a=parse(&["--wire-mbps","120","--payload","900","--nack-ms","9","--warm-sessions","0"]);
        assert_eq!((a.wire_mbps,a.payload,a.nack_ms,a.warm_sessions),(120,900,9,Some(0)));
        let raw=parse_input(["agg","client","--profile","latency"].into_iter().map(Into::into).collect());
        assert_eq!((raw.data_shards,raw.wire_mbps),(1,80));
        let raw=parse_input(["agg","client"].into_iter().map(Into::into).collect());
        assert_eq!(raw.profile,"balanced");
    }
}
