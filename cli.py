
import argparse, concurrent.futures, csv, ipaddress, json, platform, re, socket, subprocess, time
from dataclasses import asdict, dataclass
from pathlib import Path

COMMON = "21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,6379,8080,8443,9200"
NAMES = {21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",80:"http",110:"pop3",135:"msrpc",139:"netbios",143:"imap",443:"https",445:"smb",993:"imaps",995:"pop3s",1433:"mssql",3306:"mysql",3389:"rdp",5432:"postgresql",5900:"vnc",6379:"redis",8080:"http-alt",8443:"https-alt",9200:"elasticsearch"}

@dataclass
class Port:
    port: int
    state: str
    service: str
    banner: str = ""

@dataclass
class Host:
    ip: str
    status: str
    os_guess: str
    open_ports: list

def parse_ports(spec):
    result=set()
    for item in spec.split(","):
        item=item.strip()
        if not item: continue
        if "-" in item:
            a,b=map(int,item.split("-",1))
            if a>b: raise ValueError("Invalid port range: "+item)
            result.update(range(a,b+1))
        else: result.add(int(item))
    if not result or min(result)<1 or max(result)>65535: raise ValueError("Ports must be 1-65535.")
    if len(result)>4096: raise ValueError("Maximum 4096 ports per scan.")
    return sorted(result)

def targets_for(spec, allow_large):
    net=ipaddress.ip_network(spec, strict=False)
    count=net.num_addresses - (2 if net.version==4 and net.prefixlen<=30 else 0)
    if count>4096 and not allow_large: raise ValueError("Target exceeds 4096 addresses; use --allow-large only on authorized networks.")
    if count>65536: raise ValueError("Hard limit is 65,536 target addresses.")
    return [str(x) for x in net.hosts()] if net.prefixlen < (32 if net.version==4 else 128) else [str(net.network_address)]

def ping(ip, timeout):
    sysname=platform.system().lower()
    if sysname=="windows": cmd=["ping","-n","1","-w",str(int(timeout*1000)),ip]
    elif sysname=="darwin": cmd=["ping","-c","1","-W",str(int(timeout*1000)),ip]
    else: cmd=["ping","-c","1","-W",str(max(1,int(timeout))),ip]
    try:
        p=subprocess.run(cmd,capture_output=True,text=True,timeout=timeout+1)
        out=p.stdout+p.stderr
        m=re.search(r"\b(?:ttl|hlim)[=\s](\d+)",out,re.I)
        return p.returncode==0, int(m.group(1)) if m else None
    except (OSError,subprocess.TimeoutExpired): return False,None

def banner_for(sock, port):
    try:
        sock.settimeout(.35)
        if port in (80,8080,8000,8888): sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        return sock.recv(512).decode("utf-8","replace").replace("\r"," ").replace("\n"," ")[:240].strip()
    except (OSError,TimeoutError): return ""

def check_port(ip, port, timeout, get_banner):
    try:
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip,port)) != 0: return None
            return Port(port,"open",NAMES.get(port,"unknown"),banner_for(s,port) if get_banner else "")
    except OSError: return None

def os_guess(ttl, ports):
    if ttl is not None:
        if ttl<=64: return "Unix/Linux-like (TTL heuristic)"
        if ttl<=128: return "Windows-like (TTL heuristic)"
        return "Network device / Unix-like (TTL heuristic)"
    if {135,445,3389}.intersection(ports): return "Possibly Windows (port heuristic)"
    if 22 in ports: return "Possibly Unix/Linux (SSH heuristic)"
    return "Unknown"

def scan_host(ip, ports, timeout, workers, do_ping, do_banner):
    alive,ttl=(ping(ip,timeout) if do_ping else (False,None))
    found=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        jobs=[pool.submit(check_port,ip,p,timeout,do_banner) for p in ports]
        for job in concurrent.futures.as_completed(jobs):
            item=job.result()
            if item: found.append(item); alive=True
    found.sort(key=lambda x:x.port)
    return Host(ip,"up" if alive else "no-response",os_guess(ttl,[p.port for p in found]),found)

def main():
    parser=argparse.ArgumentParser(prog="netprobe",description="Threaded TCP scanner for authorized network inventory.")
    sub=parser.add_subparsers(dest="cmd",required=True)
    scan=sub.add_parser("scan",help="Discover responsive hosts and open TCP ports.")
    scan.add_argument("target",help="Single IP address or CIDR network")
    scan.add_argument("--ports",default=COMMON,help="Ports: 22,80,443 or range 1-1024")
    scan.add_argument("--threads",type=int,default=100)
    scan.add_argument("--timeout",type=float,default=.6)
    scan.add_argument("--no-ping",action="store_true")
    scan.add_argument("--no-banner",action="store_true")
    scan.add_argument("--format",choices=["json","csv"],default="json")
    scan.add_argument("-o","--output",type=Path,default=Path("netprobe-results.json"))
    scan.add_argument("--allow-large",action="store_true")
    args=parser.parse_args()
    if not 1<=args.threads<=500: parser.error("--threads must be 1-500")
    if not 0<args.timeout<=10: parser.error("--timeout must be >0 and <=10")
    try: targets=targets_for(args.target,args.allow_large); ports=parse_ports(args.ports)
    except ValueError as e: parser.error(str(e))
    print(f"[*] {len(targets)} target(s), {len(ports)} TCP port(s). Scan only with permission.")
    start=time.time(); results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as pool:
        jobs=[pool.submit(scan_host,ip,ports,args.timeout,min(args.threads,500),not args.no_ping,not args.no_banner) for ip in targets]
        for job in concurrent.futures.as_completed(jobs):
            host=job.result(); results.append(host)
            if host.status=="up":
                opened=", ".join(f"{p.port}/{p.service}" for p in host.open_ports) or "no selected ports open"
                print(f"[+] {host.ip} | {host.os_guess} | {opened}")
    results.sort(key=lambda h:ipaddress.ip_address(h.ip))
    args.output.parent.mkdir(parents=True,exist_ok=True)
    if args.format=="json":
        args.output.write_text(json.dumps([asdict(h) for h in results],indent=2),encoding="utf-8")
    else:
        with args.output.open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f,fieldnames=["ip","status","os_guess","port","state","service","banner"]); w.writeheader()
            for h in results:
                if not h.open_ports: w.writerow({"ip":h.ip,"status":h.status,"os_guess":h.os_guess})
                for p in h.open_ports: w.writerow({"ip":h.ip,"status":h.status,"os_guess":h.os_guess,**asdict(p)})
    print(f"\n[+] Finished in {time.time()-start:.1f}s. Live: {sum(h.status=='up' for h in results)}/{len(results)}")
    print(f"[+] Results: {args.output}")
    return 0

if __name__=="__main__": raise SystemExit(main())
