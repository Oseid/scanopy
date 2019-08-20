#!/usr/bin/python
######################################
#Scanopy: multi-threaded-prot-scanner#
######################################
#Version:    (1.0)                   #
######################################
#CodedBy: Oseid Aldary               #
######################################
import threading,socket,Queue,optparse,signal
from sys import stdout as std
from os import system as sy
qu = Queue.Queue()
done = False
fin = False
openPorts = []
threadFin = 0
fltr = lambda lst,val: list(filter(lambda elem:elem !=val,lst))
def handler(sig,frame):
    global done
    global threadFin
    done = True
    while threadFin==0:continue
    try: qu.task_done()
    finally:exit(1)
def service(port):
    try:return socket.getservbyport(int(port))
    except socket.error: return "??"
def sorte(LIST):
    ck = set()
    cksort = ck.add
    return [elm for elm in LIST if not (elm in ck or cksort(elm))]
def isFloat(var):
    try:
        test = float(var)
        return True
    except ValueError: return False
def scan(server,proto,timeout,verb):
    global done
    global fin
    global threadFin
    while not done:
        if qu.empty():
            fin=True
            return
        try:
         port = qu.get(timeout=.5)
        except Exception:
		fin=True
		return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) if proto.lower() == "tcp" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(int(timeout))
        try:
          s.connect((server,port))
          std.write("[+] {} :: {} :: {} :: {} :: {} ::=> OPEN\n".format(server,port,service(port),proto,str(timeout)+"s" if verb else ""))
          openPorts.append(str(port)+"\\{} ".format(service(port)))
        except socket.error:
            if verb: std.write("[-] {} :: {} :: {} :: {} :: {} ::=> CLOSE\n".format(server,port, service(port),proto,str(timeout)+"s"))
        except Exception:
            qu.put(port)
            qu.task_done()
            return
        qu.task_done()
    threadFin = 1
    std.write("[!] Scan Die: reason: aborted by user !!!\n")
def startScan(target,ports,proto,timeout,threadlen,verb):
    if "," in ports:
        ports = fltr(ports.split(","), "")
        if not all(ports).numerator or not all( 0<= int(port) <=65535 for port in ports):
            print("\n[!] Invalid some port selected !!!")
            exit(1)
        ports = sorte(ports)
    elif "-" in ports:
        start,end = ports.split("-")
        if not start.isdigit() or not end.isdigit() or int(start) > int(end) or int(start) <0 or int(end) > 65535:
            print("\n[!] Invalid Ports Range Selected !!!")
            exit(1)
        ports = range(int(start),int(end)+1)
    else:
        if not ports.strip() or not ports.isdigit():
            print("[!] Invalid Port selected !!!")
            exit(1)
        ports = [ports]
    THREADS = []
    for port in ports: qu.put(int(port))
    if len(ports) < threadlen:threadlen=len(ports)
    print("[i] [{}] Threads started".format(threadlen))
    for i in range(threadlen):
        thread = threading.Thread(target=scan,args=(target,proto,timeout,verb))
        thread.daemon = True
        thread.start()
        THREADS.append(thread)
    signal.signal(signal.SIGINT, handler)
    while not fin: continue
    for thread in THREADS:thread.join()
    qu.join()

parse = optparse.OptionParser("""
   _____                                   
  / ___/_________ _____  ____  ____  __  __
  \\__ \\/ ___/ __ `/ __ \\/ __ \\/ __ \\/ / / /
 ___/ / /__/ /_/ / / / / /_/ / /_/ / /_/ / 
/____/\\___/\\__,_/_/ /_/\\____/ .___/\\__, /  
                           /_/    /____/
[*] Multi-Threaded Port Scanner        1.0
[*] Welcome To Scanopy (^_^)

 [OPTIONS]:
          |-------------------------------------------------
          | -t --target   <TARGET>    [Enter Target to scan]
          |-------------------------------------------------
          | -p --ports    <PORT/S>    [Enter Ports to scan]
          |------------------------------------------------
          | -P --protocol <protocol>  [Enter Connection Protocol]
          |------------------------------------------------------
          | -T --timeout  <Timeout>   [Enter Connection Timeout]
          |-----------------------------------------------------
          | -d --threads  <threads>   [Enter Number Of Threads]
          |----------------------------------------------------
          | -v --verbose              [Show More Output]
[EXAMPLES]:=========================================================
          |--------------------------------------------------------------
          | python scanopy.py -t google.com -p 1-1025 -P UDP -T 0.5 -d 10
          |--------------------------------------------------------------
          | python scanopy.py -t google.com -p 21,22,25,443,80 -P TCP -T 2 -d 5
          |---------------------------------------------------------------------
""")
def main():
    sy("cls||clear")
    parse.add_option("-t","--target",dest="target",type=str)
    parse.add_option("-p","--ports",dest="ports",type=str)
    parse.add_option("-P","--protocol",dest="proto",type=str)
    parse.add_option("-T","--timeout",dest="timeout",type=str)
    parse.add_option("-d","--threads",dest="threads",type=str)
    parse.add_option("-v","--verbose",action="store_true",dest="verb",default=False)
    (opt,args) = parse.parse_args()
    default = []
    if opt.target !=None:
        target = opt.target
        if opt.verb:verb = True
        else:verb = False 
        if opt.ports !=None:
            ports = opt.ports
            if "," in ports and "-" in ports or not ports.replace("-","",1).replace(",","").isdigit():exit("[!] Invalid ports selected !!!\n")
        else:
            default.append("ports=21,22,23,25,51,80,135,139,443,444,445")
            ports = "21,22,23,25,51,80,135,139,443,444,445"
        if opt.proto !=None:
            proto = opt.proto.lower()
            if proto not in ("tcp","udp"):exit("[!] Invalid Connection protocol selected !!!\n")
        else:
            default.append("protocol=TCP")
            proto="tcp"
        if opt.timeout !=None:
                timeout = opt.timeout
                if timeout.isdigit(): timeout = int(timeout)
                elif isFloat(timeout): timeout = float(timeout)
                else:exit("[!] Invalid Timeout selected !!!\n")
        else:
            default.append("timeout=2")
            timeout=2
        if opt.threads !=None:
                threads = opt.threads
                if not threads.isdigit(): exit("[!] Invalid threads Number selected !!!\n")
                else: threads = int(threads)
        else:
            default.append("threads=5")
            threads = 5
        if default:
            print("[*] Using default config of:")
            print("\n".join(default))
        print("\n[~] Scanning ...\n")
        startScan(target, ports, proto, timeout,threads,verb)
        if openPorts:
         print("\n====================================")
         print("[+] OPEND PORTS : [ "+",".join(openPorts)+"]")
    else:
        print(parse.usage)
        exit(1)
if __name__ == "__main__":
    main()

##############################################################
#####################                #########################
#####################   END OF TOOL  #########################
#####################                #########################
##############################################################
#This Tool by Oseid Aldary
#Have a nice day :)
#GoodBye

