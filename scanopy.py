#!/usr/bin/python
######################################
#Scanopy: multi-threaded-prot-scanner#
######################################
#Version:    (1.0)                   #
######################################
#CodedBy: Oseid Aldary               #
######################################
######### Libraries & Config #########
import threading,socket,optparse,signal
from sys import stdout as std,version_info
from os import system as sy
if version_info.major == 2:
    import Queue
    qu = Queue.Queue()
else:
    import queue
    qu = queue.Queue()
openPorts = []
THREADS = []
onc = 0
finlen = 0
stop = threading.Event()
def handler(sig,frame):
    stop.set()
    finlen=len(THREADS)
    for thread in THREADS:
        while thread.isAlive():continue
    if ver:printThreads("abro")
    std.write("[!] Scan Die: reason: aborted by user !!!\n")
    joinThreads()
    printOpenPorts()
    exit(1)
def joinThreads():
    stop.set()
    for thread in THREADS:thread.join()
def printOpenPorts():
    if openPorts:
        std.write("\n====================================\n")
        std.write("[+] OPEND PORTS : [ "+", ".join(openPorts)+"]\n")
    else:std.write("\n====================================\n[-] No Open Ports was detected !!!\n")
fltr = lambda lst: list(filter(lambda elem:elem if elem.strip() else None,lst))
def service(port,ck=False):
    try:
        serv = socket.getservbyport(int(port))
        return "{}".format( serv if not ck else "\\{} ".format(serv))
    except socket.error:return "{}".format("??" if not ck else "")
def sorte(LIST):
    ck = set()
    cksort = ck.add
    return [elm for elm in LIST if not (elm in ck or cksort(elm))]
def isFloat(var):
    try:
        test = float(var)
        return True
    except ValueError: return False
def printThreads(act):
    global onc
    if act =="fin" and onc ==0:
        for thread in THREADS:print("[*] thread-{} Finshied".format(thread.ident))
    elif act =="abro" and onc==0:
        for thread in THREADS:print("[!] thread-{} Aborted".format(thread.ident))
    onc+=1
def getPorts(ports):
    PORTS = []
    ports = ports.strip()
    if "," in ports:
        ports = fltr(ports.split(","))
        for port in ports:
            if "-" not in port:
                if port.isdigit():PORTS.append(int(port))
            else:
                s,e= port.split("-")
                if s.isdigit() and e.isdigit():
                    s,e=int(s),int(e)
                    if s<e:
                        if s >=0 and e <= 65535: PORTS+=range(s, e+1)
    elif "-" in ports:
        s,e = ports.split("-")
        if s.isdigit() and e.isdigit():
            s,e=int(s),int(e)
            if s<e:
                if s >= 0 and e <= 65535:PORTS=range(s, e+1)
    else:
        if ports.isdigit() and 0 <= int(ports) <= 65535 :PORTS = [int(ports)]
    return PORTS
def scan(stop,server,proto,timeout,verb):
    global ver
    global finlen
    ver=verb
    while not stop.wait(1):
        if qu.empty():
             finlen+=1
             break
        try:port = qu.get()
        except Exception:
                finlen+=1
                break
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) if proto.lower() == "tcp" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(int(timeout))
        try:
          s.connect((server,port))
          std.write("[+] {} :: {} :: {} :: {} :: {} ::=> OPEN\n".format(server,port,service(port),proto,str(timeout)+"s" if verb else ""))
          openPorts.append(str(port)+"{}".format(service(port,ck=True)))
        except socket.error:
            if verb: std.write("[-] {} :: {} :: {} :: {} :: {} ::=> CLOSE\n".format(server,port, service(port),proto,str(timeout)+"s"))
        except Exception:qu.put(port)
        qu.task_done()
def startScan(target,ports,proto,timeout,threadlen,verb):
    ports = list(dict.fromkeys(ports))
    for port in ports:qu.put(port)
    if len(ports) < threadlen:threadlen=len(ports)
    for i in range(threadlen):
        thread = threading.Thread(target=scan,args=(stop,target,proto,timeout,verb))
        thread.setDaemon = True
        thread.start()
        THREADS.append(thread)
    print("[~] [{}] Threads Has Started".format(threadlen))
    signal.signal(signal.SIGINT, handler)
    while len(THREADS) !=finlen:continue
    qu.join()
    joinThreads()
    if verb:printThreads("fin")
parse = optparse.OptionParser("""
   _____                                   
  / ___/_________ _____  ____  ____  __  __
  \\__ \\/ ___/ __ `/ __ \\/ __ \\/ __ \\/ / / /
 ___/ / /__/ /_/ / / / / /_/ / /_/ / /_/ / 
/____/\\___/\\__,_/_/ /_/\\____/ .___/\\__, /  
                           /_/    /____/
[*] Multi-Threaded Port Scanner        1.1
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
          |---------------------------------------------
[EXAMPLES]:
          |-------------------------------------------------------------
          | python scanopy.py -t google.com -p 1-1025 -P UDP -T 0.5 -d 10
          |--------------------------------------------------------------
          | python scanopy.py -t 192.168.1.1 -p 21-25,80,135,443-445,139 -P TCP -T 2 -d 6 -v
          |---------------------------------------------------------------------------------
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
            ports = getPorts(ports)
            if not ports:exit("[!] Invalid Ports Selected !!!")
        else:
            default.append("ports=21,22,23,25,51,80,135,139,443,444,445")
            ports = [21,22,23,25,51,80,135,139,443,444,445]
        if opt.proto !=None:
            proto = opt.proto.lower()
            if proto not in ("tcp","udp"):exit("[!] Invalid Connection Protocol !!!\n")
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
                if not threads.isdigit(): exit("[!] Invalid Number Of Threads!!!\n")
                else: threads = int(threads)
        else:
            default.append("threads=5")
            threads = 5
        if default:
            print("[*] Using default config of:")
            print("\n".join(default))
        print("\n[~] Scanning ...\n")
        startScan(target, ports, proto, timeout,threads,verb)
        printOpenPorts()
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
