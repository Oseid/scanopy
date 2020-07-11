#!/usr/bin/python
######################################
#Scanopy: multi-threaded-prot-scanner#
######################################
#Version:    (2.0)                   #
######################################
#CodedBy: Oseid Aldary               #
######################################

import socket,threading,signal,sys,optparse,random,struct
from time import sleep as se
from os import path,sep,system
from collections import OrderedDict as odict

if not path.isdir("core"):
    print("[!] Error: subFolder[Core] Is Missing Please reinstall the tool to reinstall it!!!")
    sys.exit(1)
if not path.isfile("core"+sep+"probes.pkl"):
    print("[!] Error: File[{}] Is Missing Please reinstall the tool to reinstall it!!!".format("core"+sep+"probes.pkl"))
    sys.exit(1)
if not path.isfile("core"+sep+"services.py"):
    print("[!] Error: File[{}] Is Missing Please reinstall the tool to reinstall it!!!".format("core"+sep+"services.py"))
    sys.exit(1)
if not path.isfile("core"+sep+"vslib.py"):
    print("[!] Error: File[{}] Is Missing Please reinstall the tool to reinstall it!!!".format("core"+sep+"vslib.py"))
    sys.exit(1)
if sys.version_info.major <=2:
    import Queue,urllib
    qu = lambda : Queue.Queue()
    input = raw_input
else:
    import queue,urllib.request as urllib
    qu = lambda : queue.Queue()
    input = input
from core.services import Services
from core.vslib import write,parser,serviceScan

errmsg = lambda msg: write("#y[#r-#y] Error: {}#r !!!#w\n".format(msg))


class anym(threading.Thread):
    def __init__(self,prompt):
        threading.Thread.__init__(self)
        self.prompt = prompt
        self.done = False
    def run(self):
        self.done = False
        anim = ('[=      ]', '[ =     ]', '[  =    ]', '[   =   ]',
         '[    =  ]', '[     = ]', '[      =]', '[      =]',
         '[     = ]', '[    =  ]', '[   =   ]', '[  =    ]',
      '[ =     ]', '[=      ]')
        i = 0
        dot = "."
        while not self.done:
                if len(dot) ==4:
                    dot = "."
                    write("\b\b\b\b")
                    write("     ")
                write("\r"+anim[i % len(anim)]+self.prompt+dot)
                se(1.0/5)
                i+=1
                dot+="."
                if self.done:break

def getPorts(ports):
    if not set(ports).issubset("1234567890,-"):return False
    PORTS = []
    ports = ports.strip()
    if "," in ports:
      ports = list(filter(lambda elem:elem if elem.strip() else None,ports.split(",")))
      for port in ports:
       if "-" not in port:
        if port.isdigit() and  0 <= int(port) <= 65535:PORTS.append(int(port))
       else:
        if port.count("-")==1:
         s,e= port.split("-")
         if s.strip() and e.strip():
          if s.isdigit() and e.isdigit():
           s,e=int(s),int(e)
           if s<e:
            if s >=0 and e <= 65535: PORTS+=range(s, e+1)
    elif "-" in ports:
     if ports.count("-")==1:
      s,e = ports.split("-")
      if s.strip() and e.strip():
       if s.isdigit() and e.isdigit():
         s,e=int(s),int(e)
         if s<e:
          if s >= 0 and e <= 65535:PORTS=range(s, e+1)
    else:
     if ports.isdigit() and 0 <= int(ports) <= 65535 :PORTS = [int(ports)]
    return PORTS

def getService(port, status="open",raw=False):
    if port in Services.keys():
       if status=="open":return  "/#g{}".format(Services[port]) if not raw else Services[port]
       else:return "/#r{}".format(Services[port])
    return ""

class PortScan(object):
    def __init__(self,sock,target,port,timeout):
        self.sock = sock
        self.target = target
        self.port=port
        self.timeout = timeout
    @property
    def tcpScan(self):
        self.sock.settimeout(self.timeout)
        try:
            self.sock.connect((self.target, self.port))
            self.sock.close()
            return True
        except socket.error:pass
        return False

    @property
    def udpScan(self):
            try:
                self.sendPkt()
                self.sock.close()
                return True
            except (socket.error,socket.timeout):pass
            return False

    def sendPkt(self):
        pkt=self._build_packet()
        self.sock.settimeout(self.timeout)
        self.sock.sendto(bytes(pkt), (self.target, self.port))
        data, addr = self.sock.recvfrom(1024)
        self.sock.close()

    def _build_packet(self):
        randint = random.randint(0, 65535)
        packet = struct.pack(">H", randint)
        packet += struct.pack(">H", 0x0100)
        packet += struct.pack(">H", 1)
        packet += struct.pack(">H", 0)
        packet += struct.pack(">H", 0)
        packet += struct.pack(">H", 0)
        packet += struct.pack("B", 0)
        packet += struct.pack(">H", 1)
        packet += struct.pack(">H", 1)
        return packet

class scanThread(threading.Thread):
    daemon = True
    def __init__(self):
        threading.Thread.__init__(self)
    createSocket = lambda self: socket.socket(socket.AF_INET, socket.SOCK_STREAM) if config['protocol'] == "tcp" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    def run(self):
        while True:
            lock.acquire()
            if config['ports'].empty():
                lock.release()
                break
            try:port = config['ports'].get()
            except Exception:break
            lock.release()
            sock = self.createSocket()
            if config['protocol']=="tcp":result = PortScan(sock, config['target'], port, config['timeout']).tcpScan
            else:result = PortScan(sock, config['target'], port, config['timeout']).udpScan
            if result:
                if config['debug']:config['result']['all'][port]="open"
                else:config['result']['open'].append(port)
                if config['verbose'] or config['debug']:
                    if not isKilled():write("#g[#w+#g] {}#w:#g{}#w{}/#g{}#w :#g OPEN\n".format(config['target'], port,getService(port), config['protocol']))
                if config['servScan']:
                    if config['verbose']:write("[~] Scanning for [{}] Service Info...\n".format(port))
                    info =config['servScan'].scan(config['target'], port, config['protocol'])
                    if info:
                        config['result']['vscan'][port]=parser(info)
                        if config['debug']:del config['result']['all'][port]
                        else:config['result']['open'].remove(port)
                config['result']['all'][0]=1
            else:
                if config['debug']:config['result']['all'][port]="close"
                else:config['result']['close'].append(port)
                if config['verbose'] or config['debug']:
                    if not isKilled():write("#y[#r-#y] {}#w:#r{}#y{}#y/#r{}#y :#r CLOSED\n".format(config['target'], port, getService(port, status="close"), config['protocol']))
            if isKilled():
                config['ret']+=1
                break
            config['ports'].task_done()

class Main(object):
    def __init__(self):
        self.interactiveMode = False
        self.runner = False
        self.done = False
        self.autoclean = False
        self.target = ""
        self.portsByProto = {"tcp":"1,3,7,9,13,17,19,20-23,25,26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464,465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000", "udp":"7,9,13,17,19,21-23,37,42,49,53,67-69,80,88,111,120,123,135-139,158,161-162,177,192,199,389,407,427,443,445,464,497,500,514-515,517-518,520,593,623,626,631,664,683,800,989-990,996-999,1001,1008,1019,1021-1034,1036,1038-1039,1041,1043-1045,1049,1068,1419,1433-1434,1645-1646,1701,1718-1719,1782,1812-1813,1885,1900,2000,2002,2048-2049,2148,2222-2223,2967,3052,3130,3283,3389,3456,3659,3703,4000,4045,4444,4500,4672,5000-5001,5060,5093,5351,5353,5355,5500,5632,6000-6001,6346,7938,9200,9876,10000,10080,11487,16680,17185,19283,19682,20031,22986,27892,30718,31337,32768-32773,32815,33281,33354,34555,34861-34862,37444,39213,41524,44968,49152-49154,49156,49158-49159,49162-49163,49165-49166,49168,49171-49172,49179-49182,49184-49196,49199-49202,49205,49208-49211,58002,65024"}
        self.protocol = "tcp"
        self.portsSet = False
        self.ports = self.portsByProto[self.protocol.lower()]
        self.timeout = "5"
        self.vscan = "false"
        self.threads = "30"
        self.verbose = "false"
        self.debug = "false"
        self.options = ("target", "ports", "protocol", "timeout", "threads", "vscan", "verbose", "debug")
        self.defaultVal = {"target":self.target,"protocol": self.protocol, "timeout": self.timeout, "threads":self.threads, "vscan":self.vscan, "verbose":self.verbose, "debug": self.debug}
        self.tarOpt = odict([("target",['yes',"Specify Target hostname or IP",self.target]),
                        ("ports",['optional',"Specify Ports To Scan",self.ports]),
                        ("protocol",['optional', "Specify Connection Protocol",self.protocol]),
                       ("timeout", ['optional',"Specify Connection Timeout",self.timeout])])
        self.modOpt = odict([
                       ("threads", ['optional', "Specify Number Of Threads",self.threads]),
                       ("vscan", ['optional', "Specify 'true' To Enable Service And Version Scan",self.vscan]),
                       ("verbose",['optional',"Specify 'true' To Show Output",self.verbose]),
                       ("debug", ['optional', "Specify 'true' To Show More Output", self.debug])])
        self.commands = odict([("help","show this help msg"),
                         ("start","start scanopy scan "),
                         ("options","show scanopy options"),
                         ("set", "set values of options"),
                         ("reset", "reset value of option to default"),
                         ("exec", "execute an external command"),
                         ("autoclean", "auto clean the screen"),
                         ("exit", "exit scanopy script")])
        self.banner = """
   _____
  / ___/_________ _____  ____  ____  __  __
  \\__ \\/ ___/ __ `/ __ \\/ __ \\/ __ \\/ / / /
 ___/ / /__/ /_/ / / / / /_/ / /_/ / /_/ /
/____/\\___/\\__,_/_/ /_/\\____/ .___/\\__, /
                           /_/    /____/
[*] Multi-Threaded Port Scanner        2.0
"""
    def quit(self,sig,fream):
     if not self.done:
      if not config['verbose'] and not config['debug']: an.done = True
      if config['servScan']:config['servScan'].done = True
      kill()
      write("\n#y[#r~#y]#r Aborting#y...\n")
      while config['ret'] != config['threads']: continue
      if config['debug'] and self.printed <2:
          for t in self.THREADS:write("#y[#r!#y] Thread-{} :#y Aborted #r!\n".format(t.ident))
      write("\n#r[#y!#r]#y Scan Die#r:#y reason#r:#y Aborted by user #r!!!\n\n")
      if not self.printed:self.printPorts()
      self.abroFlag = True
     else:sys.exit("\n")
    def startThreads(self):
        if config['verbose'] or config['debug']:write("#g[#w~#g]#w Scanning ...\n")
        else:
            global an
            an = anym("Scanning[{}]".format(config['target']))
            an.start()
        for _ in range(config["threads"]):
            thread = scanThread()
            thread.start()
            self.THREADS.append(thread)
        for t in self.THREADS:t.join()
        self.finFlag = True

    def printPorts(self):
        vv = False
        if config['servScan'] and config['result']['vscan']:
            vv = True
            write("[*] Services Info OF[{}]\n".format(config['target']))
            for port,info in config['result']['vscan'].items():
                space ="==========="+"="*len(str(port))+"====="
                write(space+"\n[*] PORT["+str(port)+"] INFO:\n"+space+ "\n")
                for key,val in info:
                    if not len(val):continue
                    write("    [+] {} : {}\n".format(key.strip(), val.strip()))
                write("\n")
        write("\n")
        if not config['debug'] and config['result']['close']:write("[*] Not Shown: [{}] closed ports.\n\n".format(len(config['result']['close'])))
        if vv:
            if  config['debug'] and config['result']['all'][0] or config['result']['open']:write("[*] Other Ports Has Found.\n\n")
        if config['result']['open'] or config['debug'] and config['result']['all'][0]:
            write("PORT\t STATE\t SERVICE\n")
            if config['debug']:
                for port,state in config['result']['all'].items()[1:]:write("{}/{}\t {}\t {}\n".format(port,config['protocol'],state,getService(port, raw=True)))
            if config["result"]['open']:
                for port in config['result']['open']:write("{}/{}\t {}\t {}\n".format(port,config['protocol'],"OPEN",getService(port, raw=True)))
        if config['debug']:
            if config["result"]['close']:
                for port in config['result']['close']:write("{}/{}\t {}\t {}\n".format(port,config['protocol'],"CLOSE",getService(port, raw=True)))
    def show_options(self):
        if self.autoclean:self.clean()
        LAYOUT ="  {!s:15} {!s:10} {!s:50} {!s:39}"
        self.tarOpt = odict([("target",['yes',"Specify Target hostname or IP",self.target]),
                        ("ports",['optional',"Specify Ports To Scan",self.ports]),
                        ("protocol",['optional', "Specify Connection Protocol",self.protocol]),
                       ("timeout", ['optional',"Specify Connection Timeout",self.timeout])])
        self.modOpt = odict([
                       ("threads", ['optional', "Specify Number Of Threads",self.threads]),
                       ("vscan", ['optional', "Specify 'true' To Enable Service And Version Scan",self.vscan]),
                       ("verbose",['optional',"Specify 'true' To Show Output",self.verbose]),
                       ("debug", ['optional', "Specify 'true' To Show More Output", self.debug])])
        write("\n#gTarget Options\n#w==============#g\n\n")
        print(LAYOUT.format("[option]","[RQ]","[Description]","[value]"))
        write("#w  --------        ----       -------------                                      -------\n")
        for opt in self.tarOpt.keys():
            val = self.tarOpt[opt]
            if opt == "ports":val[-1]="top-200-ports"
            print(LAYOUT.format(*[opt]+val))

        write("\n#wModule Options\n#g==============#w\n\n")
        print(LAYOUT.format("[option]","[RQ]","[Description]","[value]"))
        write("#g  --------        ----       -------------                                      -------\n")
        for opt in self.modOpt.keys():
            print(LAYOUT.format(*[opt]+self.modOpt[opt]))

    def show_help(self):
                if self.autoclean:self.clean()
                LAYOUT ="  {!s:16} {!s:10}"
                write("\n#gScanopy Commands\n#w================\n\n")
                write("  Command          Description\n  #g-------#w          #g-----------\n")
                for com,des in self.commands.items():
                    print(LAYOUT.format(*[com,des]))
    clean = staticmethod(lambda : system("cls||clear"))

    def resetPorts(self):
        self.portsSet = False
        return self.portsByProto[self.protocol]

    def checkInternet(self):
       try:
         socket.create_connection((socket.gethostbyname("www.google.com"), 80), 2)
         return True
       except socket.error: pass
       return False

    def interactive(self,skip=0):
       if not skip:
          self.clean()
          write(self.banner+"\n")
          write("[*] Welcome To Scanopy Interactive Mode Interface(^_^)\n[*] type 'help' to show help msg.\n\n")
       try:
        while True:
            cmd = input("Scanopy> ").strip()
            if not cmd:continue
            elif cmd.lower() == "update":
                if not self.checkInternet():
                      errmsg("Error: Unable to update reason: no internet connection")
                      continue
                write("[~] Checking for updates...")
                repoVersion = urllib.urlopen("https://raw.githubusercontent.com/Oseid/scanopy/master/core/version.txt").read().strip()
                with open("core"+sep+"version.txt") as version:
                     thisVersion = version.read().strip()
                if repoVersion == thisVersion:
                        write("  [*] The tool is up to date!\n")
                        continue
                else:
                    ask = input("[?] An update has been found, do you want to update now?(Y:n)> ").strip()
                    while not ask:
                             ask = input(" [!] please ansawer by 'y' for yes or 'n' for no ?> ").strip()
                    if ask.lower() in ("yes","y"):
                         write("\m[~] Updating...please wait")
                         script = urllib.urlopen("https://raw.githubusercontent.com/Oseid/scanopy/master/scanopy.py").read()
                         with open("scanopy.py", "wb") as  scanopy:
                               scanopy.write(script)

                         write("  [+] Successfully updated :)\n\n[*] Please relaunch tool to apply :)")
                         break
                script = urllib.urlopen("https://raw.githubusercontent.com/Oseid/scanopy/master/scanopy.py").read()
            elif cmd.lower() == "exit":
                        print("[*] Exit Scanopy script...bye :)")
                        break
            elif cmd.lower() == "autoclean":
                self.autoclean = True if not self.autoclean else False
                write("[+] autoclean ==> {}\n".format("#w[#gON#w]" if self.autoclean else "#y[#rOFF#y]"))
            elif cmd.lower() in ("cls", "clear"):self.clean()
            elif cmd.lower() == "help":self.show_help()
            elif cmd.lower() == "options":self.show_options()
            elif cmd.lower() == "start":self.start()
            elif cmd.lower().startswith("set"):
                data = "".join(cmd.strip().split("set")).strip()
                if not data:write("Usage: set <Option> <Value>\n")
                elif not " " in data:
                    opt = data.strip()
                    if not opt in  self.options:write("[!] Unknown Option: '{}' !!!\n".format(opt))
                    elif opt == "target":write("Usage: set target <target hostname or ip> e.g: set target google.com\n")
                    elif opt == "ports":write("Usage: set ports <port1,port2,port-range> e.g: set ports 20-25,80,445,8080,200-1025\n")
                    elif opt == "protocol":write("Usage: set protocol <protocol(tcp,udp)> e.g: set protocol udp\n")
                    elif opt == "timeout":write("Usage: set timeout  e.g: set timeout 0.05\n")
                    elif opt == "threads":write("Usage: set threads <number_of_threads> e.g: set threads 200\n")
                    elif opt == "vscan":write("Usage: set vscan <true, false> e.g: set vscan true")
                    elif opt == "verbose":write("Usage: set verbose <true, false> e.g: set verbose true")
                    else:write("Usage: set debug <true, false> e.g: set debug true")
                elif data.count(" ") != 1:write("[!] Unknown Command: '{}' !!!\n".format(data))
                else:
                    opt,val = data.split(" ")
                    opt = opt.lower()
                    if opt not in self.options:
                        write("[!] Unknown Option: '{}' !!!\n".format(opt))
                        continue
                    for option in self.options:
                        if opt == option:
                            if option == "ports":self.portsSet = True
                            if option == "protocol":
                                if not val.lower() in ("tcp", "udp"):
                                      errmsg("Invalid Connection Protocol Must be 'tcp' or 'udp'")
                                      break
                                if not self.portsSet:self.ports = self.portsByProto[val.lower()]
                            write("[+] {} ==> {}\n".format(option, val))
                            exec('self.{} = "{}"'.format(option,val))
                            break
            elif cmd.lower().startswith("exec"):
                execom = "".join(cmd.split("exec")[1]).strip()
                if not execom:
                    write("[!] exec <command <args>: eg: ls -alt>\n")
                    continue
                system(execom)
            elif cmd.lower() in self.options:write("[*] {} = {} ".format(cmd, eval("self.{}".format(cmd.lower()))))
            elif cmd.lower().startswith("reset"):
                opt = cmd.lower().strip().split(" ")
                if len(opt) == 2:
                  opt = opt[1].lower()
                  if opt == "all":
                    write("[~] Reset All Options...\n")
                    for option in self.options:
                        defval = self.defaultVal[option] if option != "ports" else self.resetPorts()
                        exec('self.{} = "{}"'.format(option, defval))
                        write("  [+] {} ==> {}\n".format(option, defval if option != "ports" else "top-200-ports"))
                    continue
                  if opt not in self.options:
                    write("[!] Unable to reset option : reason: Unknown option !!!\n")
                    continue
                  defaultValue = self.defaultVal[opt] if opt != "ports" else self.resetPorts()
                  exec('self.{} = "{}"'.format(opt,defaultValue))
                  write("[~] {} ==> {}\n".format(opt, defaultValue if opt != "ports" else "top-200-ports"))
                  continue
                write("[*] Usage:  reset <option, all> (e.g: reset target)")
            else:write("[!] Unknown Command: '{}' !!!\n".format(cmd))
            print(" ")
        sys.exit(1)
       except (KeyboardInterrupt,EOFError):sys.exit("\n")

    def start(self):
        global event
        global kill
        global isKilled
        global lock
        event = threading.Event()
        kill = lambda :event.set()
        isKilled =lambda :event.isSet()
        lock = threading.Lock()
        self.THREADS = []
        self.finFlag = False
        self.abroFlag = False
        self.printed = 0
        target = self.target
        ports = self.ports
        protocol = self.protocol.lower()
        timeout = self.timeout
        versionScan = self.vscan
        threads = self.threads
        verbose = self.verbose
        debug = self.debug
        if not target.strip():
            errmsg("Target is not selected")
            return False
        ports =  getPorts(ports)
        if not ports:
            errmsg("Invalid Ports Selected")
            return False
        try:timeout = float(timeout)
        except ValueError:
              if not timeout.strip() or not timeout.isdigit():
                errmsg("timeout must be an number")
                return False
              timeout = int(timeout)
        if not timeout:
            errmsg("timeout cannot be '{}'".format(timeout))
            return False
        if not threads.strip() or not threads.isdigit():
            errmsg("threads Must be an number")
            return False
        threads = int(threads)
        if not threads:
            errmsg("threads cannot be '{}'".format(threads))
            return False
        if not verbose.strip() or verbose.lower() not in {'true','false'}:
            errmsg("verbose: must be 'true' or 'false'")
            return False
        if not debug.strip() or debug.lower() not in {'true', 'false'}:
            errmsg("debug: must be 'true' or 'false'")
            return False
        if not versionScan.strip() or versionScan.lower() not in {'true', 'false'}:
            errmsg("versionScan: must be 'true' or 'false'")
            return False
        verbose = True if verbose.lower() == "true" else False
        debug = True if debug.lower() == "true" else False
        versionScan = True if versionScan.lower() == "true" else False
        if versionScan:
            if not self.runner:
              write("[~] Loading ....\n")
              servScan = serviceScan()
              servScan.verbose = verbose
              self.runner = servScan
            else:servScan = self.runner
        else:servScan = False
        if threads > len(ports):threads = len(ports)
        qus = qu()
        for port in ports:qus.put(port)
        global config
        config = {"target":target,
                  "ports":qus,
                  "protocol":protocol,
                  "timeout":timeout,
                  "threads":threads,
                  "servScan": servScan,
                  "verbose": verbose,
                  "debug":debug,
                  "ret":0,
                  "result":{
                    "open":[],
                   "close":[],
                   "all":{0:0},
                   "vscan": {}}}
        if verbose or debug: write("#w[#y~#w]#y Starting #g{}#y Threads#w....\n".format(threads))
        mainThread = threading.Thread(target=self.startThreads)
        mainThread.daemon = True
        mainThread.start()
        self.done = False
        signal.signal(signal.SIGINT, self.quit)
        signal.signal(signal.SIGTERM,self.quit)
        while not self.finFlag:
            if self.abroFlag:break
            continue
        self.done = True
        if self.abroFlag:
          if self.interactiveMode:self.interactive(skip=1)
          else:sys.exit(1)
        if debug:
            for thread in self.THREADS:write("#g[#w*#g]#w Thread-{} : has #gFinshied\n".format(thread.ident))
            self.printed+=1
        if  not config['verbose'] and not config['debug']: an.done = True
        write("\n")
        self.printPorts()
        self.printed+=1
        mainThread.join()
        config['ports'].join()
        if self.interactiveMode:self.interactive(skip=1)
        else:sys.exit(1)

parse = optparse.OptionParser("""
Usage: python ./scanopy.py [OPTIONS...]
-------------
OPTIONS:
       |
    |--------
    | -t --target   <TARGET>      (<required>)
    |--------
    | -p --ports    <PORT/S>      Default(<TOP_PORTS>)
    |--------
    | -P --protocol <protocol>    Default(<tcp>)
    |--------
    | -T --timeout  <Timeout>     Default(<5>)
    |--------
    | -r --threads  <threads>     Default(<5>)
    |--------
    | -i --interactive            Default(<off>)
    |--------
    | -s --vscan                  Default(<off>)
    |--------
    | -v --verbose                Default(<off>)
    |--------
    | -d --debug                  Default(<off>)
-------------
Examples:
        |
     |--------
     | python scanopy.py -i # enter to interactive mode interface
     |-----------------------------------------------------------
     | python scanopy.py -t google.com -p 1-1025 -P UDP -T 0.5 -r 10  -v
     |------------------------------------------------------------------
     | python scanopy.py -t 192.168.1.1 -p 21-25,80,135,443-445,139 -P TCP -T 2 -r 15 -d
     |----------------------------------------------------------------------------------
     | python scanopy.py -t 192.168.1.1 -p 1-1025,4444 -P TCP -T 2  -s -r 20 -d
     |-------------------------------------------------------------------------
""")

def main():
    portScan = Main()
    portScan.clean()
    write(portScan.banner + "\n")
    write("[*] Welcome To Scanopy (^_^)\n")
    parse.add_option("-i", "--interactive", action="store_true", dest="interactive",default=False)
    parse.add_option("-t","--target",dest="target",type=str, help="set target to scan")
    parse.add_option("-p","--ports",dest="ports",type=str, help="set ports to scan target with it")
    parse.add_option("-P","--protocol",dest="protocol",type=str, help="set Connection Protocol")
    parse.add_option("-T","--timeout",dest="timeout",type=str, help="set Connection Timeout")
    parse.add_option("-s","--vscan",action="store_true",dest="vscan",default=False, help="use service and version scan")
    parse.add_option("-r","--threads",dest="threads",type=str, help="set how many threads you wont to scan")
    parse.add_option("-d","--debug",action="store_true",dest="debug",default=False, help="Show more Output")
    parse.add_option("-v","--verbose",action="store_true",dest="verbose",default=False, help="show Output")
    (opt,args) = parse.parse_args()
    if opt.interactive:
        portScan.interactiveMode = True
        portScan.interactive()

    elif opt.target !=None:
        portScan.target = opt.target
        if opt.verbose:portScan.verbose = "true"
        if opt.debug:portScan.debug = "true"
        if opt.ports !=None:portScan.ports = opt.ports
        if opt.protocol !=None:portScan.protocol = opt.protocol
        if opt.timeout !=None:portScan.timeout = opt.timeout
        if opt.vscan:portScan.vscan = 'true'
        if opt.threads !=None:portScan.threads = opt.threads
        portScan.start()
    else:
        print(parse.usage)
        sys.exit(1)

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
