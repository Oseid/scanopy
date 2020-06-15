#!/usr/bin/python
######################################
#Scanopy: multi-threaded-prot-scanner#
######################################
#Version:    (2.0)                   #
######################################
#CodedBy: Oseid Aldary               #
######################################
import socket,threading,signal,sys,optparse
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
    import Queue
    qu = lambda : Queue.Queue()
    input = raw_input
else:
    import queue
    qu = lambda : queue.Queue()
    input = input
from core.services import Services
from core.vslib import write,parser,serviceScan

errmsg = lambda msg: write("#y[#r-#y] Error: {}#r!!!#w\n".format(msg))


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
class scanThread(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.daemon = True
    createSocket = lambda self: socket.socket(socket.AF_INET, socket.SOCK_STREAM) if config['proto'] == "tcp" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
            sock.settimeout(config['timeout'])
            try:
                sock.connect((config['target'], port))
                sock.close()
                del sock
                if config['debug']:config['result']['all'][port]="open"
                else:config['result']['open'].append(port)
                if config['verbose'] or config['debug']:
                    if not isKilled():write("#g[#w+#g] {}#w:#g{}#w{}/#g{}#w :#g OPEN\n".format(config['target'], port,getService(port), config['proto']))
                if config['servScan']:
                    if config['verbose']:write("[~] Scanning for [{}] Service Info...\n".format(port))
                    info =config['servScan'].scan(config['target'], port, config['proto'])
                    if info:
                        config['result']['vscan'][port]=parser(info)
                        if config['debug']:del config['result']['all'][port]
                        else:config['result']['open'].remove(port)
                config['result']['all'][0]=1
            except socket.error:
                sock.close()
                del sock
                if config['debug']:config['result']['all'][port]="close"
                else:config['result']['close'].append(port)
                if config['verbose'] or config['debug']:
                    if not isKilled():write("#y[#r-#y] {}#w:#r{}#y{}#y/#r{}#y :#r CLOSED\n".format(config['target'], port, getService(port, status="close"), config['proto']))
            except Exception:break
            if isKilled():break
            config['ports'].task_done()

class Main(object):
    def __init__(self):
        self.interactiveMode = False
        self.InteractiveExit = False
        self.runner = False
        self.autoclean = False
        self.target = ""
        self.ports = "20-25,53,67,68,80,443,110,111,135,139,143,445,465,993,995,1433,1521,3306,3389,4899,8080"
        self.proto = "tcp"
        self.timeout = "5"
        self.vscan = "false"
        self.threads = "5"
        self.verbose = "false"
        self.debug = "false"
        self.options = ("target", "ports", "proto", "timeout", "threads", "vscan", "verbose", "debug", "autoclean")
        self.tarOpt = odict([("target",['yes',"Specify Target hostname or IP",self.target]),
                        ("ports",['optional',"Specify Ports To Scan",self.ports]),
                        ("proto",['optional', "Specify Connection Protocol",self.proto]),
                       ("timeout", ['optional',"Specify Connection Timeout",self.timeout])])
        self.modOpt = odict([
                       ("threads", ['optional', "Specify Number Of Threads",self.threads]),
                       ("vscan", ['optional', "Specify 'true' To Enable Service And Version Scan",self.vscan]),
                       ("verbose",['optional',"Specify 'true' To Show Output",self.verbose]),
                       ("debug", ['optional', "Specify 'true' To Show More Output", self.debug]),
                       ("autoclean", ["optional","auto clear the screen", "false"])])
        self.commands = odict([("help","show this help msg"),
                         ("start","start scanopy scan "),
                         ("options","show scanopy options"),
                         ("set", "set values of options"),
                         ("exec", "execute an external command"),
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
        write("\n#y[#r~#y]#r Aborting#y...\n")
        if not config['verbose'] and not config['debug']: an.done = True
        if config['servScan']:config['servScan'].done = True
        kill()
        if config['debug'] and self.printed <2:
            for t in self.THREADS:write("#y[#r!#y] Thread-{} :#y Aborted #r!\n".format(t.ident))
        write("#r[#y!#r]#y Scan Die#r:#y reason#r:#y Aborted by user #r!!!\n\n")
        if not self.printed:self.printPorts()
        self.abroFlag = True
    def interExit(self,sig,fream):
          print("\n[!] Exit Scanopy script...bye :)")
          sys.exit(1)

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
                for port,state in config['result']['all'].items()[1:]:write("{}/{}\t {}\t {}\n".format(port,config['proto'],state,getService(port, raw=True)))
            if config["result"]['open']:
                for port in config['result']['open']:write("{}/{}\t {}\t {}\n".format(port,config['proto'],"OPEN",getService(port, raw=True)))
        if config['debug']:
            if config["result"]['close']:
                for port in config['result']['close']:write("{}/{}\t {}\t {}\n".format(port,config['proto'],"CLOSE",getService(port, raw=True)))
    def show_options(self):
        if self.autoclean:self.clean()
        LAYOUT ="  {!s:15} {!s:10} {!s:50} {!s:50}"
        self.tarOpt = odict([("target",['yes',"Specify Target hostname or IP",self.target]),
                        ("ports",['optional',"Specify Ports To Scan",self.ports]),
                        ("proto",['optional', "Specify Connection Protocol",self.proto]),
                       ("timeout", ['optional',"Specify Connection Timeout",self.timeout])])
        self.modOpt = odict([
                       ("threads", ['optional', "Specify Number Of Threads",self.threads]),
                       ("vscan", ['optional', "Specify 'true' To Enable Service And Version Scan",self.vscan]),
                       ("verbose",['optional',"Specify 'true' To Show Output",self.verbose]),
                       ("debug", ['optional', "Specify 'true' To Show More Output", self.debug]),
                       ("autoclean", ["optional","auto clear the screen", "true" if self.autoclean else "false"])])
        write("\n#gTarget Options\n#w==============\n\n#g")
        print(LAYOUT.format("[option]","[RQ]","[Description]","[value]"))
        write("#w  --------        ----       -------------                                      -------\n")
        for opt in self.tarOpt.keys():
            print(LAYOUT.format(*[opt]+self.tarOpt[opt]))

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
    def interactive(self,skip=0):
        signal.signal(signal.SIGINT, self.interExit)
        signal.signal(signal.SIGTERM, self.interExit)
        if not skip:
          self.clean()
          write(self.banner+"\n")
          write("[*] Welcome To Scanopy Interactive Mode Interface(^_^)\n[*] type 'help' to show help msg.\n\n")
        while True:
            cmd = input("Scanopy> ").strip()
            if not cmd:continue
            elif cmd.lower() == "exit":break
            elif cmd.lower() in ("cls", "clear"):self.clean()
            elif cmd.lower() == "help":self.show_help()
            elif cmd.lower() == "options":self.show_options()
            elif cmd.lower() == "start":self.start()
            elif cmd.lower().startswith("set"):
                data = "".join(cmd.strip().split("set")).strip()
                if not data:
                    write("Usage: set <Option> <Value>\n")
                    continue
                elif not " " in data:
                    opt = data.strip()
                    if not opt in  self.options:write("[!] Unknown Option: '{}' !!!\n".format(opt))
                    elif opt == "target":write("Usage: set target <target hostname or ip>\n")
                    elif opt == "ports":write("Usage: set ports <port1,port2,port-range>\n")
                    elif opt == "proto":write("Usage: set proto <protocol(tcp,udp)>\n")
                    elif opt == "timeout":write("Usage: set timeout <timeout(eg: 2,0.05)>\n")
                    else:write("Usage: set autoclean <true, false> default(<False>)\n")
                    continue
                elif data.count(" ") != 1:
                    write("[!] Unknown Command: '{}' !!!\n".format(data))
                    continue
                else:
                    opt,val = data.split(" ")
                    opt = opt.lower()
                    if opt not in self.options:
                        write("[!] Unknown Option: '{}' !!!\n".format(opt))
                        continue
                    for option in self.options:
                        if opt == option :
                            if option == "autoclean":
                                if val.lower() not in ("true", "false"):
                                    write("[!] Invalid Value: autoclean(true, false): your value({})".format(val))
                                    break
                                self.autoclean = True if val.lower() == "true" else False
                                write("[+] {} ==> {}\n".format(option, val))
                                break
                            write("[+] {} ==> {}\n".format(option, val))
                            exec('self.{} = "{}"'.format(option,val))
                            break
            elif cmd.startswith("exec"):
                execom = "".join(cmd.split("exec")[1]).strip()
                if not execom:
                    write("[!] exec <command <args>: eg: ls -alt>\n")
                    continue
                system(execom)
            else:write("[!] Unknown Command: '{}' !!!\n".format(cmd))
            print(" ")
        self.InteractiveExit = True
        print("\n[!] Exit Scanopy script...bye :)")
      # except (KeyboardInterrupt, EOFError):
      #    print("\n[!] Exit Scanopy script...bye :)")
      #    sys.exit(1)
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
        proto = self.proto
        timeout = self.timeout
        versionScan = self.vscan
        threads = self.threads
        verbose = self.verbose
        debug = self.debug
        if not target.strip():
            errmsg("Target is not selected")
            return False
        ports = getPorts(ports)
        if not ports:
            errmsg("Invalid Ports Selected")
            return False
        if not proto.strip() or proto.lower() not in {"tcp", "udp"}:
            errmsg("Invalid Connection Protocol Must be 'tcp' or 'udp'")
            return False
        proto = proto.lower()
        try:timeout = float(timeout)
        except ValueError:
              if not timeout.strip() or not timeout.isdigit():
                errmsg("timeout must be an number")
                return False
              timeout = int(timeout)
        if not threads.strip() or not threads.isdigit():
            errmsg("threads Must be an number !!!")
            return False
        threads = int(threads)
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
                  "proto":proto,
                  "timeout":timeout,
                  "threads":threads,
                  "servScan": servScan,
                  "verbose": verbose,
                  "debug":debug,
                  "result":{
                    "open":[],
                   "close":[],
                   "all":{0:0},
                   "vscan": {}}}
        if verbose or debug: write("#w[#y~#w]#y Starting #g{}#y Threads#w....\n".format(threads))
        mainThread = threading.Thread(target=self.startThreads)
        mainThread.daemon = True
        mainThread.start()
        signal.signal(signal.SIGINT, self.quit)
        signal.signal(signal.SIGTERM,self.quit)
        while not self.finFlag:
            if self.abroFlag:break
            continue
        signal.signal(signal.SIGINT, self.interExit)
        signal.signal(signal.SIGTERM, self.interExit)
        if self.abroFlag:
            if self.interactiveMode:
                self.interactive(skip=1)
            else:sys.exit(1)
        if self.InteractiveExit:sys.exit(1)
        if debug:
            for thread in self.THREADS:write("#g[#w*#g]#w Thread-{} : has #gFinshied\n".format(thread.ident))
            self.printed+=1
        if  not config['verbose'] and not config['debug']: an.done = True
        write("\n")
        self.printPorts()
        self.printed+=1
        mainThread.join()
        config['ports'].join()

parse = optparse.OptionParser("""
Usage: python ./scanopy.py [OPTIONS...]
-------------
OPTIONS:
       |
    |--------
    | -t --target   <TARGET>      (<required>)
    |--------
    | -p --ports    <PORT/S>      Default(<20-25,53,67,68,80,443,110,111,135,139,143,445,465,993,995,1433,1521,3306,3389,4899,8080>)
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
    parse.add_option("-P","--protocol",dest="proto",type=str, help="set Connection Protocol")
    parse.add_option("-T","--timeout",dest="timeout",type=str, help="set Connection Timeout")
    parse.add_option("-s","--vscan",action="store_true",dest="vscan",default=False, help="use service and version scan")
    parse.add_option("-r","--threads",dest="threads",type=str, help="set how many threads you wont to scan")
    parse.add_option("-d","--debug",action="store_true",dest="debug",default=False, help="Show more Output")
    parse.add_option("-v","--verbose",action="store_true",dest="verbose",default=False, help="show Output")
    (opt,args) = parse.parse_args()
    if opt.interactive:
        portScan.interactiveMode = True
        portScan.interactive()
        sys.exit(1)

    elif opt.target !=None:
        portScan.target = opt.target
        if opt.verbose:portScan.verbose = "true"
        if opt.debug:portScan.debug = "true"
        if opt.ports !=None:portScan.ports = opt.ports
        if opt.proto !=None:portScan.proto = opt.proto
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
