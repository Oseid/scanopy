#-* coding: utf-8 -*-
import os,re,codecs,socket,contextlib,pickle,sys

parser = lambda data: [[key,"|".join(data['match']['versioninfo'][key])] for key in data['match']['versioninfo'].keys() if data['match']['versioninfo'][key]] if "match" in data.keys() and "versioninfo" in data['match'].keys() else None
def write(text):
    sys.stdout.write(text.replace("#r", "\033[1;31m").replace("#g","\033[1;32m").replace("#y", "\033[1;33m").replace("#w", "\033[1;37m") + '\033[1;37m')
    sys.stdout.flush()
class serviceScan(object):
    def __init__(self, socktimeout=10, socksize=1024, tryy=2,verbose=False):
        self.socktimeout = socktimeout
        self.socksize = socksize
        self.verbose = verbose
        self.tryy = tryy
        self.tryyb  =self.tryy
        probesFile = open(__file__.split("vslib.py")[0]+"probes.pkl", "rb")
        self.allprobes =  pickle.load(probesFile) if sys.version_info.major <=2 else pickle.load(probesFile, encoding="utf8")
        probesFile.close()
    sort_probes_by_rarity = lambda self,probes:sorted(probes, key=lambda k: k['rarity']['rarity'])
    def scan(self, host, port, protocol):
        self.done = False
        self.tryy = self.tryyb
        nmap_fingerprint = {}
        in_probes, ex_probes = self.filter_probes_by_port(port, self.allprobes)
        if in_probes:
            probes = self.sort_probes_by_rarity(in_probes)
            nmap_fingerprint = self.scan_with_probes(host, port, protocol, probes)
        if nmap_fingerprint: return nmap_fingerprint
        if ex_probes:
            nmap_fingerprint = self.scan_with_probes(host, port, protocol, ex_probes)
        return nmap_fingerprint
    def scan_with_probes(self, host, port, protocol, probes):
        nmap_fingerprint = {}
        for probe in probes:
            record = self.send_probestring_request(host, port, protocol, probe, self.socktimeout)
            if bool(record["match"]["versioninfo"]):
                nmap_fingerprint = record
                break
            if self.done:break
        return nmap_fingerprint
    def send_probestring_request(self, host, port, protocol, probe, timeout):
        proto = probe['probe']['protocol']
        payload = probe['probe']['probestring']
        payload, _ = codecs.escape_decode(payload)
        response = ""
        if (proto.upper() == protocol.upper()):
            if (protocol.upper() == "TCP"):response = self.send_tcp_request(host, port, payload, timeout)
            elif (protocol.upper() == "UDP"):response = self.send_udp_request(host, port, payload, timeout)
        nmap_pattern, nmap_fingerprint = self.match_probe_pattern(response, probe)
        return {"probe": {
                     "probename": probe["probe"]["probename"],
                     "probestring": probe["probe"]["probestring"]
                      },
                  "match": {
                     "pattern": nmap_pattern,
                     "versioninfo": nmap_fingerprint
                  }}
    def send_tcp_request(self, host, port, payload, timeout):
        data = ''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as client:
                client.settimeout(timeout)
                client.connect((host, int(port)))
                client.send(payload)
                while True:
                    if self.done:break
                    _ = client.recv(self.socksize)
                    if not _: break
                    data += _ if sys.version_info.major <=2 else _.decode("ISO-8859-1")
        except Exception as err:
           if self.verbose: write("Try[#{}] {} : {} - {}".format(self.tryy,host, port, err))
           if not self.tryy:self.done = True
           else:self.tryy-=1
        return data
    def send_udp_request(self, host, port, payload, timeout):
        data = ''
        try:
            with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_DGRAM)) as client:
                client.settimeout(timeout)
                client.sendto(payload, (host, port))
                while True:
                    if self.done:break
                    _, addr =client.recvfrom(self.socksize)
                    if not _: break
                    data += _ if sys.version_info.major <=2 else _.decode("ISO-8859-1")
        except Exception as err:
           if self.verbose: write("Try[#{}] {} : {} - {}\n".format(self.tryy,host, port, err))
           if not self.tryy:self.done = True
           else:self.tryy-=1
        return data
    def match_probe_pattern(self, data, probe):
        nmap_pattern, nmap_fingerprint = "", {}
        if not data:return nmap_pattern, nmap_fingerprint
        for match in probe['matches']:
            rfind = match['pattern_compiled'].findall(data)
            if rfind and ("versioninfo" in match):
                versioninfo = match['versioninfo']
                rfind = rfind[0]
                rfind = [rfind] if isinstance(rfind, str) else rfind
                for index, value in enumerate(rfind):
                    dollar_name = "${}".format(index + 1)
                    versioninfo = versioninfo.replace(dollar_name, value)
                nmap_pattern = match['pattern']
                nmap_fingerprint = self.match_versioninfo(match['service'],versioninfo)
                break
        return nmap_pattern, nmap_fingerprint
    def match_versioninfo(self, service,versioninfo):
        record = {"service":[service],
                  "vendorproductname": [],
                  "version": [],
                  "info": [],
                  "hostname": [],
                  "operatingsystem": [],
                  "cpename": []}
        if "p/" in versioninfo:
            regex = re.compile(r"p/([^/]*)/")
            vendorproductname = regex.findall(versioninfo)
            record["vendorproductname"] = vendorproductname
        if "v/" in versioninfo:
            regex = re.compile(r"v/([^/]*)/")
            version = regex.findall(versioninfo)
            record["version"] = version
        if "i/" in versioninfo:
            regex = re.compile(r"i/([^/]*)/")
            info = regex.findall(versioninfo)
            record["info"] = info
        if "h/" in versioninfo:
            regex = re.compile(r"h/([^/]*)/")
            hostname = regex.findall(versioninfo)
            record["hostname"] = hostname
        if "o/" in versioninfo:
            regex = re.compile(r"o/([^/]*)/")
            operatingsystem = regex.findall(versioninfo)
            record["operatingsystem"] = operatingsystem
        if "d/" in versioninfo:
            regex = re.compile(r"d/([^/]*)/")
            devicetype = regex.findall(versioninfo)
            record["devicetype"] = devicetype
        if "cpe:/" in versioninfo:
            regex = re.compile(r"cpe:/a:([^/]*)/")
            cpename = regex.findall(versioninfo)
            record["cpename"] = cpename
        return record
    def filter_probes_by_port(self, port, probes):
        included = []
        excluded = []
        for probe in probes:
            if "ports" in probe:
                ports = probe['ports']['ports']
                if self.is_port_in_range(port, ports):included.append(probe)
                else:excluded.append(probe)
            elif "sslports" in probe:
                sslports = probe['sslports']['sslports']
                if self.is_port_in_range(port, sslports):included.append(probe)
                else: excluded.append(probe)
            else:excluded.append(probe)
        return included, excluded
    def is_port_in_range(self, port, nmap_port_rule):
        bret = False
        ports = nmap_port_rule.split(',')
        if str(port) in ports:
            bret = True
        else:
            for nmap_port in ports:
                if "-" in nmap_port:
                    s, e = nmap_port.split('-')
                    if int(port) in range(int(s), int(e)):
                        bret = True
        return bret
