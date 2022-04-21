import nmap
ipValueRange=input("IP Giriniz ")
print(ipValueRange)
print("Lütfen Bekleyiniz")
nm = nmap.PortScanner()
def scanhosts():
    scan_range = nm.scan(hosts=ipValueRange)
    print(scan_range['scan'])
    return ()

def scanhosts_nicer_output():
    scan_range = nm.scan(hosts=ipValueRange)
    nm.all_hosts()
    for host in nm.all_hosts():
        print("Host: %s(%s)" % (host, nm[host].hostname()))

        print("Open TCP Ports: ")

        print("%s" % (nm[host].all_tcp()))

    return ()
scanhosts_nicer_output()

breakpoint()