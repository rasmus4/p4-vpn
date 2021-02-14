#!venv3.8/bin/python

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.link import Intf
from p4_study_cli import StudyCLI
from mininet.node import OVSSwitch, OVSBridge

from nodes.p4switch import P4Switch
from nodes.router import LinuxRouter
from nodes.tunnel import L2TPTunnel, VXLANTunnel
from nodes.p4nve import P4NVE
from nodes.ovs import OVS

import subprocess
import sys
import json
import logging
import time

LOGGING_FORMAT = "%(asctime)s - %(name)s [%(levelname)s]: %(message)s"
logging.basicConfig(format = LOGGING_FORMAT, filename="log/rootlogger.log")
logger = logging.getLogger("Network Controller")
logger.setLevel(logging.DEBUG)

def raiseOnError(result):
    if result != 0:
        raise Exception("Result != 0")


class SwitchStub():
    def __init__(self, name):
        self.name = name


class Network():
    def __init__(self, topology_path, vns_path):
        self.links = []
        self.hosts = {}
        self.switches = {}
        self.mininet = Mininet()
        self.loadTopology(topology_path)
        self.loadVns(vns_path)
        self.createHosts(self.topology["hosts"])
        self.createSwitches(self.topology["switches"])
        self.createRouters(self.topology["routers"])
        self.createTunnels(self.topology["tunnels"])
        self.connectLinks(self.topology["links"], self.hosts, self.switches)
        self.disable_ipv6()
        logger.info("Network is ready!")


    def lateConfiguration(self):
        self.configureRouters(self.topology["routers"])
        self.configureTunnels(self.topology["tunnels"])
        self.runLateHostCommands(self.topology["hosts"])
        self.runLateHostCommands(self.topology["tunnels"])
        self.runLateHostCommands(self.topology["routers"])
        logger.info("Late configuration finished!")

    def start(self):
        self.mininet.start()
        self.lateConfiguration()


    def close(self):
        self.mininet.stop()


    def disable_ipv6(self):
        # Disable spammy IPv6 packets.
        for node in self.mininet.hosts:
            for interface in node.intfs.values():
                node.cmd("sysctl net.ipv6.conf.{dev}.disable_ipv6=1".format(dev = interface.name))
        for node in self.mininet.switches:
            for interface in node.intfs.values():
                node.cmd("sysctl net.ipv6.conf.{dev}.disable_ipv6=1".format(dev = interface.name))
        logger.info("IPv6 disabled for all nodes")


    def loadTopology(self, topology_path):
        with open(topology_path, "r") as topology_file:
            topology = topology_file.read()
        self.topology = json.loads(topology)
        logger.info("Topology loaded")


    def loadVns(self, vns_path):
        self.mininet.vns = None
        if vns_path is None:
            return
        with open(vns_path, "r") as topology_file:
            topology = topology_file.read()
        self.mininet.vns = json.loads(topology)
        logger.info("Topology loaded")


    def connectLinks(self, links, hosts, switches):
        for link in links:
            nodes = [None, None]
            ports = [None, None]
            for index, end in enumerate(link):
                if "-p" in end:
                    nodes[index], ports[index] = end.split("-p")
                    ports[index] = int(ports[index])
                else:
                    nodes[index] = end
            assert(nodes[0] != None and nodes[1] != None)
            try:
                self.mininet.addLink(
                    node1 = nodes[0],
                    node2 = nodes[1],
                    port1 = ports[0],
                    port2 = ports[1]
                )
            except:
                logger.exception(
                    "Failed to add link '%s':'%s' <=> '%s':'%s'",
                    nodes[0],
                    ports[0],
                    nodes[1],
                    ports[1]
                )
                assert(0)

        logger.info("%d links connected", len(links))


    def createHosts(self, hosts):
        for host in hosts.keys():
            self.createHost(host, hosts[host])
        logger.info("%d hosts created", len(hosts))


    def createHost(self, hostName, params):
        host = self.mininet.addHost(
            hostName,
            ip=params["ip"] if "ip" in params else None,
            mac=params["mac"] if "mac" in params else None
        )
        if "commands" in params:
            for command in params["commands"]:
                host.sendCmd(command)
                host.waitOutput()
        self.hosts[hostName] = host


    def createSwitches(self, switches):
        for index, switch in enumerate(switches):
            if "type" in switches[switch]:
                if switches[switch]["type"] == "p4":
                    _switch = self.mininet.addSwitch(
                        switch,
                        cls=P4Switch,
                        device_id=index
                    )
                    if "runtime_json" in switches[switch]:
                        _switch.setRuntimePath(switches[switch]["runtime_json"])
                elif switches[switch]["type"] == "ovs":
                    _switch = self.mininet.addSwitch(
                        switch,
                        cls=OVS,
                        device_id=index
                        #failMode="standalone"
                    )
                elif switches[switch]["type"] == "bridge":
                    _switch = self.mininet.addSwitch(
                        switch,
                        cls=OVSBridge,
                        device_id=index
                    )

            self.switches[switch] = _switch
        logger.info("%d switches created", len(switches))


    def createRouters(self, routers):
        for routerName in routers:
            self.mininet.addHost(
                routerName,
                cls=LinuxRouter
            )
        logger.info("%d routers created", len(routers))


    def createTunnels(self, tunnels):
        for index, (tunnelName, tunnelOptions) in enumerate(tunnels.items()):
            if tunnelOptions["type"] == "p4nve":
                _tunnel = self.mininet.addSwitch(
                    tunnelName,
                    device_id=index,
                    cls=P4NVE,
                    tunnelArgs=tunnelOptions
                )
                _tunnel.setRuntimePath(tunnelOptions["runtime_json"])
                _tunnel.setBGPAddress(tunnelOptions["bgp_address"])
                _tunnel.setBGPPort(tunnelOptions["bgp_port"])
                _tunnel.setRemoteBGPPeers(tunnelOptions["bgp_peers"])
                _tunnel.setBGPHopAddress(tunnelOptions["bgp_hop_address"])

                remoteVNIMappings = {}
                for index2, (_, tunnelOptions2) in enumerate(tunnels.items()):
                    if index == index2:
                        continue
                    for vni in tunnelOptions2["vni_list"]:
                        if tunnelOptions2["bgp_hop_address"] not in remoteVNIMappings:
                            remoteVNIMappings[tunnelOptions2["bgp_hop_address"]] = [vni]
                        else:
                            remoteVNIMappings[tunnelOptions2["bgp_hop_address"]].append(vni)
                _tunnel.setRemoteVNIMappings(remoteVNIMappings)
                #logger.debug("bgpaddress: '%s', peer[0]: '%s'", tunnelOptions["bgp_address"], tunnelOptions["bgp_peers"][0])
                mappings = []
                for nveConfig in tunnelOptions["nve_config"]:
                    vni = nveConfig["vni"]
                    for port in nveConfig["bridge_ports"]:
                        mappings.append((vni, port[1:]))
                _tunnel.addVNIMappings(mappings)
                self.switches[tunnelName] = _tunnel
            elif tunnelOptions["type"] == "p4bridge":
                _switch = self.mininet.addSwitch(
                    tunnelName,
                    cls=P4Switch,
                    device_id=index
                )
                if "runtime_json" in tunnelOptions:
                    _switch.setRuntimePath(tunnelOptions["runtime_json"])
            else:
                if tunnelOptions["type"] == "bridge":
                    self.mininet.addSwitch(
                        tunnelName,
                        cls=OVSBridge,
                        device_id=index
                    )
                else:
                    if tunnelOptions["type"] == "l2tp":
                        tunnelcls = L2TPTunnel
                    elif tunnelOptions["type"] == "vxlan":
                        tunnelcls = VXLANTunnel

                    self.mininet.addHost(
                        tunnelName,
                        device_id=index,
                        cls=tunnelcls,
                        tunnelArgs=tunnelOptions
                    )
        logger.info("%d tunnel endpoints created", len(tunnels))


    def runLateHostCommands(self, hosts):
        cmdCount = 0
        hostlist = ""
        for hostName, options in hosts.items():
            hostlist += hostName + ", "
            h = self.mininet.nameToNode[hostName]
            if "late_commands" in options:
                for lateCommand in options["late_commands"]:
                    cmdCount += 1
                    h.sendCmd(lateCommand)
                    res = h.waitOutput()
                    if res:
                        logger.warning(
                            "Command '%s' in host '%s' yielded the following output: '%s'",
                            lateCommand,
                            hostName,
                            res
                        )
        logger.info("%d late commands run on hosts %s", cmdCount, hostlist.rstrip(", "))


    def configureRouters(self, routers):
        configCount = 0
        for routerName, options in routers.items():
            try:
                for interface_config in options["interface_configs"]:
                    configCount += 1
                    r = self.mininet.nameToNode[routerName]
                    port = int(interface_config["port"].strip("p"))
                    interface = r.intfs[port].name
                    ip, prefixLen = interface_config["ip"].split("/")
                    mac = interface_config["mac"]
                    cmdsToRun = []
                    if interface_config["nat"] == True:
                        cmdsToRun.append("iptables -t nat -A POSTROUTING -o {dev} -j MASQUERADE".format(
                            dev=interface
                        ))
                    r.setIP(ip, int(prefixLen), interface)
                    r.setMAC(mac, interface)
                    for cmdToRun in cmdsToRun:
                        r.sendCmd(cmdToRun)
                        res = r.waitOutput()
                        if res:
                            logger.warning(
                                "Command '%s' in router '%s' yielded the following output: '%s'",
                                cmdToRun,
                                routerName,
                                res
                            )
            except:
                logger.exception("Failed to configure router '%s'", routerName)
        logger.info("%d routers configured", configCount)


    def configureTunnels(self, tunnels):
        configCount = 0
        for tunnelName, options in tunnels.items():
            configCount += 1
            if "interface_configs" in options:
                for interface_config in options["interface_configs"]:
                    r = self.mininet.nameToNode[tunnelName]
                    port = int(interface_config["port"].strip("p"))
                    interface = r.intfs[port].name
                    ip, prefixLen = interface_config["ip"].split("/")
                    r.setIP(
                        ip,
                        int(prefixLen),
                        interface
                    )
                self.mininet.nameToNode[tunnelName].lateConfig()
        for _, switch in self.switches.items():
            if isinstance(switch, P4NVE):
                switch.controller.initBGP()

        waitForBGPToEstablish = True
        while waitForBGPToEstablish:
            waitForBGPToEstablish = False
            for _, switch in self.switches.items():
                if isinstance(switch, P4NVE) and hasattr(switch.controller, "bgpspeaker"):
                    if not switch.controller.bgpspeaker.connection_thread.ready:
                        waitForBGPToEstablish = True
                        break
            if waitForBGPToEstablish:
                logger.info("Waiting for BGP connections to be established")
                time.sleep(0.2)

        logger.info("%d tunnel endpoints configured", configCount)


if __name__ == '__main__':
    net = Network(
       "topos/gentopo/topology.json",
       "topos/gentopo/vns.json"
    )
    # net = Network(
    #    "topos/2switches/topology.json",
    #    "topos/gentopo/vns.json"
    # )
    normalExit = True
    try:
        net.start()
        if len(sys.argv) > 2:
            s = StudyCLI(
                net.mininet,
                testResultsFolder=sys.argv[1],
                nameOfTestRun=sys.argv[2],
                running=False if "runtests" in sys.argv else True
            )
            if "runtests" in sys.argv:
                s.do_testvns("")
                #s.do_testiperf("")
                #s.do_testiperfsinglepair("")
                s.do_exit("")
        else:
            StudyCLI(net.mininet)
    except:
        logger.exception("Exception caught at top level")
        normalExit = False
    finally:
        net.close()
    if not normalExit:
        sys.exit(1)