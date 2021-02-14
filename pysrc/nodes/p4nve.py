from mininet.node import Switch
from nve_controller.controller import Controller
import tempfile
import logging
import re
from time import sleep

LOGGING_FORMAT = "%(asctime)s - %(name)s [%(levelname)s]: %(message)s"
logging.basicConfig(format = LOGGING_FORMAT)
logger = logging.getLogger("P4NVE")
logger.setLevel(logging.DEBUG)

CPU_PORT = 16
GRPC_PORT_START = 50051
THRIFT_PORT_START = 9090
GRPC_ADDRESS = "127.0.0.1"

class P4NVE(Switch):
    def __init__(self, name, device_id, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.device_id = device_id
        self.grpc_listen_port = GRPC_PORT_START + self.device_id
        self.thrift_listen_port = THRIFT_PORT_START + self.device_id
        self.runtime_path = None
        self.controlIntf = False

    def lateConfig(self):
        pass

    def setRuntimePath(self, runtime_path):
        self.runtime_path = runtime_path
    
    def addVNIMappings(self, mappings):
        self.mappings = mappings

    def setBGPAddress(self, address):
        self.bgp_address = address

    def setBGPPort(self, port):
        self.bgp_port = port

    def setRemoteBGPPeers(self, peers):
        self.bgp_remote_peers = peers
    
    def setBGPHopAddress(self, hopaddr):
        self.bgp_hop_address = hopaddr

    def setRemoteVNIMappings(self, remoteVNIMappings):
        self.remoteVNIMappings = remoteVNIMappings

    def start(self, controllers):
        bmv2_options = ""
        simple_switch_options = ""
        for port, interface in self.intfs.items():
            if interface.name != "lo":
                #self.cmd("ip link set dev {dev} mtu 1600".format(dev=interface))
                bmv2_options += "-i {port}@{dev} ".format(port = port, dev = interface)
                #logger.debug("%s (P4Switch-%d): %s", self.name, self.device_id, "-i {port}@{dev} ".format(port = port, dev = interface))

        bmv2_options += "--pcap pcaps "
        bmv2_options += "--device-id {device_id} ".format(device_id = self.device_id)
        bmv2_options += "--log-console "
        bmv2_options += "--thrift-port {thrift_port} ".format(thrift_port=self.thrift_listen_port)
        simple_switch_options += "--cpu-port {cpu_port} ".format(cpu_port = CPU_PORT)
        simple_switch_options += "--grpc-server-addr 0.0.0.0:{grpc_listen_port} ".format(grpc_listen_port = self.grpc_listen_port)

        with tempfile.NamedTemporaryFile() as pidfile:
            cmdToRun = "simple_switch_grpc {bmv2_options} build/switch.json -- {simple_switch_options} > {logfile} & echo $! > {pidfile}".format(
                bmv2_options=bmv2_options,
                simple_switch_options = simple_switch_options,
                logfile="log/{name}-p4switch-{id}.log".format(name = self.name, id = self.device_id),
                pidfile=pidfile.name
            )
            res = self.cmd(cmdToRun)
            pidline = pidfile.readline().decode().strip("\n")
            if pidline.isdigit():
                self.switch_pid = int(pidline)
            else:
                raise Exception("Unexpected line in pidfile for {name} (P4Switch-{device_id}): '{pidline}' \
                    \nCommand: {command} \
                    \nOutput: {output}".format(
                    name = self.name,
                    device_id = self.device_id,
                    pidline = pidline,
                    command = cmdToRun,
                    output = res
                ))

        m = re.search(r"\[\d\] \d+(.*)", res.rstrip("\r\n"))
        if len(m.groups()[0]) > 0:
            logger.warning(
                "Command '%s' in switch '%s' yielded the following output: '%s'",
                cmdToRun,
                self.name,
                res
            )
        logger.info("%s (P4NVE-%d) started, gRPC listening on :%d", self.name, self.device_id, self.grpc_listen_port)

        # Wait for switch to accept gRPC connection
        exitcode = 1
        while exitcode != 0:
            _, _, exitcode = self.pexec("nc -zv 127.0.0.1 " + str(self.grpc_listen_port))

        self.controller = Controller(
            device_id = self.device_id,
            address = "127.0.0.1",
            port = self.grpc_listen_port,
            switch_name = self.name,
            switch_runtime_path = self.runtime_path,
            bgp_address = self.bgp_address,
            bgp_port = self.bgp_port,
            bgp_nexthop = self.bgp_hop_address,
            remote_bgp_peers = self.bgp_remote_peers
        )
        self.controller.program()
        self.controller.addVNIMappings(self.mappings)

        lastNexthop = {}
        for nextHop, vniList in self.remoteVNIMappings.items():
            for vni in vniList:
                if vni not in lastNexthop:
                    self.controller.handleNewVNINextHopMapping(vni, nextHop, None)
                    lastNexthop[vni] = nextHop
                else:
                    self.controller.handleNewVNINextHopMapping(vni, nextHop, lastNexthop[vni])
                    lastNexthop[vni] = nextHop
        self.controller.start()

    def stop(self, deleteIntfs = True):
        try:
            self.controller.stop()
        except AttributeError:
            logger.warning("%s (P4NVE-%d) has no controller, skipping controller.stop() call", self.name, self.device_id)

        self.cmd("kill {pid}".format(pid = self.switch_pid))
        self.cmd("wait {pid}".format(pid = self.switch_pid))
        if deleteIntfs:
            self.deleteIntfs()
        logger.info("%s (P4NVE-%d) killed", self.name, self.device_id)