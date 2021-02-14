from mininet.node import Switch
from controller.controller import Controller
import tempfile
import logging
import re
from time import sleep

LOGGING_FORMAT = "%(asctime)s - %(name)s [%(levelname)s]: %(message)s"
logging.basicConfig(format = LOGGING_FORMAT)
logger = logging.getLogger("P4Switch")
logger.setLevel(logging.DEBUG)

CPU_PORT = 16
GRPC_PORT_START = 50051
THRIFT_PORT_START = 9090
GRPC_ADDRESS = "127.0.0.1"

class P4Switch(Switch):
    def __init__(self, name, device_id, **kwargs):
        Switch.__init__(self, name, **kwargs)
        self.device_id = device_id
        self.grpc_listen_port = GRPC_PORT_START + self.device_id
        self.thrift_listen_port = THRIFT_PORT_START + self.device_id
        self.runtime_path = None

    def setRuntimePath(self, runtime_path):
        self.runtime_path = runtime_path

    def start(self, controllers):
        bmv2_options = ""
        simple_switch_options = ""
        ports = []
        for port, interface in self.intfs.items():
            if interface.name != "lo":
                bmv2_options += "-i {port}@{dev} ".format(port = port, dev = interface)
                #logger.debug("%s (P4Switch-%d): %s", self.name, self.device_id, "-i {port}@{dev} ".format(port = port, dev = interface))
                ports.append(port)

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
        logger.info("%s (P4Switch-%d) started, gRPC listening on :%d", self.name, self.device_id, self.grpc_listen_port)

        exitcode = 1
        while exitcode != 0:
            _, _, exitcode = self.pexec("nc -zv 127.0.0.1 " + str(self.grpc_listen_port))

        self.controller = Controller(
            device_id = self.device_id,
            address = "127.0.0.1",
            port = self.grpc_listen_port,
            switch_name = self.name,
            switch_runtime_path=self.runtime_path
        )
        self.controller.program()
        self.controller.setupBroadcast(ports)
        self.controller.start()

    def stop(self, deleteIntfs = True):
        try:
            self.controller.stop()
        except AttributeError:
            logger.warning("%s (P4Switch-%d) has no controller, skipping controller.stop() call", self.name, self.device_id)

        self.cmd("kill {pid}".format(pid = self.switch_pid))
        self.cmd("wait {pid}".format(pid = self.switch_pid))
        if deleteIntfs:
            self.deleteIntfs()
        logger.info("%s (P4Switch-%d) killed", self.name, self.device_id)