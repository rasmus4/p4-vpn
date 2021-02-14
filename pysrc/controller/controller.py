from .p4runtime_lib import simple_controller
from .p4runtime_lib.bmv2 import Bmv2SwitchConnection
from .p4runtime_lib.helper import P4InfoHelper
import os
import sys

import threading
import logging
from grpc import RpcError, StatusCode

LOGGING_FORMAT = "%(asctime)s - %(name)s [%(levelname)s]: %(message)s"
DEFAULT_SWITCH_RUNTIME_PATH = "pysrc/controller/config/switch-runtime.json"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)

def macToString(mac):
    return ':'.join(mac[i:i+1].hex() for i in range(len(mac)))

def ipToString(ip):
    return '.'.join(str(i) for i in ip)

class Controller(threading.Thread):
    def __init__(
        self,
        device_id=0,
        address="127.0.0.1",
        port=50051,
        switch_runtime_path=None,
        switch_name=None
        ):
        self.device_id = device_id
        self.switch_name = switch_name
        self.initLogging()
        threading.Thread.__init__(self)
        full_grpc_address = address + ":" + str(port)
        self.logger.info("Connecting to '%s'", full_grpc_address)
        self.connection = Bmv2SwitchConnection(
            address=full_grpc_address,
            device_id=self.device_id
        )
        self.switch_runtime_path = switch_runtime_path if switch_runtime_path is not None else DEFAULT_SWITCH_RUNTIME_PATH
        self.connection.MasterArbitrationUpdate() # Make controller master, switch slave
        self.p4info_helper = P4InfoHelper("build/switch.p4.p4info.txt")

    def initLogging(self):
        loggingFormatter = logging.Formatter(fmt = LOGGING_FORMAT)
        self.logger = logging.getLogger("P4Controller-" + str(self.device_id))
        if self.switch_name is None:
            fh = logging.FileHandler("log/p4controller-devid" + str(self.device_id) + ".log")
        else:
            fh = logging.FileHandler("log/p4controller-" + self.switch_name + ".log")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(loggingFormatter)
        self.logger.addHandler(fh)

    def program(self):
        self.logger.critical("Programmming switch: '" + self.switch_runtime_path + "'")

        # Load P4 program
        bmv2_json_path = (self.switch_runtime_path)
        self.connection.SetForwardingPipelineConfig(
            p4info = self.p4info_helper.p4info,
            bmv2_json_file_path = bmv2_json_path
        )

        # Enable digests
        self.L2_DIGEST_ID = self.p4info_helper.get(entity_type="digests", name="L2_digest").preamble.id
        self.connection.WriteDigestEntry(self.L2_DIGEST_ID)

        # Load runtime config
        with open(self.switch_runtime_path, "r") as sw_conf_file:
            sw_conf = simple_controller.json_load_byteified(sw_conf_file)
            if 'table_entries' in sw_conf:
                table_entries = sw_conf['table_entries']
                self.logger.info("Inserting %d table entries...", len(table_entries))
                for entry in table_entries:
                    self.logger.info(simple_controller.tableEntryToString(entry))
                    simple_controller.insertTableEntry(self.connection, entry, self.p4info_helper)

            if 'multicast_group_entries' in sw_conf:
                group_entries = sw_conf['multicast_group_entries']
                self.logger.info("Inserting %d group entries...", len(group_entries))
                for entry in group_entries:
                    self.logger.info(simple_controller.groupEntryToString(entry))
                    simple_controller.insertMulticastGroupEntry(self.connection, entry, self.p4info_helper)

    def setupBroadcast(self, ports):
        # Magic number 1 is a multicast group id: MCAST_BROADCAST is defined as 0x01 in l2.p4
        mcast_entry = self.p4info_helper.buildMulticastGroupEntry(1, [{"egress_port": port, "instance": 1} for port in ports])
        self.connection.WritePREEntry(mcast_entry)

    def handleL2Digest(self, digest_data):
        macAddress = digest_data[0].struct.members[0].bitstring
        port = digest_data[0].struct.members[1].bitstring
        self.logger.debug("L2 digest: %s (port %s)", macToString(macAddress), int.from_bytes(port, byteorder="big"))

        table_entry_responses = self.connection.ReadTableEntries(
            table_id = self.p4info_helper.get_id("tables", "MyIngress.L2.smac")
        )

        smac_entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.L2.smac",
            match_fields = { "hdr.ethernet.srcAddr": macAddress , "standard_metadata.ingress_port": port },
            action_name = "NoAction"
        )

        dmac_entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.L2.dmac",
            match_fields = { "hdr.ethernet.dstAddr": macAddress },
            action_name = "MyIngress.L2.l2_forward",
            action_params = {
                "port": port
            }
        )

        for response in table_entry_responses:
            for entity in response.entities:
                entry = entity.table_entry
                if entry.match[0].exact.value == macAddress:
                    if entry.match[1].exact.value == port:
                        self.logger.debug("Identical entry already present, skipping update")
                    else:
                        self.logger.debug("New port for this MAC address, updating entry")
                        #self.connection.WriteTableEntry(smac_entry, update_entry=True)
                        smac_entry = self.p4info_helper.buildTableEntry(
                            table_name = "MyIngress.L2.smac",
                            match_fields = { "hdr.ethernet.srcAddr": macAddress , "standard_metadata.ingress_port": entry.match[1].exact.value },
                            action_name = "NoAction"
                        )
                        self.connection.WriteTableEntry(smac_entry, delete_entry=True)
                        self.connection.WriteTableEntry(dmac_entry, update_entry=True)
                    return

        self.connection.WriteTableEntry(smac_entry)
        self.connection.WriteTableEntry(dmac_entry)

    def run(self):
        try:
            self.logger.debug("run() entered")
            for item in self.connection.stream_msg_resp:
                if item.WhichOneof("update") == "digest" and item.digest.digest_id == self.L2_DIGEST_ID:
                        self.handleL2Digest(item.digest.data)
                else:
                    self.logger.debug("%s", item)
        except RpcError as e:
            try:
                if e.code() == StatusCode.CANCELLED:
                    self.logger.info("Controller stopped by application!")
                elif e.code() == StatusCode.UNAVAILABLE:
                    self.logger.info("Controller failed to reach switch!")
                else:
                    self.logger.warning("Controller failed, code: %s", str(e.code()))
            except AttributeError:
                self.logger.exception("Controller stopped, status code not available")

    def stop(self):
        self.connection.shutdown()