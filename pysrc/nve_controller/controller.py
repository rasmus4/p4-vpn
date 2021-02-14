from .p4runtime_lib import simple_controller
from .p4runtime_lib.bmv2 import Bmv2SwitchConnection
from .p4runtime_lib.helper import P4InfoHelper
from .p4runtime_lib.convert import decodeIPv4, decodeMac, encodeIPv4, encodeMac, encodeNum
from .bgpspeaker import Tables, BGPSpeaker
import os
import sys

import threading
import logging
from grpc import RpcError, StatusCode

LOGGING_FORMAT = "%(asctime)s - %(name)s [%(levelname)s]: %(message)s"
DEFAULT_SWITCH_RUNTIME_PATH = "pysrc/nve_controller/config/switch-runtime.json"
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
REMOTE_PORT = 1
ASN = 64512
DP_LEARNING = False
ARP_PROXY = True

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
        switch_name=None,
        bgp_address="127.0.0.1",
        bgp_nexthop=None,
        bgp_port=179,
        remote_bgp_peers=[]
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
        self.bgp_address = bgp_address
        self.bgp_nexthop = bgp_address if bgp_nexthop is None else bgp_nexthop
        self.bgp_port = bgp_port
        self.bgp_remote_peers = remote_bgp_peers
        self.p4rlock = threading.Lock()

    def initBGP(self):
        if DP_LEARNING:
            return

        self.tables = Tables(name=self.switch_name)
        self.bgpspeaker = BGPSpeaker(
            listen_addr=self.bgp_address,
            port=self.bgp_port,
            asn=ASN,
            tables=self.tables,
            peers=self.bgp_remote_peers,
            name=self.switch_name,
            nexthop=self.bgp_nexthop
        )
        self.bgpspeaker.start()
        #for remote_bgp_peer in self.bgp_remote_peers:
        #    self.logger.info("'%s' attempting to connect to '%s'", self.bgp_address, remote_bgp_peer["address"])
        #    self.bgpspeaker.connect(remote_bgp_peer["address"], remote_bgp_peer["port"])
        self.tables.addMACIPCallback(self.handleRemoteEntry)
        self.tables.addRemoteVNICallback(self.handleNewVNINextHopMapping)

    def initLogging(self):
        loggingFormatter = logging.Formatter(fmt = LOGGING_FORMAT)
        self.logger = logging.getLogger("P4Controller-" + str(self.device_id))
        if self.switch_name is None:
            fh = logging.FileHandler("log/p4nvecontroller-devid" + str(self.device_id) + ".log")
        else:
            fh = logging.FileHandler("log/p4nvecontroller-" + self.switch_name + ".log")
        fh.setLevel(logging.DEBUG)
        self.logger.setLevel(logging.INFO)
        fh.setFormatter(loggingFormatter)
        self.logger.addHandler(fh)

    def program(self):
        self.logger.info("Programmming switch")

        # Load P4 program
        bmv2_json_path = ("build/switch.json")
        self.connection.SetForwardingPipelineConfig(
            p4info = self.p4info_helper.p4info,
            bmv2_json_file_path = bmv2_json_path
        )

        # Enable digests
        if DP_LEARNING:
            self.geneve_digest_t = self.p4info_helper.get(entity_type="digests", name="geneve_digest_t").preamble.id
            self.connection.WriteDigestEntry(self.geneve_digest_t)

        if ARP_PROXY:
            self.arp_digest_t = self.p4info_helper.get(entity_type="digests", name="arp_digest_t").preamble.id
            self.connection.WriteDigestEntry(self.arp_digest_t, max_list_size=1, max_timeout_ns=10)

        self.local_digest_t = self.p4info_helper.get(entity_type="digests", name="local_digest_t").preamble.id
        self.connection.WriteDigestEntry(self.local_digest_t, max_list_size=1, max_timeout_ns=10)

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

        self.addNVEBroadcastMapping(240, self.bgp_nexthop)

    def getVNIMappings(self):
        with self.p4rlock:
            table_entry_responses = self.connection.ReadTableEntries(
                table_id = self.p4info_helper.get_id("tables", "MyIngress.Geneve.ingress_port_to_vni")
            )
        res = "{:>3} | {:>4} | {:>9}\n".format("#", "Port", "VNI/EVI")
        res += "{:=>22}\n".format("")
        i = 1
        for response in table_entry_responses:
            for entity in response.entities:
                entry = entity.table_entry
                res += "{:>3} | {:>4} | {:>9}\n".format(
                    i,
                    int.from_bytes(entry.match[0].exact.value, byteorder="big"),
                    int.from_bytes(entry.action.action.params[0].value, byteorder="big")
                )
                i = 1
        return res

    def getARPProxyMappings(self):
        if not ARP_PROXY:
            return "ARP Proxy disabled!"

        with self.p4rlock:
            table_entry_responses = self.connection.ReadTableEntries(
                table_id = self.p4info_helper.get_id("tables", "MyIngress.Geneve.arp_proxy")
            )
        res = "{:>3} | {:>9} | {:>15} | {:>17}\n".format("#", "VNI/EVI", "IPv4", "MAC")
        res += "{:=>53}\n".format("")
        i = 1
        for response in table_entry_responses:
            for entity in response.entities:
                entry = entity.table_entry
                res += "{:>3} | {:>9} | {:>15} | {:>17}\n".format(
                    i,
                    int.from_bytes(entry.match[0].exact.value, byteorder="big"),
                    decodeIPv4(entry.match[1].exact.value),
                    decodeMac(entry.action.action.params[0].value)
                )
                i += 1
        return res

    def getDmacVNI(self):
        with self.p4rlock:
            table_entry_responses = self.connection.ReadTableEntries(
                table_id = self.p4info_helper.get_id("tables", "MyIngress.Geneve.ingress_dmac_vni")
            )
        res = "{:>3} | {:>9} | {:>17} | {:>4}\n".format("#", "VNI/EVI", "MAC", "Mask")
        res += "{:=>42}\n".format("")
        i = 1
        for response in table_entry_responses:
            for entity in response.entities:
                entry = entity.table_entry
                res += "{:>3} | {:>9} | {:>17} | {:>4}\n".format(
                    i,
                    int.from_bytes(entry.match[0].exact.value, byteorder="big"),
                    decodeMac(entry.match[1].lpm.value) if len(entry.match) >= 2 else "N/A",
                    entry.match[1].lpm.prefix_len if len(entry.match) >= 2 else "0"
                )
                #self.logger.critical("\n%s", entry.match[1].lpm.value)
                i += 1
        return res

    def getVNINextHopMappings(self):
        with self.p4rlock:
            table_entry_responses = self.connection.ReadTableEntries(
                table_id = self.p4info_helper.get_id("tables", "MyEgress.Geneve.remote_nexthop")
            )
        res = "{:>3} | {:>9} | {:>15} | {:>15}\n".format("#", "VNI/EVI", "cur", "next")
        res += "{:=>52}\n".format("")
        i = 1
        for response in table_entry_responses:
            for entity in response.entities:
                entry = entity.table_entry
                res += "{:>3} | {:>9} | {:>15} | {:>15}\n".format(
                    i,
                    int.from_bytes(entry.match[0].exact.value, byteorder="big"),
                    decodeIPv4(entry.match[1].exact.value),
                    decodeIPv4(entry.action.action.params[0].value)
                )
                i += 1
        return res


    def addNVEBroadcastMapping(self, port, srcAddr):
        with self.p4rlock:
            nve_broadcast_entry = self.p4info_helper.buildTableEntry(
                    table_name = "MyEgress.Geneve.nve_broadcast",
                    match_fields = { "standard_metadata.egress_port": int(port) },
                    action_name = "MyEgress.Geneve.remote_broadcast",
                    action_params = { "srcAddr": srcAddr }
                )
            self.connection.WriteTableEntry(nve_broadcast_entry)

    def addVNIMappings(self, mappings):
        with self.p4rlock:
            mappingsDict = {}
            for vni, port in mappings:
                if vni not in mappingsDict:
                    mappingsDict[int(vni)] = [ { "egress_port": int(port), "instance": int(vni) } ]
                else:
                    mappingsDict[int(vni)].append({ "egress_port": int(port), "instance": int(vni) })
                # ingress_port_to_vni
                ingress_port_to_vni_entry = self.p4info_helper.buildTableEntry(
                    table_name = "MyIngress.Geneve.ingress_port_to_vni",
                    match_fields = { "standard_metadata.ingress_port": int(port) },
                    action_name = "MyIngress.Geneve.set_ingress_vni",
                    action_params = { "vni": int(vni) }
                )
                self.connection.WriteTableEntry(ingress_port_to_vni_entry)

            for vni, ports in mappingsDict.items():
                # ingress_dmac_vni
                ingress_dmac_vni_entry = self.p4info_helper.buildTableEntry(
                    table_name = "MyIngress.Geneve.ingress_dmac_vni",
                    match_fields = { "meta.vni": int(vni), "hdr.ethernet.dstAddr": ("ff:ff:ff:ff:ff:ff", 48) },
                    action_name = "MyIngress.Geneve.broadcast"
                )
                self.connection.WriteTableEntry(ingress_dmac_vni_entry)

                # egress_dmac_vni
                egress_dmac_vni_entry = self.p4info_helper.buildTableEntry(
                    table_name = "MyIngress.Geneve.egress_dmac_vni",
                    match_fields = { "hdr.geneve.vni": int(vni), "hdr.inner_ethernet.dstAddr": "ff:ff:ff:ff:ff:ff" },
                    action_name = "MyIngress.Geneve.broadcast"
                )
                self.connection.WriteTableEntry(egress_dmac_vni_entry)

                mcast_entry = self.p4info_helper.buildMulticastGroupEntry(vni+1, ports + [{"egress_port": 240, "instance": 240}])
                # self.logger.info("mcast_entry (%s, %s)", vni+1, ports)
                self.connection.WritePREEntry(mcast_entry)

    def handleRemoteEntry(self, MAC, instance, next_hop, ipAddr=None):
        #self.logger.info("handleRemoteEntry(%s, %d)", MAC, instance)
        with self.p4rlock:
            #self.logger.debug("handleRemoteEntry(%s, %d) rattled that lock", MAC, instance)

            # Handle ARP proxy entry first, as entry may already be installed in ingress_dmac_vni
            if ipAddr is not None:
                self._handleARPEntry(
                    encodeNum(instance, 24),
                    encodeMac(MAC),
                    encodeIPv4(ipAddr)
                )

            table_entry_responses = self.connection.ReadTableEntries(
                table_id = self.p4info_helper.get_id("tables", "MyIngress.Geneve.ingress_dmac_vni")
            )
            for response in table_entry_responses:
                for entity in response.entities:
                    entry = entity.table_entry
                    if int.from_bytes(entry.match[0].exact.value, byteorder="big") == instance:
                        if len(entry.match) >= 2:
                            if macToString(entry.match[1].lpm.value) == MAC and entry.match[1].lpm.prefix_len == 48:
                                self.logger.debug("(ingress_dmac_vni) Identical entry already present, skipping update")
                                return

            ingress_dmac_entry = self.p4info_helper.buildTableEntry(
                table_name = "MyIngress.Geneve.ingress_dmac_vni",
                match_fields = { "meta.vni": instance, "hdr.ethernet.dstAddr": (MAC, 48) },
                action_name = "MyIngress.Geneve.remote_forward",
                action_params = {
                    "srcAddr": self.bgp_address,
                    "dstAddr": next_hop,
                }
            )
            self.connection.WriteTableEntry(ingress_dmac_entry)

    def handleNewVNINextHopMapping(self, instance, nextHop, lastNextHop):
        with self.p4rlock:
            remote_nexthop_entry = self.p4info_helper.buildTableEntry(
                table_name = "MyEgress.Geneve.remote_nexthop",
                match_fields = { "hdr.geneve.vni": instance, "hdr.ipv4.dstAddr": lastNextHop if lastNextHop is not None else "0.0.0.0" },
                action_name = "MyEgress.Geneve.remote_forward",
                action_params = { "dstAddr": nextHop }
            )
            self.connection.WriteTableEntry(remote_nexthop_entry)
            # if lastNextHop is None:
            #     ingress_dmac_entry = self.p4info_helper.buildTableEntry(
            #         table_name = "MyIngress.Geneve.ingress_dmac_vni",
            #         match_fields = { "meta.vni": instance },
            #         action_name = "MyIngress.Geneve.remote_broadcast",
            #         action_params = { "srcAddr": self.bgp_address }
            #     )
            #     self.connection.WriteTableEntry(ingress_dmac_entry)

    def handleLocalDigest(self, digest_data):
        #self.logger.critical("digest (Local) len: %d", len(digest_data))
        for _dd in digest_data:
            vni = _dd.struct.members[0].bitstring
            macAddress = _dd.struct.members[1].bitstring
            port = _dd.struct.members[2].bitstring

            # Only pass this digest to BGP peers if DP_LEARNING is False
            if DP_LEARNING or self._passLocalMACIPtoPeers(
                    int.from_bytes(vni, byteorder="big"),
                    macToString(macAddress)
                ):
                with self.p4rlock:
                    self._handleLocalDigest(vni, macAddress, port)


    def handleARPDigest(self, digest_data):
        #self.logger.critical("digest (ARP) len: %d", len(digest_data))
        for _dd in digest_data:
            vni = _dd.struct.members[0].bitstring
            macAddress = _dd.struct.members[1].bitstring
            port = _dd.struct.members[2].bitstring
            ipAddress = _dd.struct.members[3].bitstring
            self.logger.debug("ARP digest: %s <=> %s", macToString(macAddress), ipToString(ipAddress))

            # Only pass this digest to BGP peers if DP_LEARNING is False
            if DP_LEARNING or self._passLocalMACIPtoPeers(
                    int.from_bytes(vni, byteorder="big"),
                    macToString(macAddress),
                    ipAddress=ipToString(ipAddress)
                ):
                with self.p4rlock:
                    self._handleARPEntry(vni, macAddress, ipAddress)
                    self._handleLocalDigest(vni, macAddress, port)

    def handleGeneveDigest(self, digest_data):
        for _dd in digest_data:
            vni = _dd.struct.members[0].bitstring
            macAddress = _dd.struct.members[1].bitstring
            ipAddress = _dd.struct.members[2].bitstring
            self.handleRemoteEntry(
                macToString(macAddress),
                int.from_bytes(vni, byteorder="big"),
                ipToString(ipAddress)
            )


    def _handleLocalDigest(self, vni, macAddress, port):
        #self.logger.info("Local digest: %s (VNI %d)", macToString(macAddress), int.from_bytes(vni, byteorder="big"))

        table_entry_responses = self.connection.ReadTableEntries(
            table_id = self.p4info_helper.get_id("tables", "MyIngress.Geneve.ingress_smac_vni")
        )

        ingress_smac_entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.Geneve.ingress_smac_vni",
            match_fields = { "meta.vni": vni, "hdr.ethernet.srcAddr": macAddress, "standard_metadata.ingress_port": port },
            action_name = "NoAction"
        )

        ingress_dmac_entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.Geneve.ingress_dmac_vni",
            match_fields = { "meta.vni": vni, "hdr.ethernet.dstAddr": (macAddress, 48) },
            action_name = "MyIngress.Geneve.local_forward",
            action_params = {
                "port": port
            }
        )

        egress_dmac_entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.Geneve.egress_dmac_vni",
            match_fields = { "hdr.geneve.vni": vni, "hdr.inner_ethernet.dstAddr": macAddress },
            action_name = "MyIngress.Geneve.local_forward",
            action_params = {
                "port": port
            }
        )

        for response in table_entry_responses:
            for entity in response.entities:
                entry = entity.table_entry
                if entry.match[0].exact.value == vni:
                    if entry.match[1].exact.value == macAddress:
                        if entry.match[2].exact.value == port:
                            self.logger.debug("Identical entry already present, skipping update")
                        else:
                            self.logger.warning(
                                "New port for MAC address '%s' (VNI %d) updating entry: old port '%d' -> new port '%d'",
                                macToString(macAddress),
                                int.from_bytes(vni, byteorder="big"),
                                int.from_bytes(port, byteorder="big"),
                                int.from_bytes(entry.match[2].exact.value, byteorder="big")
                            )
                            self.connection.WriteTableEntry(ingress_smac_entry)

                            # Re-enable local_digest for previous port
                            prev_ingress_smac_entry = self.p4info_helper.buildTableEntry(
                                table_name = "MyIngress.Geneve.ingress_smac_vni",
                                match_fields = { "meta.vni": vni, "hdr.ethernet.srcAddr": macAddress, "standard_metadata.ingress_port": entry.match[2].exact.value },
                                action_name = "NoAction"
                            )
                            self.connection.WriteTableEntry(prev_ingress_smac_entry, delete_entry=True)
                            self.connection.WriteTableEntry(ingress_dmac_entry, update_entry=True)
                            self.connection.WriteTableEntry(egress_dmac_entry, update_entry=True)
                        return

        self.connection.WriteTableEntry(ingress_smac_entry)
        self.connection.WriteTableEntry(ingress_dmac_entry)
        self.connection.WriteTableEntry(egress_dmac_entry)


    def _handleARPEntry(self, vni, macAddress, ipAddress):
        if not ARP_PROXY:
            return

        #self.logger.debug("_handleARPEntry: %s (VNI %d)", macToString(macAddress), int.from_bytes(vni, byteorder="big"))
        table_entry_responses = self.connection.ReadTableEntries(
            table_id = self.p4info_helper.get_id("tables", "MyIngress.Geneve.arp_smac_sip")
        )

        for response in table_entry_responses:
            for entity in response.entities:
                entry = entity.table_entry
                if entry.match[0].exact.value == vni:
                    if entry.match[1].exact.value == macAddress:
                        if entry.match[2].exact.value == ipAddress:
                            self.logger.debug("(_handleARPEntry) Identical entry already present, skipping update")
                            return

        arp_smac_sip_entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.Geneve.arp_smac_sip",
            match_fields = { "meta.vni": vni, "hdr.arp.senderHwAddr": macAddress, "hdr.arp.senderIPAddr": ipAddress },
            action_name = "NoAction"
        )

        arp_proxy_entry = self.p4info_helper.buildTableEntry(
            table_name = "MyIngress.Geneve.arp_proxy",
            match_fields = { "meta.vni": vni, "hdr.arp.targetIPAddr": ipAddress },
            action_name = "MyIngress.Geneve.arp_respond",
            action_params= {
                "dst": macAddress
            }
        )

        self.connection.WriteTableEntry(arp_smac_sip_entry)
        self.connection.WriteTableEntry(arp_proxy_entry)


    # TODO re-learning local CEs will not work as port is not saved in MACVRF entries
    def _passLocalMACIPtoPeers(self, vni, macAddress, ipAddress="0.0.0.0"):
        newEntry = self.tables.addMACVRFEntry(
                self.bgp_address,
                macAddress,
                vni,
                self.bgp_nexthop,
                vni,
                callback=False, # No callback for local learning
                ipAddr=ipAddress
            )
        if newEntry:
            self.bgpspeaker.advertiseLocalMAC(
                macAddress,
                vni,
                vni,
                ipAddress
            )
        return newEntry


    def run(self):
        try:
            self.logger.debug("run() entered")
            for item in self.connection.stream_msg_resp:
                if item.WhichOneof("update") == "digest" and item.digest.digest_id == self.local_digest_t:
                    self.handleLocalDigest(item.digest.data)
                elif ARP_PROXY and item.WhichOneof("update") == "digest" and item.digest.digest_id == self.arp_digest_t:
                    self.handleARPDigest(item.digest.data)
                elif DP_LEARNING and item.WhichOneof("update") == "digest" and item.digest.digest_id == self.geneve_digest_t:
                    self.handleGeneveDigest(item.digest.data)
                else:
                    self.logger.debug("%s", item)
        except RpcError as e:
            try:
                if e.code() == StatusCode.CANCELLED:
                    self.logger.info("Controller stopped by application!")
                elif e.code() == StatusCode.UNAVAILABLE:
                    self.logger.info("Controller failed to reach switch!")
                else:
                    self.logger.exception("Controller failed, code: %s", str(e.code()))
            except AttributeError:
                self.logger.exception("Controller stopped, status code not available")

    def stop(self):
        self.connection.shutdown()
        if hasattr(self, "bgpspeaker"):
            self.bgpspeaker.stop()
