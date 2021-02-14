from .util.bgp import (BGPHeader, BGPOpen, BGPKeepAlive, BGP, BGPUpdate, BGPPathAttr, BGPPAMPReachNLRI, BGPPAExtCommunity, BGPPAExtComms,
    BGPPAExtCommTwoOctetASSpecific, BGPPAOrigin, BGPPAASPath, BGPPANextHop)
from .util.bgp import EVPNNLRI, RTEthernetAutoDiscovery, RTMacIPAdvertisementRoute, RouteDistinguisher, RouteDistinguisherValueType1, RT_MAC_IP_ROUTE
from .util.bgp import _bgp_message_types as bgp_message_types
from scapy.fields import ShortField
from scapy.supersocket import SimpleSocket
from scapy.layers.inet import IP, TCP
import socket
import argparse
import logging
import threading
import select
import os
import time

LOGGING_FORMAT = "%(asctime)s - %(name)s [%(levelname)s]: %(message)s"
logging.basicConfig(format = LOGGING_FORMAT)
logger = logging.getLogger("NVE Controller")
logger.setLevel(logging.INFO)

EVENT_STOP = b'0'
EVENT_CONTINUE = b'1'

BUFFER_SIZE = 1024

class Tables():
    class MACVRFEntry():
        def __init__(self, nextHop, routeTarget, instance, MAC, ipAddr="0.0.0.0"):
            self.nextHop = nextHop
            self.routeTarget = routeTarget
            self.instance = instance
            self.MAC = MAC
            self.ipAddr = ipAddr

        def __eq__(self, other):
            return self.nextHop == other.nextHop and\
                self.routeTarget == other.routeTarget and\
                self.instance == other.instance and\
                self.MAC == other.MAC


    def __init__(self, name = "NOT SET"):
        self.MACVRF = {}
        self.MACVRFLock = threading.Lock()
        self.MACVRFPerConnection = {}
        self.nextHopsPerInstance = {}
        self.lastAddedNextHopPerInstance = {} # This table is used to circumvent fact that clone3 is not supported on BMv2 (preserving metadata)
        self.MACIPCallbacks = []
        self.remoteVNICallbacks = []
        self.name = name

    def addMACIPCallback(self, callback):
        self.MACIPCallbacks.append(callback)

    def addRemoteVNICallback(self, callback):
        self.remoteVNICallbacks.append(callback)

    # Returns True if MAC-VRF entry successfully added, False otherwise (e.g. if entry is already present)
    def addMACVRFEntry(self, peerAddress, MAC, instance, nextHop, routeTarget, callback=True, ipAddr="0.0.0.0"):
        macVRFEntry = Tables.MACVRFEntry(nextHop, routeTarget, instance, MAC, ipAddr)
        logger.debug("%s: Adding '%s' to MAC-VRF %d, nexthop: '%s'", self.name, MAC, instance, nextHop)

        newRemoteVNIEntry = False

        with self.MACVRFLock:
            if instance in self.nextHopsPerInstance:
                if nextHop not in self.nextHopsPerInstance[instance]:
                    self.nextHopsPerInstance[instance].append(nextHop)
                    newRemoteVNIEntry = True
            else:
                self.nextHopsPerInstance[instance] = [nextHop]
                self.lastAddedNextHopPerInstance[instance] = None
                newRemoteVNIEntry = True
            # Make sure we don't add duplicate entry
            if peerAddress in self.MACVRFPerConnection:
                for entry in self.MACVRFPerConnection[peerAddress]:
                    if entry == macVRFEntry:
                        if ipAddr != "0.0.0.0" and entry.ipAddr != ipAddr:
                            self.MACVRFPerConnection[peerAddress].remove(entry)
                            logger.info("Updating IP Addr for entry '%s', EVI %s", MAC, instance)
                            break
                        else:
                            return False

            if instance not in self.MACVRF:
                self.MACVRF[instance] = {}
            self.MACVRF[instance][MAC] = macVRFEntry
            logger.debug("Added to MACVRF: '%s'", macVRFEntry)
            if peerAddress not in self.MACVRFPerConnection:
                self.MACVRFPerConnection[peerAddress] = []
            self.MACVRFPerConnection[peerAddress].append(macVRFEntry)

        # Perform callback outside of lock
        if callback:
            for _c in self.MACIPCallbacks:
                if ipAddr != "0.0.0.0":
                    # Release wild daemon thread out into wilderness
                    # threading.Thread(target=_c, args=(MAC, instance, nextHop, ipAddr), daemon=True).start()
                    _c(MAC, instance, nextHop, ipAddr=ipAddr)
                else:
                    # Release wild daemon thread out into wilderness
                    # threading.Thread(target=_c, args=(MAC, instance, nextHop), daemon=True).start()
                    _c(MAC, instance, nextHop)
            # if newRemoteVNIEntry:
            #     for _c in self.remoteVNICallbacks:
            #         _c(instance, nextHop, self.lastAddedNextHopPerInstance[instance])
            #     self.lastAddedNextHopPerInstance[instance] = nextHop
        return True

    def withdrawEntriesByConnection(self, peerAddress):
        logger.debug("Withdraw from peer '%s'", peerAddress)
        for entry in self.MACVRFPerConnection[peerAddress]:
            logger.debug("Remove from MACVRF: '%s'", entry)
            self.MACVRF[entry.instance].pop(entry.MAC)
        self.MACVRFPerConnection.pop(peerAddress, None)

    def __str__(self):
        _str = "MACVRF\n"
        _str += "{:>3} | {:>5} | {:>17} | {:>15} | {:>15}\n".format("#", "EVI", "MAC", "IP", "NH")
        _str += "{:=>67}\n".format("")
        i = 1
        for entry in self.MACVRF.items():
            for entryMac in entry[1].items():
                _str += "{:>3} | ".format(i)
                _str += "{:5d} | ".format(entry[0])
                _str += "{:>17} | ".format(entryMac[0])
                _str += "{:>15} | ".format(entryMac[1].ipAddr)
                _str += "{:>15}".format(entryMac[1].nextHop)
                _str += "\n"
                i += 1

        _str += "MACVRFPerConnection\n"
        _str += "{:>3} | {:>15} | {:>5} | {:>17} | {:>15} | {:>15}\n".format("#", "Peer", "EVI", "MAC", "IP", "NH")
        _str += "{:=>85}\n".format("")
        i = 1
        for addr, entries in self.MACVRFPerConnection.items():
            for entry in entries:
                _str += "{:>3} | ".format(i)
                _str += "{:>15} | ".format(addr)
                _str += "{:5d} | ".format(entry.instance)
                _str += "{:>17} | ".format(entry.MAC)
                _str += "{:>15} | ".format(entry.ipAddr)
                _str += "{:>15}".format(entry.nextHop)
                _str += "\n"
                i += 1

        _str += "EVI <=> NH Mapping\n"
        _str += "{:>3} | {:>5} | {:>15}\n".format("#", "EVI", "NH")
        _str += "{:=>85}\n".format("")
        i = 1
        for evi, entries in self.nextHopsPerInstance.items():
            for nextHop in entries:
                _str += "{:>3} | ".format(i)
                _str += "{:>5} | ".format(evi)
                _str += "{:>15}".format(nextHop)
                _str += "\n"
                i += 1

        return _str

class BGPEvents():
    AUTOMATIC_START = 3
    TCP_CONFIRMED = 17
    TCP_FAIL = 18
    BGPOPEN = 19
    BGPOPEN_DELAY_TIMER_RUNNING = 20
    BGPHEADER_ERR = 21
    BGPOPEN_ERR = 22
    OPEN_COLLISION_DUMP = 23
    NOTIFICATION_VER_ERR = 24
    NOTIFICATION = 25
    KEEPALIVE = 26
    UPDATE = 27
    UPDATE_ERR = 28

class BGPConnection():
    BGP_CONNECT_RETRY_TIME = 2.0

    BGP_FSM_IDLE = 0
    BGP_FSM_CONNECT = 1
    BGP_FSM_OPENSENT = 2
    BGP_FSM_OPENCONFIRM = 3
    BGP_FSM_ACTIVE = 4
    BGP_FSM_ESTABLISHED = 5

    _stateMapStr = {
        BGP_FSM_IDLE: "IDLE",
        BGP_FSM_CONNECT: "CONNECT",
        BGP_FSM_OPENSENT: "OPENSENT",
        BGP_FSM_OPENCONFIRM: "OPENCONFIRM",
        BGP_FSM_ACTIVE: "ACTIVE",
        BGP_FSM_ESTABLISHED: "ESTABLISHED",
    }

    @staticmethod
    def stateToString(state):
        return BGPConnection._stateMapStr[state]

    def __init__(self, address, port):
        self.address = address
        self.port = port
        self.state = BGPConnection.BGP_FSM_IDLE
        self.connect_retry_counter = 0
        self.connect_retry_timer = 0
        self.connect_retry_time = BGPConnection.BGP_CONNECT_RETRY_TIME
        self.hold_timer = 0
        self.hold_time = 0
        self.keep_alive_timer = 0
        self.keep_alive_time = 0

    def hasConnectRetryExpired(self):
        timeRemaining = (self.connect_retry_timer + self.connect_retry_time) - time.time()
        return timeRemaining < 0, timeRemaining

    def resetConnectRetry(self):
        self.connect_retry_timer = time.time()


class BGPConnections():
    def __init__(self):
        self.connections = {}
        self.connections_lock = threading.Lock()

    def add(self, addr):
        peer = addr["address"]
        port = addr["port"]
        with self.connections_lock:
            if peer not in self.connections.keys():
                self.connections[peer] = BGPConnection(peer, port)

    def setState(self, peer, state):
        with self.connections_lock:
            self.connections[peer].state = state
            logger.info("Settings state for %s to %s", peer, BGPConnection.stateToString(state))

    def reportEvent(self, peer, event):
        with self.connections_lock:
            current_state = self.connections[peer].state
            if current_state == BGPConnection.BGP_FSM_IDLE:
                if event == BGPEvents.AUTOMATIC_START:
                    self.connections[peer].state = BGPConnection.BGP_FSM_CONNECT
                    return True
                return False
            elif current_state == BGPConnection.BGP_FSM_CONNECT:
                if event == BGPEvents.BGPOPEN:
                    self.connections[peer].state = BGPConnection.BGP_FSM_OPENCONFIRM
                    return True
                elif event == BGPEvents.TCP_CONFIRMED:
                    self.connections[peer].state = BGPConnection.BGP_FSM_OPENSENT
                    return True
                return False
            elif current_state == BGPConnection.BGP_FSM_OPENSENT:
                if event == BGPEvents.BGPOPEN:
                    self.connections[peer].state = BGPConnection.BGP_FSM_OPENCONFIRM
                    return True
                elif event == BGPEvents.TCP_FAIL:
                    self.connections[peer].state = BGPConnection.BGP_FSM_CONNECT
                    return True
                return False
            elif current_state == BGPConnection.BGP_FSM_OPENCONFIRM:
                if event == BGPEvents.KEEPALIVE:
                    self.connections[peer].state = BGPConnection.BGP_FSM_ESTABLISHED
                    return True
                elif event == BGPEvents.TCP_FAIL:
                    self.connections[peer].state = BGPConnection.BGP_FSM_CONNECT
                    return True
                return False

    def getState(self, peer):
        with self.connections_lock:
            return self.connections[peer].state

    def hasConnectRetryExpired(self, peer):
        with self.connections_lock:
            return self.connections[peer].hasConnectRetryExpired()

    def resetConnectRetry(self, peer):
        with self.connections_lock:
            self.connections[peer].resetConnectRetry()

    def __str__(self):
        _str = "BGP STATES\n"
        _str += "{:>3} | {:>15} | {:>17}\n".format("#", "PEER", "STATE")
        _str += "{:=>47}\n".format("")
        i = 1
        for peer, connection in self.connections.items():
            _str += "{:>3} | ".format(i)
            _str += "{:>15} | ".format(peer)
            _str += "{:>17}".format(BGPConnection.stateToString(connection.state))
            _str += "\n"
            i += 1

        return _str


class BGPSpeaker(threading.Thread):
    class BGPConnectionThread(threading.Thread):
        def __init__(self, addr, connections, connect_function):
            threading.Thread.__init__(self)
            self.ready = False
            self.addr = addr
            self.bgp_connections = BGPConnections()
            self.connect = connect_function
            for connection in connections:
                self.bgp_connections.add(connection)
                self.bgp_connections.reportEvent(
                    connection["address"], BGPEvents.AUTOMATIC_START
                )

        def run(self):
            self.running = True
            while self.running:
                numberOfIdleConnections = 0
                numberOfEstablishedConnections = 0
                timeUntilNextExpire = BGPConnection.BGP_CONNECT_RETRY_TIME
                ts = time.time()
                for key in self.bgp_connections.connections.keys():
                    if self.bgp_connections.getState(key) == BGPConnection.BGP_FSM_CONNECT:
                        numberOfIdleConnections += 1
                        hasExpired, timeRemaining = self.bgp_connections.hasConnectRetryExpired(key)
                        if hasExpired and self.addr > key:
                            self.connect(key, self.bgp_connections.connections[key].port)
                            self.bgp_connections.resetConnectRetry(key)
                        elif timeRemaining < timeUntilNextExpire:
                            newTs = time.time()
                            diff = newTs - ts
                            if timeUntilNextExpire - diff < 0:
                                timeUntilNextExpire = 0.0
                            elif timeRemaining < timeUntilNextExpire - diff:
                                timeUntilNextExpire = timeRemaining
                                ts = newTs
                    elif self.bgp_connections.getState(key) == BGPConnection.BGP_FSM_ESTABLISHED:
                        numberOfEstablishedConnections += 1
                if timeUntilNextExpire > 0.0:
                    time.sleep(timeUntilNextExpire)

                if numberOfEstablishedConnections == len(self.bgp_connections.connections.keys()):
                    self.ready = True

        def stop(self):
            self.running = False


    def __init__(self, listen_addr, port, asn, tables, peers, name="NOT SET", nexthop=None):
        threading.Thread.__init__(self)
        self.listen_addr = listen_addr
        self.listen_port = port
        self.connections = []
        self.asn = asn
        self.tables = tables
        self.name = name
        self.nexthop = listen_addr if nexthop is None else nexthop
        self.event_pipe = os.pipe()
        self.connection_thread = BGPSpeaker.BGPConnectionThread(self.listen_addr, peers, self.connect)
        self.connection_thread.start()

    def connect(self, remote_address, port):
        logger.debug("BGPSpeaker '%s:%d' -> '%s:%d': Initialising", self.listen_addr, self.listen_port, remote_address, port)
        try:
            s = socket.create_connection((remote_address, port), timeout=2.0, source_address=(self.listen_addr, 0))
            ss = SimpleSocket(s)
            ss.addr = remote_address

            logger.debug("BGPSpeaker -> OPEN")
            ss.send(BGPHeader()/BGPOpen(bgp_id=self.listen_addr))
            if self.connection_thread.bgp_connections.reportEvent(ss.addr, BGPEvents.TCP_CONFIRMED):
                self.connections.append(ss)
                self.interruptListenThread()
                logger.info("BGPSpeaker '%s' -> '%s:%d': Connected", self.listen_addr, remote_address, port)
            else:
                s.close()
        except ConnectionRefusedError:
            logger.warning("BGPSpeaker '%s' -> '%s:%d': Connection refused", self.listen_addr, remote_address, port)
        except socket.timeout:
            logger.warning("BGPSpeaker '%s' -> '%s:%d': Timed out on connect", self.listen_addr, remote_address, port)

    def run(self):
        self.listen(self.listen_addr, self.listen_port)


    def stop(self):
        self.running = False
        self.connection_thread.stop()
        try:
            self.serv.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.serv.close()
        os.write(self.event_pipe[1], EVENT_STOP)
        for connection in self.connections:
            try:
                connection.ins.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.connection_thread.join(timeout=BGPConnection.BGP_CONNECT_RETRY_TIME)

    def interruptListenThread(self):
        os.write(self.event_pipe[1], EVENT_CONTINUE)


    def listen(self, listen_addr, port):
        self.serv = socket.create_server((listen_addr, port), family=socket.AF_INET)
        logger.info("BGPSpeaker '%s:%d' <- : Listening for connections", listen_addr, port)
        self.running = True
        read_list = [self.serv, self.event_pipe[0]]

        while self.running:
            r, _, _ = select.select(
                read_list + self.connections,
                [],
                [],
            )
            for s in r:
                if s is self.event_pipe[0]:
                    event = os.read(s, 1)
                    if event == EVENT_STOP:
                        if not self.running:
                            return
                        self.running = False
                    elif event == EVENT_CONTINUE:
                        pass
                elif s is self.serv and self.running:
                    conn, addr = self.serv.accept()
                    logger.info("BGPSpeaker '%s:%d' <- '%s:%d': New connection", listen_addr, port, addr[0], addr[1])
                    ss = SimpleSocket(conn)
                    ss.addr = addr[0]
                    ss.send(BGPHeader()/BGPOpen(bgp_id=self.listen_addr))
                    if self.connection_thread.bgp_connections.reportEvent(ss.addr, BGPEvents.TCP_CONFIRMED):
                        self.connections.append(ss)
                    else:
                        ss.close()
                elif self.running:
                    data = b""
                    try:
                        while 1:
                            _, _data, _ = s.recv_raw(BUFFER_SIZE)
                            data += _data
                            if len(_data) != BUFFER_SIZE:
                                break
                    except ConnectionResetError:
                        self.connection_thread.bgp_connections.reportEvent(s.addr, BGPEvents.TCP_FAIL)
                        s.close()
                        self.connections.remove(s)
                        continue

                    if len(data) == 0:
                        self.tables.withdrawEntriesByConnection(s.addr)
                        self.connections.remove(s)
                        logger.warning("BGPSpeaker '%s:%d' <- '?' Connection closed", listen_addr, port)
                        logger.debug("%s", self.tables)
                        continue
                    if data is None:
                        logger.error("data is None")
                        continue

                    prevDataLen = len(data)
                    while len(data) > 0:
                        bgpHeader = BGPHeader(data)

                        if bgp_message_types[bgpHeader.fields["type"]] == "OPEN":
                            if self.connection_thread.bgp_connections.reportEvent(s.addr, BGPEvents.BGPOPEN):
                                logger.debug("BGPSpeaker <- OPEN")
                                #bgpOpen = BGPOpen(data[19:])
                                logger.debug("BGPSpeaker -> KEEPALIVE")
                                try:
                                    s.send(BGPKeepAlive())
                                except:
                                    self.connection_thread.bgp_connections.reportEvent(s.addr, BGPEvents.TCP_FAIL)
                                    s.close()
                                    self.connections.remove(s)
                                    break
                            else:
                                s.close()
                                self.connections.remove(s)
                        elif bgp_message_types[bgpHeader.fields["type"]] == "KEEPALIVE":
                            logger.debug("BGPSpeaker <- KEEPALIVE")
                            if not self.connection_thread.bgp_connections.reportEvent(s.addr, BGPEvents.KEEPALIVE):
                                s.close()
                                self.connections.remove(s)
                        elif bgp_message_types[bgpHeader.fields["type"]] == "UPDATE":
                            #logger.info("BGPSpeaker '%s:%d' <- UPDATE", listen_addr, port)
                            entryAdded = False
                            bgpUpdate = BGPUpdate(data[19:])
                            for path_attr in bgpUpdate.path_attr:
                                if path_attr.type_code == 16: # EXTENDED_COMMUNITIES
                                    for attr in path_attr.attribute:
                                        for ec in attr.extended_communities:
                                            routeTarget = ec.value.local_administrator
                                if path_attr.type_code == 14: # MP_REACH_NLRI
                                    for attr in path_attr.attribute:
                                        nextHop = attr.nh_v4_addr
                                        for nlri in attr.nlri:
                                            peerAddress = nlri.route_type_specific.route_distinguisher.value.ip_address
                                            MAC = nlri.route_type_specific.mac_address
                                            ipAddr = nlri.route_type_specific.ip_address
                                            instance = nlri.route_type_specific.mpls_label1
                                            logger.debug("BGPSpeaker '%s:%d' <- UPDATE ('%s', '%d')", listen_addr, port, MAC, instance)
                                            entryAdded = True
                                            self.tables.addMACVRFEntry(
                                                peerAddress = peerAddress,
                                                MAC = MAC,
                                                instance = instance,
                                                nextHop = nextHop,
                                                routeTarget = routeTarget,
                                                ipAddr = ipAddr
                                            )
                                if path_attr.type_code == 2:
                                    pass
                                if path_attr.type_code == 3:
                                    pass
                            if not entryAdded:
                                logger.error("BGPSpeaker '%s:%d' <- UPDATE lead to no new entry!", listen_addr, port)
                                bgpUpdate.show()

                        if len(data) > bgpHeader.len:
                            data = data[bgpHeader.len:]
                        else:
                            data = []
                        if prevDataLen == len(data):
                            logger.critical("prevDataLen == len(data), breaking loop!")
                            break
                        else:
                            prevDataLen = len(data)
        if self.running:
            logger.critical("BGPSpeaker '%s:%d' MAIN LOOP EXITED WHILE self.running is True!", self.listen_addr, self.listen_port)
        self.stop()

    def sendToAll(self, data, _id=""):
        total_sent = 0
        for s in self.connections:
            total_sent = 0
            while total_sent < len(data):
                sent = s.send(data[total_sent:])
                if sent != len(data):
                    logger.warning("sent != len(data) (id %s)", _id)
                elif sent == 0:
                    raise Exception("Socket is dead")
                total_sent += sent
        # logger.info("BGPSpeaker '%s:%d' -> sent '%d' bytes to %d peers (id %s)", self.listen_addr, self.listen_port, total_sent, len(self.connections), _id)

    def advertiseLocalMAC(self, macAddr, macVRFId, routeTarget, ipAddr="0.0.0.0"):
        #logger.info("BGPSpeaker %s -> UPDATE ('%s', '%d')", self.listen_addr, macAddr, macVRFId)
        data = BGPHeader()/BGPUpdate(
            path_attr=[
                BGPPathAttr(
                    type_code=16, # EXTENDED_COMMUNITIES
                    attribute=[
                        BGPPAExtComms(
                            extended_communities=BGPPAExtCommunity(
                                type_high=0, # Transitive Four-Octet AS-Specific Extended Community
                                type_low=2, # Route Target
                                value=BGPPAExtCommTwoOctetASSpecific(
                                    local_administrator=routeTarget,
                                    global_administrator=self.asn
                                )
                            )
                        )
                    ]
                ),
                BGPPathAttr(
                    type_code=1, # BGPPAOrigin
                    type_flags=["Transitive"],
                    attribute=BGPPAOrigin(
                        origin=0
                    )
                ),
                BGPPathAttr(
                    type_code=2, # BGPPAASPath
                    type_flags=["Transitive"],
                    attribute=BGPPAASPath(
                        segments=[]
                    )
                ),
                BGPPathAttr(
                    type_code=3, # BGPPANextHop
                    type_flags=["Transitive"],
                    attribute=BGPPANextHop(
                        next_hop=self.nexthop
                    )
                ),
                BGPPathAttr(
                    type_code=14, # MP_REACH_NLRI
                    attribute=[
                        BGPPAMPReachNLRI(
                            afi=25, # L2VPN
                            safi=70, # EVPN
                            nh_addr_len=4,
                            nh_v4_addr=self.nexthop,
                            nlri=[
                                EVPNNLRI(
                                    route_type=RT_MAC_IP_ROUTE,
                                    length=37 if ipAddr is not None else 33,
                                    route_type_specific=RTMacIPAdvertisementRoute(
                                        route_distinguisher=RouteDistinguisher(
                                            type=1,
                                            value=RouteDistinguisherValueType1(
                                                ip_address=self.listen_addr,
                                                assigned_number=macVRFId
                                            )
                                        ),
                                        mac_address=macAddr,
                                        ip_address_length=32 if ipAddr is not None else 0,
                                        ip_address=ipAddr,
                                        mpls_label1=macVRFId
                                    )
                                )
                            ]
                        )
                    ]
                )
            ]
        )
        self.sendToAll(data, "'{}', '{}'".format(macAddr, macVRFId))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("addr", help="Address to listen on for other BGP speakers")
    parser.add_argument("--port", "-p", help="Port to listen for other BGP speakers on", type=int, default=179)
    args = parser.parse_args()
    tables = Tables()
    bc = BGPSpeaker(args.addr, args.port, asn=64512, tables=tables)
    bc.start()
    if args.port != 179:
        bc.connect(args.addr, 179)
        bc.advertiseLocalMAC("aa:bb:cc:11:22:33", 51, 1)
    try:
        bc.join()
    except KeyboardInterrupt:
        logger.debug("KeyboardInterrupt caught, shutting down..")
        bc.stop()