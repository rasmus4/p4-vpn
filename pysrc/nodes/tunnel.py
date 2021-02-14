from mininet.node import Node
import re
import logging

LOGGING_FORMAT = "%(asctime)s - %(name)s [%(levelname)s]: %(message)s"
logging.basicConfig(format = LOGGING_FORMAT)
logger = logging.getLogger("Tunnel")
logger.setLevel(logging.DEBUG)

class Tunnel(Node):
    def config(self, **kwargs):
        super(Tunnel, self).config(**kwargs)
        # Enable forwarding on the tunnel
        self.cmd("sysctl net.ipv4.ip_forward=1")


    def runCommands(self, cmdsToRun):
        for _cmd in cmdsToRun:
            cmd = re.sub(" +", " ", _cmd)
            res = self.cmd(cmd).rstrip("\n")
            if len(res) > 0:
                logger.warning("Command '%s' yielded result: '%s'", cmd, res)


    def terminate(self):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        super(Tunnel, self).terminate()

class VXLANTunnel(Tunnel):
    def config(self, **kwargs):
        super(VXLANTunnel, self).config(**kwargs)


    def lateConfig(self):
        tunnelArgs = self.params.get("tunnelArgs", None)
        if tunnelArgs is None:
            return
        if "vxlan_config" not in tunnelArgs:
            return
        vxlans = tunnelArgs["vxlan_config"]
        for i, vxlanargs in enumerate(vxlans):
            vxlan_if_name = "vxlan" + str(i)
            br_if_name = "br" + str(i)
            if len(vxlanargs) == 0:
                return
            cmdsToRun = []
            if "remotegroup" in vxlanargs:
                cmdsToRun.append("ip link add {vxlan_if_name} type vxlan \
                    id {vni} \
                    dev {tunnel_dev} \
                    group {remotegroup} \
                    local {local} \
                    dstport {dstport}".format(
                        vxlan_if_name=vxlan_if_name,
                        vni=vxlanargs["vni"],
                        tunnel_dev=self.intfs[int(vxlanargs["tunnel_port"][1:])].name,
                        remotegroup=vxlanargs["remotegroup"],
                        local=vxlanargs["local"],
                        dstport=vxlanargs["dstport"]
                    )
                )
            else:
                cmdsToRun.append("ip link add {vxlan_if_name} type vxlan \
                    id {vni} \
                    dev {tunnel_dev} \
                    remote {remote} \
                    local {local} \
                    dstport {dstport}".format(
                        vxlan_if_name=vxlan_if_name,
                        vni=vxlanargs["vni"],
                        tunnel_dev=self.intfs[int(vxlanargs["tunnel_port"][1:])].name,
                        remote=vxlanargs["remote"],
                        local=vxlanargs["local"],
                        dstport=vxlanargs["dstport"]
                    )
                )
            cmdsToRun.append("sysctl -q net.ipv6.conf.{vxlan_if_name}.disable_ipv6=1".format(
                vxlan_if_name=vxlan_if_name
            ))
            cmdsToRun.append("ip link set {vxlan_if_name} up".format(
                vxlan_if_name=vxlan_if_name
            ))
            cmdsToRun.append("ip link add {br_if_name} type bridge".format(
                br_if_name=br_if_name
            ))
            cmdsToRun.append("ip link set {vxlan_if_name} master {br_if_name}".format(
                vxlan_if_name=vxlan_if_name,
                br_if_name=br_if_name
            ))
            for port in vxlanargs["bridge_ports"]:
                dev = self.intfs[int(port[1:])]
                cmdsToRun.append("ip link set {bridged_interface} master {br_if_name}".format(
                    bridged_interface=dev,
                    br_if_name=br_if_name
                ))
            cmdsToRun.append("ip link set {br_if_name} up".format(
                br_if_name=br_if_name
            ))
            cmdsToRun.append("sysctl -q net.ipv6.conf.{br_if_name}.disable_ipv6=1".format(
                br_if_name=br_if_name
            ))
            cmdsToRun.append("ifconfig {br_if_name} {bridge_address}".format(
                br_if_name=br_if_name,
                bridge_address=vxlanargs["bridge_address"]
            ))
            self.runCommands(cmdsToRun)


    def terminate(self):
        super(VXLANTunnel, self).terminate()

class L2TPTunnel(Tunnel):
    def config(self, **kwargs):
        super(L2TPTunnel, self).config(**kwargs)


    def lateConfig(self):
        tunnelArgs = self.params.get("tunnelArgs", None)
        if tunnelArgs is None:
            return
        if "l2tp_config" not in tunnelArgs:
            return
        l2tpargs = tunnelArgs["l2tp_config"]
        if len(l2tpargs) == 0:
            return
        cmdsToRun = []
        cmdsToRun.append("ip l2tp add tunnel \
            tunnel_id {tunnel_id} \
            peer_tunnel_id {peer_tunnel_id} \
            udp_sport {udp_sport} \
            udp_dport {udp_dport} \
            local {local} \
            remote {remote} \
            encap {encap}".format(
                tunnel_id=l2tpargs["tunnel_id"],
                peer_tunnel_id=l2tpargs["peer_tunnel_id"],
                udp_sport=l2tpargs["udp_sport"],
                udp_dport=l2tpargs["udp_dport"],
                local=l2tpargs["local"],
                remote=l2tpargs["remote"],
                encap=l2tpargs["encap"]
            )
        )
        cmdsToRun.append(
            "ip l2tp add session \
            tunnel_id {tunnel_id} \
            session_id {session_id} \
            peer_session_id {peer_session_id}".format(
                tunnel_id=l2tpargs["tunnel_id"],
                session_id=l2tpargs["session_id"],
                peer_session_id=l2tpargs["peer_session_id"]
            )
        )
        cmdsToRun.append("sysctl -q net.ipv6.conf.l2tpeth0.disable_ipv6=1")
        cmdsToRun.append("ip link set l2tpeth0 up mtu 1446")
        cmdsToRun.append("ip link add br0 type bridge")
        cmdsToRun.append("ip link set l2tpeth0 master br0")
        for interface in tunnelArgs["interface_configs"]:
            if interface["type"] == "bridge":
                dev = self.intfs[int(interface["port"][1:])]
                cmdsToRun.append("ip link set {br0_interface} master br0".format(
                    br0_interface=dev))
        cmdsToRun.append("ip link set br0 up")
        cmdsToRun.append("ifconfig br0 {bridge_address}".format(
            bridge_address=l2tpargs["bridge_address"]
        ))
        self.runCommands(cmdsToRun)


    def terminate(self):
        super(L2TPTunnel, self).terminate()