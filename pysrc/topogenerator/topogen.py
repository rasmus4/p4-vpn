#!/usr/bin/python2.7
import sys
import json
import copy
import random

class TopologyGenerator():
    def __init__(self, template_path):
        self.loadTemplate(template_path)


    def printError(self, message):
        print "ERROR: " + message


    def loadTemplate(self, template_path):
        with open(template_path, "r") as template_file:
            templateRaw = template_file.read()
        self.template = json.loads(templateRaw)


    def generate(self):
        self.topology = {
            "hosts": {},
            "routers": {},
            "switches": {},
            "tunnels": {},
            "links": []
        }
        systems = {}
        for i, system in enumerate(self.template["systems"]):
            flattenedNodes = self.flattenNodes(system["nodes"])
            self.assignNodeNames(system["name"], flattenedNodes)
            flattenedNodes = self.resolveIds(flattenedNodes)
            links = self.getLinks(flattenedNodes)
            hosts = self.getHosts(
                flattenedNodes,
                subnet="10.<TWIN-NO-OVERLAP>.%d." % i,
                defaultRoute="10.<TWIN-NO-OVERLAP>.%d.1" % i,
                macprefix="08:<TWIN-NO-OVERLAP-02d>:00:00:%02d:" % i
            )
            switches = self.getSwitches(flattenedNodes)
            routers = self.getRouters(
                flattenedNodes,
                links,
                ip="10.<TWIN-NO-OVERLAP>.%d.1/24" % i,
                mac="88:<TWIN-NO-OVERLAP-02d>:00:00:%02d:00" % i
            )
            systems[system["name"]] = {
                "links": links,
                "hosts": hosts,
                "switches": switches,
                "routers": routers,
                "gateway": "10.<TWIN-NO-OVERLAP>.%d.1" % i,
                "subnet": "10.<TWIN-NO-OVERLAP>.%d.0/24" % i,
                "systemid": i
            }

        for _, system in systems.items():
            self.setLateRouterCommands(system, systems)

        random.seed(51)
        clonedSystems = {}
        sites = {}

        # For max-spread setting
        currentSiteIndex = 0

        for twin in range(self.template["twins"]):
            for name, system in systems.items():
                deepcopiedSystem = copy.deepcopy(system)
                clonedSystems["t" + str(twin) + "_" + name] = deepcopiedSystem
                deepcopiedSystem["twin"] = twin

                # Adjust link names
                for linkindex in range(len(deepcopiedSystem["links"])):
                    link = deepcopiedSystem["links"][linkindex]
                    end = [link[0], link[1]]
                    for i in range(2):
                        if link[i] != "EDGE":
                            end[i] = ("t%d_" % twin) + link[i]
                    deepcopiedSystem["links"][linkindex] = (end[0], end[1])

                # Adjust node names
                for nodeType in ["routers", "hosts", "switches"]:
                    keysToChange = []
                    for node in deepcopiedSystem[nodeType]:
                        keysToChange.append(node)
                    for key in keysToChange:
                        deepcopiedSystem[nodeType][("t%d_" % twin) + key] = deepcopiedSystem[nodeType].pop(key)

                if "no-overlap" in self.template["nvetype"]:
                    tVal = twin
                else:
                    tVal = 0

                for _, router in deepcopiedSystem["routers"].items():
                    for i, late_cmd in enumerate(router["late_commands"]):
                        router["late_commands"][i] = late_cmd.replace("<TWIN-NO-OVERLAP>", "%d" % tVal)
                        router["late_commands"][i] = router["late_commands"][i].replace("<TWIN>", "%d" % twin)
                    for i, if_config in enumerate(router["interface_configs"]):
                        router["interface_configs"][i]["ip"] = if_config["ip"].replace("<TWIN-NO-OVERLAP>", "%d" % tVal)
                        router["interface_configs"][i]["mac"] = if_config["mac"].replace("<TWIN-NO-OVERLAP-02d>", "%02d" % tVal)
                for _, host in deepcopiedSystem["hosts"].items():
                    for i, late_cmd in enumerate(host["late_commands"]):
                        host["late_commands"][i] = late_cmd.replace("<TWIN-NO-OVERLAP>", "%d" % tVal)
                        host["late_commands"][i] = host["late_commands"][i].replace("<TWIN>", "%d" % twin)
                    host["ip"] = host["ip"].replace("<TWIN-NO-OVERLAP>", "%d" % tVal)
                    host["mac"] = host["mac"].replace("<TWIN-NO-OVERLAP-02d>", "%02d" % tVal)

                # Add system to site
                if self.template["placement"] == "random":
                    deepcopiedSystem["site"] = random.randint(0, self.template["sites"]-1)
                elif self.template["placement"] == "max-spread":
                    if currentSiteIndex > (self.template["sites"] - 1):
                        currentSiteIndex = 0
                    deepcopiedSystem["site"] = currentSiteIndex
                    currentSiteIndex = currentSiteIndex + 1

                # System placement independent of placement type
                if deepcopiedSystem["site"] in sites:
                    sites[deepcopiedSystem["site"]].append(deepcopiedSystem)
                else:
                    sites[deepcopiedSystem["site"]] = [deepcopiedSystem]

        self.nves = {}
        self.links = []
        for site in range(self.template["sites"]):
            if self.template["nvetype"] == "p4-evpn-geneve" or self.template["nvetype"] == "p4-dp-geneve":
                nve = {
                    "type": "p4nve",
                    "runtime_json": "pysrc/nve_controller/config/switch-runtime.json",
                    "nve_config": [],
                    "interface_configs": [
                        {"ip": ("172.16.0.1%d/24" % site), "port": "p1"}
                    ],
                    "late_commands": [],
                    "bgp_address": ("172.16.0.1%d" % site),
                    "bgp_hop_address": ("172.16.0.1%d" % site),
                    "bgp_port": 179,
                    "bgp_peers": [],
                    "vni_list": []
                }
                for i in range(self.template["sites"]):
                    if i == site:
                        continue
                    nve["bgp_peers"].append({"address": "172.16.0.1%d" % i, "port": 179})
            elif self.template["nvetype"] == "no-overlap":
                nve = {
                    "type": "bridge"
                }
            elif self.template["nvetype"] == "no-overlap-p4":
                nve = {
                    "type": "p4bridge",
                    "runtime_json": "pysrc/controller/config/switch-runtime.json"
                }
            elif self.template["nvetype"] == "vxlan-bridge":
                nve = {
                    "type": "vxlan",
                    "vxlan_config": [],
                    "interface_configs": [
                        {"ip": ("172.16.0.1%d/24" % site), "port": "p1"}
                    ],
                    "late_commands": []
                }
            vniMap = {}
            portIndex = 2
            if site in sites:
                for i, system in enumerate(sites[site]):
                    for linkindex, link in enumerate(system["links"]):
                        nvePortName = "s{id}-p{port}".format(id=site+1, port=portIndex)
                        if link[0] == "EDGE":
                            isRouter = True if "_r" in link[1] else False
                            self.links.append((nvePortName, link[1]))
                            #print "Resolving edge link {e1} <=> {e2}".format(e1 = nvePortName, e2 = link[1])
                        elif link[1] == "EDGE":
                            isRouter = True if "_r" in link[0] else False
                            self.links.append((link[0], nvePortName))
                            #print "Resolving edge link {e1} <=> {e2}".format(e1 = link[0], e2 = nvePortName)
                        else:
                            continue

                        if self.template["nvetype"] == "p4-evpn-geneve" or self.template["nvetype"] == "p4-dp-geneve":
                            #vni = system["twin"]*128 + (1 if isRouter else system["systemid"]*2)
                            vni = system["twin"]
                            if vni not in nve["vni_list"]:
                                nve["vni_list"].append(vni)
                        else:
                            vni = system["twin"]

                        if vni in vniMap:
                            vniMap[vni]["bridge_ports"].append(
                                "p%d" % (portIndex)
                            )
                        else:
                            if self.template["nvetype"] == "p4-evpn-geneve" or self.template["nvetype"] == "p4-dp-geneve":
                                nveConfig = {
                                    "vni": vni,
                                    "tunnel_port": "p1",
                                    "bridge_address": "0.0.0.0",
                                    "bridge_ports": [ "p%d" % (portIndex) ]
                                }
                                nve["nve_config"].append(nveConfig)
                                vniMap[vni] = nveConfig
                            elif self.template["nvetype"] == "vxlan-bridge":
                                vxlanConfig = {
                                        "vni": vni,
                                        "tunnel_port": "p1",
                                        "local": "any",
                                        "remotegroup": "239.1.1.1%d" % vni,
                                        "dstport": 4789,
                                        "bridge_address": "0.0.0.0",
                                        "bridge_ports": [ "p%d" % (portIndex) ]
                                }
                                nve["vxlan_config"].append(vxlanConfig)
                                vniMap[vni] = vxlanConfig
                        if "interface_configs" in nve:
                            nve["interface_configs"].append(
                                {"ip": "0.0.0.0/0", "port": "p%d" % (portIndex)}
                            )
                        portIndex += 1

            self.nves["s%d" % (site+1)] = nve

        for system in clonedSystems.values():
            for link in system["links"]:
                if link[0] != "EDGE" and link[1] != "EDGE":
                    self.links.append(link)

            for nodeType in ["hosts", "routers", "switches"]:
                for nodename, node in system[nodeType].items():
                    self.topology[nodeType][nodename] = node

        self.topology["switches"]["c_s1"] = {
            "type": "bridge"
        }

        for i, nve in enumerate(self.nves.keys()):
            self.links.append((nve + "-p1", "c_s1"))
            #self.links.append((nve + "-p1", "backbone-p%d" % (i+1)))
            """self.topology["switches"]["backbone"]["interface_configs"].append(
                {"ip": "172.16.0.1/24", "port": "p%d" % (i+1), "nat": False}
            )"""

        self.topology["debug"] = clonedSystems
        self.topology["tunnels"] = self.nves
        self.topology["links"] = self.links

        # Generate vns dict
        self.vns = []
        for twin in range(self.template["twins"]):
            self.vns.append({
                "VNID": "Twin %d" % twin,
                "hosts": []
            })
        for system in clonedSystems.values():
            self.vns[system["twin"]]["hosts"].extend(system["hosts"])
            self.vns[system["twin"]]["hosts"].extend(system["routers"])


    def saveToFiles(self, savepath):
        with open(savepath + "/topology.json", 'w') as outfile:
            json.dump(self.topology, outfile, indent=4, sort_keys=True)
        with open(savepath + "/vns.json", 'w') as outfile:
            json.dump(self.vns, outfile, indent=4, sort_keys=True)


    def setLateRouterCommands(self, system, systems):
        for rname, router in system["routers"].items():
            for _, _system in systems.items():
                if _system["subnet"] == system["subnet"]:
                    continue
                router["late_commands"].extend([
                    "ip route add {gw} dev t<TWIN>_{name}-eth1".format(
                        gw=_system["gateway"],
                        name=rname
                    ),
                    "ip route add {subnet} via {gw}".format(
                        subnet=_system["subnet"],
                        gw=_system["gateway"]
                    )
                ])


    def getRouters(self, flattenedNodes, links, ip = None, nat = False, mac="88:00:00:00:00:00"):
        routers = {}
        linksPerNode = {}
        for link in links:
            for i, _end in enumerate(link):
                if "-p" in _end[-3:-1]:
                    end = _end[0:-3]
                else:
                    end = _end
                if end in linksPerNode:
                    linksPerNode[end].append(link[1-i])
                else:
                    linksPerNode[end] = [link[1-i]]

        for node in flattenedNodes:
            portIndex = 2
            if "type" in node and node["type"] == "router":
                router = {}
                router["interface_configs"] = []
                router["late_commands"] = []
                for linkIndex, link in enumerate(linksPerNode[node["name"]]):
                    if link == "EDGE":
                        router["interface_configs"].append({
                            "ip": ip,
                            "port": "p1",
                            "nat": nat,
                            "mac": mac
                        })
                    else:
                        router["interface_configs"].append({
                            "ip": ip,
                            "port": "p%d" % portIndex,
                            "nat": nat,
                            "mac": mac
                        })
                        portIndex += 1
                    router["late_commands"].append(
                        "ethtool -K t<TWIN>_{name}-eth{devId} tso off tx off".format(
                            name=node["name"],
                            devId=linkIndex+1
                        )
                    )
                    router["late_commands"].append(
                        "ip l set dev t<TWIN>_{name}-eth{devId} mtu 1450".format(
                            name=node["name"],
                            devId=linkIndex+1
                        )
                    )
                router["late_commands"].append(
                    "ip route del {subnet} dev t<TWIN>_{name}-eth1".format(
                        subnet=ip[0:-4] + "0/24",
                        name=node["name"]
                    )
                )

                routers[node["name"]] = router
        return routers

    def getHosts(self, flattenedNodes, subnet = "10.0.0.", defaultRoute = None, macprefix="08:00:00:00:00:"):
        hosts = {}
        hostCount = 0
        for node in flattenedNodes:
            if "type" in node and node["type"] == "host":
                host = {}
                host["late_commands"] = []
                if defaultRoute is not None:
                    host["late_commands"].append("ip route add default via " + defaultRoute)
                host["late_commands"].append("ethtool -K t<TWIN>_{name}-eth0 tso off tx off".format(
                    name=node["name"]
                ))
                host["late_commands"].append(
                        "ip l set dev t<TWIN>_{name}-eth0 mtu 1450".format(
                            name=node["name"]
                        )
                    )
                host["ip"] = subnet + str(hostCount+10) + "/24"
                host["mac"] = macprefix + ("%02d" % hostCount)
                host["commands"] = []
                hosts[node["name"]] = host
                hostCount += 1
        return hosts


    def getSwitches(self, flattenedNodes):
        switches = {}
        for node in flattenedNodes:
            if "type" in node and node["type"] == "bridge":
                switches[node["name"]] = { "type": "bridge" }
        return switches


    def getLinks(self, flattenedNodes):
        links = []
        nodeNameMap = {}
        for node in flattenedNodes:
            nodeNameMap[node["name"]] = node
            for link in node["links"]:
                if "edge" in link and link["edge"]:
                    links.append((node["name"], "EDGE"))
                else:
                    links.append((node["name"], self.iidMap[link["_iid"]]["name"]))

        linkCount = {}
        for i, link in enumerate(links):
            skip = False
            for j in range(2):
                if link[j] == "EDGE" and nodeNameMap[link[1-j]]["type"] == "router":
                    links[i] = (link[j], link[1-j] + "-p1")
                    skip = True
            if skip:
                continue
            for j in range(2):
                end = link[j]
                if end != "EDGE" and nodeNameMap[end]["type"] == "router":
                    if end in linkCount:
                        linkCount[end] += 1
                    else:
                        linkCount[end] = 2
                    links[i] = (link[1-j], link[j] + "-p%d" % linkCount[end])
        return links


    def assignNodeNames(self, prefix, flattenedNodes):
        typeCount = {}
        for node in flattenedNodes:
            if "name" not in node and "type" in node:
                if node["type"] not in typeCount:
                    typeCount[node["type"]] = 1
                node["name"] = prefix + "_" + node["type"][0] + str(typeCount[node["type"]])
                typeCount[node["type"]] += 1


    def resolveIds(self, flattenedNodes):
        newList = []
        idMap = {}
        self.iidMap = {}

        for _node in flattenedNodes:
            node = _node
            if "id" in node and "type" in node:
                if node["id"] in idMap:
                    self.printError("Duplicate of id '" + node["id"] + "'")
                    return 1
                idMap[node["id"]] = node
                self.iidMap[node["_iid"]] = node
                newList.append(node)
            elif "id" in node:
                if "nodes" in node:
                    self.printError("Field 'nodes' not allowed in referenced node! (" + node["id"] + ")")
                    return 1
                if node["id"] not in idMap:
                    self.printError("Reference to node id '" + node["id"] + "' leads nowhere!")
                    return 1
                continue
            else:
                self.iidMap[node["_iid"]] = node
                newList.append(node)
            for link in node["links"]:
                if "id" in link:
                    if link["id"] in idMap:
                        link["_iid"] = idMap[link["id"]]["_iid"]
                    del link["id"]
        return newList


    def flattenNodes(self, nodes, currentId = 0, root = True, parentId = {"_iid": -1}):
        listOfNodes = []
        for node in nodes:
            _node = { "links": [] }
            for k, v in node.items():
                if k == "nodes":
                    continue
                _node[k] = v
                _node["parent"] = parentId
                if "type" in node:
                    _node["_iid"] = currentId
                    currentId += 1
            if "nodes" in node:
                flattenedNodes = self.flattenNodes(node["nodes"], currentId, False, {"_iid": _node["_iid"]} if "_iid" in _node else {"id": _node["id"]})
                for _n in flattenedNodes:
                    if "_iid" in _n:
                        if ("_iid" in _node and _n["parent"]["_iid"] == _node["_iid"]) or ("id" in _node and _n["parent"]["id"] == _node["id"]):
                            _node["links"].append({"_iid": _n["_iid"]})
                    elif "id" in _n:
                        if ("_iid" in _node and _n["parent"]["_iid"] == _node["_iid"]) or ("id" in _node and _n["parent"]["id"] == _node["id"]):
                            _node["links"].append({"id": _n["id"]})
                listOfNodes.extend(flattenedNodes)
            if root:
                _node["links"].append({"edge": True})
            listOfNodes.append(_node)
        return listOfNodes


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print "Usage: ./topogen <path-to-template> <path-to-save-dir>"
        sys.exit(1)
    topoGenerator = TopologyGenerator(sys.argv[1])
    topoGenerator.generate()
    topoGenerator.saveToFiles(sys.argv[2])