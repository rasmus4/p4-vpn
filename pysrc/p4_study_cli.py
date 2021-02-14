from mininet.cli import CLI
from mininet.log import info, output, error
from mininet.util import quietRun
from nodes.p4nve import P4NVE
import threading
import networkx as nx
import matplotlib.pyplot as plot
import re
import time
import statistics

class StudyCLI(CLI):
    class TestVNSThread(threading.Thread):
        def __init__(self, execNode, ip, port, expected, resultMap, resultMapKey, proto="TCP"):
            threading.Thread.__init__(self)
            self.execNode = execNode
            self.ip = ip
            self.port = port
            self.expected = expected
            self.resultMap = resultMap
            self.resultMapKey = resultMapKey
            self.proto = proto

        def run(self):
            clientCmd = "python3 pysrc/node_utils/client.py " +\
                self.ip + " " +\
                self.port + " " +\
                self.expected + " " +\
                self.proto
            out, err, code = self.execNode.pexec(clientCmd)

            #output(clientCmd)

            if code != 0:
                self.resultMap[self.resultMapKey] = code
                #output(" Failed!\nerr: " + err + "\nout: " + out + "\n")
                #output(" .. failed")
                out, _, _ = self.execNode.pexec("ifconfig")
                #output(" (" + out + ")\n")
            else:
                self.resultMap[self.resultMapKey] = code
                #output(" OK\n")
                #output(" .. ok\n")

    class TestVNSServerThread(threading.Thread):
        def __init__(self, execNode, port, expected, proto):
            threading.Thread.__init__(self)
            self.execNode = execNode
            self.port = port
            self.expected = expected
            self.proto = proto

        def run(self):
            serverCmd = "python3 pysrc/node_utils/server.py " + str(self.port) + " " + self.expected + " " + self.proto
            res = self.execNode.cmd(serverCmd)
            #output(res + "\n")

    class TestIPerfClientThread(threading.Thread):
        def __init__(self, execNode, proto, address):
            threading.Thread.__init__(self)
            self.execNode = execNode
            self.proto = proto
            self.address = address

        def run(self):
            cmd = "iperf -c " + self.address + (" -u" if self.proto == "UDP" else "")
            #output("Running '" + cmd + "' .. ")
            output(self.execNode.name + ": " + cmd + "\n")
            self.execNode.pexec(cmd)
            #output(res + "\n")

    def __init__(self, mininet, testResultsFolder="testresults", nameOfTestRun="default", running=True):
        self.nameOfTestRun = nameOfTestRun
        self.testResultsFolder = testResultsFolder
        self.running = running
        super().__init__(mininet)

    def run(self):
        while self.running:
            try:
                # Make sure no nodes are still waiting
                for node in self.mn.values():
                    while node.waiting:
                        info( 'stopping', node, '\n' )
                        node.sendInt()
                        node.waitOutput()
                if self.isatty():
                    quietRun( 'stty echo sane intr ^C' )
                self.cmdloop()
                break
            except KeyboardInterrupt:
                # Output a message - unless it's also interrupted
                # pylint: disable=broad-except
                try:
                    output( '\nInterrupt\n' )
                except Exception:
                    pass
                # pylint: enable=broad-except

    def do_showgraph(self, line):
        graph = nx.Graph()
        labels = {}
        for host in self.mn.hosts:
            graph.add_node(host.name)
            labels[host.name] = host.name
            #for intf in host.intfList():
            #    if intf.IP() is not None:
            #        labels[host.name] += "\n" + intf.name + ": " + intf.IP()
        for switch in self.mn.switches:
            graph.add_node(switch.name)
            labels[switch.name] = switch.name
        for link in self.mn.links:
            graph.add_edge(link.intf1.node.name, link.intf2.node.name)
        #pos = nx.spring_layout(graph)
        nx.draw(graph, with_labels=True, labels=labels, node_color="#94afff")
        plot.show(block=False)

    def do_dumpnvetables(self, line):
        for switch in self.mn.switches:
            if isinstance(switch, P4NVE):
                output("*** " + switch.name + " ***\n")
                output(switch.controller.tables)

    def do_dumpbgpstates(self, line):
        for switch in self.mn.switches:
            if isinstance(switch, P4NVE):
                output("*** " + switch.name + " ***\n")
                output(switch.controller.bgpspeaker.connection_thread.bgp_connections)

    def do_p4vnimappings(self, line):
        for switch in self.mn.switches:
            if isinstance(switch, P4NVE):
                output("*** " + switch.name + " ***\n")
                output(switch.controller.getVNIMappings() + "\n")

    def do_p4arpproxymappings(self, line):
        for switch in self.mn.switches:
            if isinstance(switch, P4NVE):
                output("*** " + switch.name + " ***\n")
                output(switch.controller.getARPProxyMappings() + "\n")

    def do_p4dmacvni(self, line):
        for switch in self.mn.switches:
            if isinstance(switch, P4NVE):
                output("*** " + switch.name + " ***\n")
                output(switch.controller.getDmacVNI() + "\n")

    def do_p4vninexthopmappings(self, line):
        for switch in self.mn.switches:
            if isinstance(switch, P4NVE):
                output("*** " + switch.name + " ***\n")
                output(switch.controller.getVNINextHopMappings() + "\n")

    def do_testtcp(self, line):
        host1, host2 = line.split()
        self._testconnectivity(host1, host2, "TCP")

    def do_testudp(self, line):
        host1, host2 = line.split()
        self._testconnectivity(host1, host2, "UDP")

    def _testconnectivity(self, host1, host2, proto):
        resultMap = {}
        #serverCmd = "python3 pysrc/node_utils/server.py " + str(self.testvnsport) + " " + host1 + " " + proto + " &"
        #self.mn.nameToNode[host1].cmd(serverCmd)
        serverThread = StudyCLI.TestVNSServerThread(
            self.mn.nameToNode[host1],
            self.testvnsport,
            host1,
            proto
        )
        serverThread.start()
        testThread = StudyCLI.TestVNSThread(
            self.mn.nameToNode[host2],
            str(self.mn.nameToNode[host1].IP()),
            str(self.testvnsport),
            host1,
            resultMap,
            host1 + "<=>" + host2,
            proto
        )
        testThread.start()
        self.testvnsport += 1
        serverThread.join()
        testThread.join()

        for pair, code in resultMap.items():
            output("    " + pair + (" OK\n" if code == 0 else " Failed!\n"))


    def do_testiperf(self, line):
        proto = "TCP"
        seq = False
        if "udp" in line:
            proto = "UDP"
        if "seq" in line:
            seq = True

        vns = []
        testThreads = []
        clientsPerServer = {}
        serversStarted = 0
        for vn in self.mn.vns:
            systemMap = {}
            for host in vn["hosts"]:
                if host[-2:] == "r1":
                    continue
                m = re.search(r"t\d+_(.+)_.+", host)
                if m is None:
                    output("Invalid host name: '" + host + "'\n")
                    return
                if m.group(1) in systemMap:
                    systemMap[m.group(1)].append(host)
                else:
                    systemMap[m.group(1)] = [host]
                    cmd = "iperf -s -y c 2>&1 | tee " + host + ".csv"
                    output(host + ": " + cmd + "\n")
                    self.mn.nameToNode[host].sendCmd(cmd)
                    serversStarted += 1
                    #output("Start server on '" + host + "'\n")
                    clientsPerServer[host] = 0
            vns.append(systemMap)
        for systemMap in vns:
            for systemName, system in systemMap.items():
                if len(system) == 1: # Only one host in system, dont start client!
                    output("Warning: System " + systemName.upper() + " has only one host! Skipping iperf -c on this system.\n")
                    continue
                else:
                    testHost = system[1]
                for systemName2, system2 in systemMap.items():
                    if systemName == systemName2:
                        continue
                    system2addr = str(self.mn.nameToNode[system2[0]].IP())
                    #self.mn.nameToNode[testHost].sendCmd("iperf -c" + system2addr)
                    testThread = StudyCLI.TestIPerfClientThread(self.mn.nameToNode[testHost], proto, system2addr)
                    testThread.start()
                    testThreads.append(testThread)
                    clientsPerServer[system2[0]] += 1

        cancel = False
        if len(testThreads) == 0:
            output("No iperf clients were started..\n")
            cancel = True

        # Wait for clients to finish
        for index, t in enumerate(testThreads):
            t.join()
            output("\r" + str(index+1) + "/" + str(len(testThreads)) + " clients finished")
        output("\n")

        goodputs = []
        # Kill remaining iperf servers
        serversKilled = 0
        for systemMap in vns:
            for system in systemMap.values():
                while not cancel and clientsPerServer[system[0]] > 0:
                    out = self.mn.nameToNode[system[0]].monitor()
                    results = re.findall(r"\d{14},\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3},\d+,\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3},\d+,\d+,.+?,(\d+),(\d+)", out)
                    if len(results) == 0:
                        output("Warning: len(results) == 0\nout: " + out + "\n")
                    for result in results:
                        goodputs.append(int(result[1]))
                        clientsPerServer[system[0]] -= 1

                self.mn.nameToNode[system[0]].sendInt()
                out = self.mn.nameToNode[system[0]].monitor()
                if "Waiting" in out:
                    self.mn.nameToNode[system[0]].sendInt()
                    out = self.mn.nameToNode[system[0]].monitor()
                if self.mn.nameToNode[system[0]].waiting:
                    #output("Warning: Interrupt '" + system[0] + "': '" + out + "', waiting: " + str(self.mn.nameToNode[system[0]].waiting) + "\n")
                    # TODO some nodes are marked as waiting, i.e. EOF is not seen on monitor() after CTRL+C. Why?
                    self.mn.nameToNode[system[0]].sendInt()
                    self.mn.nameToNode[system[0]].waiting = False
                serversKilled += 1
                output("\r" + str(serversKilled) + "/" + str(serversStarted) + " servers killed")
        output("\n")
        if not cancel:
            avgGoodputPerHost = round(statistics.mean(goodputs)/1000000.0, 3)
            totalAvgGoodputInNet = round(sum(goodputs)/1000000.0, 3)
            output("Avg goodput per host     : " + str(avgGoodputPerHost) + " Mb/s\n")
            output("Total avg goodput in net : " + str(totalAvgGoodputInNet) + " Mb/s\n")
            if self.nameOfTestRun != "default":
                with open(self.testResultsFolder + "/testiperf", "a") as f:
                    f.write("{runName};{avgGoodputPerHost};{totalAvgGoodputInNet}\n".format(
                        runName = self.nameOfTestRun,
                        avgGoodputPerHost = str(avgGoodputPerHost),
                        totalAvgGoodputInNet = str(totalAvgGoodputInNet)
                    ))

    def do_testiperfsinglepair(self, line):
        proto = "TCP"
        if "udp" in line:
            proto = "UDP"

        testThreads = []
        serversStarted = 0

        cmd = "iperf -s -y c 2>&1 | tee " + "t0_a_h1-singlepair" + ".csv"
        output("t0_a_h1" + ": " + cmd + "\n")
        self.mn.nameToNode["t0_a_h1"].sendCmd(cmd)
        serversStarted += 1

        system2addr = str(self.mn.nameToNode["t0_a_h1"].IP())
        testThread = StudyCLI.TestIPerfClientThread(self.mn.nameToNode["t0_b_h1"], proto, system2addr)
        testThread.start()
        testThreads.append(testThread)

        cancel = False
        if len(testThreads) == 0:
            output("No iperf clients were started..\n")
            cancel = True

        # Wait for clients to finish
        for index, t in enumerate(testThreads):
            t.join()
            output("\r" + str(index+1) + "/" + str(len(testThreads)) + " clients finished")
        output("\n")

        goodputs = []
        # Kill remaining iperf servers
        done = False
        while not cancel and not done:
            out = self.mn.nameToNode["t0_a_h1"].monitor()
            results = re.findall(r"\d{14},\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3},\d+,\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3},\d+,\d+,.+?,(\d+),(\d+)", out)
            if len(results) == 0:
                output("Warning: len(results) == 0\nout: " + out + "\n")
            for result in results:
                goodputs.append(int(result[1]))
                done = True

        self.mn.nameToNode["t0_a_h1"].sendInt()
        out = self.mn.nameToNode["t0_a_h1"].monitor()
        if "Waiting" in out:
            self.mn.nameToNode["t0_a_h1"].sendInt()
            out = self.mn.nameToNode["t0_a_h1"].monitor()
        if self.mn.nameToNode["t0_a_h1"].waiting:
            #output("Warning: Interrupt '" + system[0] + "': '" + out + "', waiting: " + str(self.mn.nameToNode[system[0]].waiting) + "\n")
            # TODO some nodes are marked as waiting, i.e. EOF is not seen on monitor() after CTRL+C. Why?
            self.mn.nameToNode["t0_a_h1"].sendInt()
            self.mn.nameToNode["t0_a_h1"].waiting = False
        if not cancel:
            goodput = round(goodputs[0]/1000000.0, 3)
            output("Goodput: " + str(goodput) + " Mb/s\n")
            if self.nameOfTestRun != "default":
                with open(self.testResultsFolder + "/testiperfsinglepair", "a") as f:
                    f.write("{runName};{goodput}\n".format(
                        runName = self.nameOfTestRun,
                        goodput = str(goodput) # (Mb/s)
                    ))

    def do_testvns(self, line):
        if not hasattr(self, "testvnsport"):
            self.testvnsport = 8000

        proto = "TCP"
        seq = False
        if "udp" in line:
            proto = "UDP"
        if "seq" in line:
            seq = True

        successful = 0
        total = 0
        testThreads = []
        resultMap = {}
        for vn in self.mn.vns:
            output("*** Testing " + vn["VNID"] + " (" + str(len(vn["hosts"])) + " hosts) ***\n")
            for host1 in vn["hosts"]:
                for host2 in vn["hosts"]:
                    if host1 == host2:
                        continue
                    serverCmd = "python3 pysrc/node_utils/server.py " + str(self.testvnsport) + " " + host1 + " " + proto + " &"
                    #output(serverCmd + "\n")
                    self.mn.nameToNode[host1].cmd(serverCmd)
                    testThread = StudyCLI.TestVNSThread(self.mn.nameToNode[host2], str(self.mn.nameToNode[host1].IP()), str(self.testvnsport), host1, resultMap, host1 + "<=>" + host2, proto)
                    #testThread.start()
                    testThreads.append(testThread)
                    total += 1
                    self.testvnsport += 1
                    if seq:
                        testThread.join()
        startTime = time.time()

        for t in testThreads:
            t.start()

        for t in testThreads:
            t.join()

        finishTime = time.time()

        for pair, code in resultMap.items():
            output("    " + pair + (" OK\n" if code == 0 else " Failed!\n"))
            if code == 0:
                successful += 1


        output(
            "*** Result: " +
            str(round(100.0*successful/total, 1)) +
            "% [" + str(successful) + "/" + str(total) + "]" +
            " in " + str(round(finishTime-startTime, 4)) + " seconds ***\n")
        if self.nameOfTestRun != "default":
            with open(self.testResultsFolder + "/testvns", "a") as f:
                f.write("{runName};{elapsedTime};{percentage}\n".format(
                    runName = self.nameOfTestRun,
                    elapsedTime = str(round(finishTime-startTime, 4)),
                    percentage = str(round(100.0*successful/total, 1))
                ))
