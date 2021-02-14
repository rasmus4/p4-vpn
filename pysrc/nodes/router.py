from mininet.node import Node

class LinuxRouter(Node):
    def config(self, **kwargs):
        super(LinuxRouter, self).config(**kwargs)
        # Enable forwarding on the router
        self.cmd("sysctl net.ipv4.ip_forward=1")


    def terminate( self ):
        self.cmd("sysctl net.ipv4.ip_forward=0")
        super(LinuxRouter, self).terminate()