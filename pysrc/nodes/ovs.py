from mininet.node import Switch

class OVS(Switch):
    def __init__(self, name, device_id, **kwargs):
        Switch.__init__(self, name, **kwargs)

    def start(self, controllers):
        pass

    def stop(self, deleteIntfs = True):
        pass