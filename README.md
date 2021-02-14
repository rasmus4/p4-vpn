# P4 VPN

This repository contains the source code for the implementations used by in the thesis "Creating Digital Twin Distributed Networks Using Switches With Programmable Data Plane".

This repository contains p4runtime_lib (in the directory tutorials) from the [p4lang/tutorials](https://github.com/p4lang/tutorials) repository, converted to Python 3.

# Running the tests

`./runtests.sh`

# Using the Mininet environment

- `make build-nve` - Build the p4src/nve.p4 program.

- `make set-p4nve-cp` - Set the P4 virtualisation variant to the one with control plane based remote MAC learning.

- `make set-p4nve-dp` - Set the P4 virtualisation variant to the one with data plane based remote MAC learning.

- `make build` - Build the p4src/switch.p4 program.

- `make topogen-%` Generate the topology file `topos/gentopo/topology.json` from a template.

- `make run` - Run the Mininet environment with the topology `topos/gentopo/topology.json`

# Disabling ARP Proxy

1. Set `ARP_PROXY = True` in `pysrc/nve_controller/controller.py`
2. Uncomment `#define NO_ARP_PROXY` in `p4src/geneve.p4`
