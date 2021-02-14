BMv2_ARGS = \
	-i 3@veth3 \
	-i 4@veth5 \
	-i 2@veth1 \
	--pcap pcaps \
	--device-id 0 \
	--log-console
SIMPLE_SWITCH_GRPC_ARGS = \
	--cpu-port 1 \
	--grpc-server-addr 0.0.0.0:50051

build : p4src/switch.p4
	p4c-bm2-ss --p4v 16 --p4runtime-files build/switch.p4.p4info.txt -o build/switch.json p4src/switch.p4
	cp build/switch.p4.p4info.txt pysrc/controller/config/switch.p4.p4info.txt
	cp build/switch.json pysrc/controller/config/switch-runtime.json

build-nve : p4src/nve.p4
	p4c-bm2-ss --p4v 16 --p4runtime-files build/switch.p4.p4info.txt -o build/switch.json p4src/nve.p4
	cp build/switch.p4.p4info.txt pysrc/nve_controller/config/switch.p4.p4info.txt
	cp build/switch.json pysrc/nve_controller/config/switch-runtime.json

topogen-% : topos/templates/%.json
	python pysrc/topogenerator/topogen.py topos/templates/$*.json topos/gentopo

run-novirt-p4 : build
	sudo pysrc/run_mininet.py

run-virt-p4 : build-nve
	sudo pysrc/run_mininet.py

run :
	sudo pysrc/run_mininet.py

run-% :
	sudo pysrc/run_mininet.py $*

set-p4nve-cp :
	sed -i 's+// DP LEARNING ENABLED+#define NO_REMOTE_DATA_PLANE_LEARNING+g' p4src/geneve.p4
	sed -i 's+DP_LEARNING = True+DP_LEARNING = False+g' pysrc/nve_controller/controller.py

set-p4nve-dp :
	sed -i 's+#define NO_REMOTE_DATA_PLANE_LEARNING+// DP LEARNING ENABLED+g' p4src/geneve.p4
	sed -i 's+DP_LEARNING = False+DP_LEARNING = True+g' pysrc/nve_controller/controller.py


# Test targets

pretest-p4-evpn-geneve : set-p4nve-cp build-nve

pretest-p4-dp-geneve : set-p4nve-dp build-nve

pretest-no-overlap-p4 : build

pretest-no-overlap :

pretest-vxlan-bridge :


test-p4-evpn-geneve-% : run-%

test-p4-dp-geneve-% : run-%

test-no-overlap-p4-% : run-%

test-no-overlap-% : run-%

test-vxlan-bridge-% : run-%
