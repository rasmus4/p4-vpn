#!/bin/bash

TWIN_COUNTS=(1 2 4 8)
SITE_COUNTS=(2 4 6 8)
NVE_TYPES=("p4-evpn-geneve" "p4-dp-geneve" "vxlan-bridge" "no-overlap" "no-overlap-p4")
RUN_ITERATIONS=5
LOG_FOLDER=testresults/`date +"%Y-%m-%d_%H-%M-%S"`
LOG_FILE=test.log
errors=0
RUNS_PER_NVE_TYPE=$((${#TWIN_COUNTS[@]} * ${#SITE_COUNTS[@]} * ${RUN_ITERATIONS}))

mkdir -p ${LOG_FOLDER}
touch ${LOG_FOLDER}/${LOG_FILE}
echo "Run;Average Goodput Per Host;Total Average Goodput In Network" > ${LOG_FOLDER}/testiperf
echo "Run;Goodput" > ${LOG_FOLDER}/testiperfsinglepair
echo "Run;Time Taken;Percentage" > ${LOG_FOLDER}/testvns

for index in ${!NVE_TYPES[@]}; do
    nve_type=${NVE_TYPES[index]}
    echo "************************************************"
    echo "*** RUNNING TESTS FOR" ${nve_type} "("$((index+1))"/"${#NVE_TYPES[@]}")"
    echo "************************************************"
    sed -i "s+\"nvetype\": .*,+\"nvetype\": \"${nve_type}\",+g" topos/templates/test-template.json
    make pretest-${nve_type}
    run_number_per_nve_type=1
    for twin_count in ${TWIN_COUNTS[@]}; do
        echo "-> Twin count:" ${twin_count}
        sed -i "s+\"twins\": .*,+\"twins\": ${twin_count},+g" topos/templates/test-template.json
        for site_count in ${SITE_COUNTS[@]}; do
            echo "--> Site count:" ${site_count}
            sed -i "s+\"sites\": .*,+\"sites\": ${site_count},+g" topos/templates/test-template.json
            make topogen-test-template
            for i in $(seq 1 ${RUN_ITERATIONS}); do
                echo "---> Iteration:" ${i}/${RUN_ITERATIONS} "("${run_number_per_nve_type}"/"${RUNS_PER_NVE_TYPE} " for this NVE type)"
                sudo venv3.8/bin/python pysrc/run_mininet.py ${LOG_FOLDER}/ ${nve_type}-${twin_count}twins-${site_count}sites-${i} runtests >> ${LOG_FOLDER}/${LOG_FILE} 2>&1
                retVal=$?
                if [ $retVal -ne 0 ]; then
                    echo
                    echo "*** WARNING: run_mininet.py returned non-zero status code! ***"
                    echo
                    errors=$((errors + 1))
                fi
                run_number_per_nve_type=$((run_number_per_nve_type + 1))
            done
        done
    done
    echo
done
