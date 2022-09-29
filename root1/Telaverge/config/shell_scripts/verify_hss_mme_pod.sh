#!/bin/bash
namespace=mme-hss
pod_count=6   # no of pods to be verified as running in given namespace
variable=`kubectl get pods -n $namespace | awk '{print$3}' | grep 'Running' | wc -l`
while [[ $variable -ne $pod_count ]]
do
        if [[ $count -gt 300 ]]  # waiting 5 minutes for pods to come in running state
        then
                echo $variable
                echo "shellscript exited with error, all pods are not in running state"
                exit 1
        fi
        sleep 1
	variable=`kubectl get pods -n $namespace | awk '{print$3}' | grep 'Running'| wc -l`
        echo $variable
        ((count++))
done
echo $variable
echo "script successfully executed"
