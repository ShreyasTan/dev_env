#!/bin/bash
namespace=mme-hss
check_status()
{
	namespace=$1
        not_found_count=0
        variable=`kubectl get pods -n $namespace | awk '{print$3}' | grep 'Terminating'`
        while [[ -z $variable ]] && [[ $not_found_count -lt 20 ]]
        do
		sleep 1
		echo "Retrying kubectl command"
                variable=`kubectl get pods -n $namespace | awk '{print$3}' | grep 'Terminating'`
                ((not_found_count++))
        done
}
check_status $namespace
count=0
while [[ $variable ]]
do
        if [ $count -gt 300 ]  # waiting 5 minutes for pods to come out from Terminating state
        then
                echo $variable
                echo "shellscript exited with error"
                exit 1
        fi
        sleep 1
	variable=`kubectl get pods -n $namespace | awk '{print$3}' | grep 'Terminating'`
        if [[ -z $variable ]]
        then
                check_status $namespace
        fi
        echo $variable
        ((count++))
done
echo $variable
echo "script successfully executed"
