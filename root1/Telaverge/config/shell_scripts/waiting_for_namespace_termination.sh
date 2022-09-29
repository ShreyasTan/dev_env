#!/bin/bash
check_status()
{
        not_found_count=0
        variable=`kubectl get ns | awk '{print$2}' | grep 'Terminating'`
        while [[ -z $variable ]] && [[ $not_found_count -lt 20 ]]
        do
		sleep 1
		echo "Retrying kubectl command"
                variable=`kubectl get ns | awk '{print$2}' | grep 'Terminating'`
                ((not_found_count++))
        done
}
check_status
count=0
while [[ $variable ]]
do
        if [ $count -gt 300 ]  # waiting 5 minutes for namespace to remove
        then
                echo $variable
                echo "shellscript exited with error"
                exit 1
        fi
        sleep 1
	variable=`kubectl get ns | awk '{print$2}' | grep 'Terminating'`
        if [[ -z $variable ]]
        then
                check_status
        fi
        echo $variable
        ((count++))
done
echo $variable
echo "script successfully executed"
