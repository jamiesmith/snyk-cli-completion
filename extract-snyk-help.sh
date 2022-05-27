#!/bin/bash

commands=$(/usr/local/bin/snyk help|grep "^  snyk"| awk '{print $2}'| sort -u)

for command in $commands
do

    echo "##################################################"
    echo "## Command: snyk $command"
    echo "##################################################"
    snyk $command --help | awk '{printf("# %s\n", $0)}'
    echo ""
    echo ""
    echo ""

done
