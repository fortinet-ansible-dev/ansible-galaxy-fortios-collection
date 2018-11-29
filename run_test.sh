#!/bin/bash

set -x

cd $( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd )

trap ctrl_c SIGINT
trap ctrl_c SIGTERM

function ctrl_c() {
    echo "** Interrupted by user **"
    echo -e "\n\n Results: \n  Success: "${success}"  Failed: "${failed}"\n"
    exit
}

if [ ! -z $1 ] && [ "$1"="--https" ]; then
  https=true
fi

rm -f $(pwd)/examples/*.retry
rm -f $(pwd)/examples/*.https
rm -f $(pwd)/examples/remove/*.retry
rm -f $(pwd)/examples/remove/*.https

version="v6.0.2"

success=0
failed=0

function modify_playbook_for_https() {
    cat $1 |sed 's/{{ vdom }}"/{{ vdom }}"\n      https: true/g' > $1.https
}

function run_example( ) {
    export ANSIBLE_LIBRARY=$(pwd)/output/${version}/$1

    filename=./examples/$2
    filename_removal=./examples/remove/$2

    if [ "$https" = true ]; then 
        modify_playbook_for_https ${filename}
        ansible-playbook ${filename}.https
        if [ $? == 0 ]; then
          success=$(($success+1))
        else
          failed=$(($failed+1))
        fi
        rm ${filename}.https
    else
        ansible-playbook ${filename}
        if [ $? == 0 ]; then
          success=$(($success+1))
        else
          failed=$(($failed+1))
        fi
    fi

    if [ -f examples/remove/$2 ]; then 
        if [ "$https" == true ]; then 
            modify_playbook_for_https ${filename_removal}
            ansible-playbook ${filename_removal}.https
            if [ $? == 0 ]; then
            success=$(($success+1))
            else
            failed=$(($failed+1))
            fi
            rm ${filename_removal}.https
        else
            ansible-playbook ${filename_removal}
            if [ $? == 0 ]; then
            success=$(($success+1))
            else
            failed=$(($failed+1))
            fi
        fi
    fi
}

run_example application fortios_application_list_example.yml
run_example firewall fortios_firewall_address_example.yml
run_example firewall fortios_firewall_address6_example.yml
run_example firewall fortios_firewall_address6_template_example.yml
run_example firewall fortios_firewall_addrgrp_example.yml
run_example firewall fortios_firewall_policy_example.yml
run_example firewall fortios_firewall_policy46_example.yml
run_example firewall fortios_firewall_policy6_example.yml
run_example firewall fortios_firewall_vip_example.yml
run_example firewall fortios_firewall_vip46_example.yml
run_example ips fortios_ips_sensor_example.yml
run_example system fortios_system_central_management_example.yml
run_example system fortios_system_sdn_connector_example.yml
run_example webfilter fortios_webfilter_content_header_example.yml
run_example webfilter fortios_webfilter_fortiguard_example.yml
run_example webfilter fortios_webfilter_profile_example.yml
run_example webfilter fortios_webfilter_search_engine_example.yml
run_example webfilter fortios_webfilter_urlfilter_example.yml
run_example webfilter fortios_webfilter_ftgd_local_cat_example.yml
run_example webfilter fortios_webfilter_ftgd_local_rating_example.yml
run_example webfilter fortios_webfilter_override_example.yml
run_example webfilter fortios_webfilter_ips_urlfilter_cache_setting_example.yml
run_example webfilter fortios_webfilter_ips_urlfilter_setting_example.yml
run_example webfilter fortios_webfilter_ips_urlfilter_setting6_example.yml

echo -e "\n\n Results: \n  Success: "${success}"  Failed: "${failed}"\n"
