#!/bin/bash

set -x

rm -f $(pwd)/examples/*.retry
rm -f $(pwd)/examples/remove/*.retry

version="v6.0.2"

function run_example( ) {
    export ANSIBLE_LIBRARY=$(pwd)/output/${version}/$1
    ansible-playbook examples/$2
    if [ -f examples/remove/$2 ]; then 
        ansible-playbook examples/remove/$2
    fi
}

run_example application fortios_application_list_example.yml
run_example firewall fortios_firewall_address_example.yml
run_example firewall fortios_firewall_addrgrp_example.yml
run_example ips fortios_ips_sensor_example.yml
run_example system fortios_system_central_management_example.yml
run_example system fortios_system_sdn_connector_example.yml
run_example webfilter fortios_webfilter_content_header_example.yml
run_example webfilter fortios_webfilter_fortiguard_example.yml
run_example webfilter fortios_webfilter_profile_example.yml
run_example webfilter fortios_webfilter_search_engine_example.yml
run_example webfilter fortios_webfilter_urlfilter_example.yml



exit