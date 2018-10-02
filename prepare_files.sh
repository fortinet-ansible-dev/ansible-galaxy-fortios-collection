#!/bin/bash

set -x

version="v6.0.2"

export ANSIBLE_LIBRARY=$(pwd)/output/${version}/application
echo $ANSIBLE_LIBRARY
ansible-playbook examples/fortios_application_list_example.yml
ansible-playbook examples/remove/fortios_application_list_example.yml

export ANSIBLE_LIBRARY=$(pwd)/output/${version}/firewall
ansible-playbook examples/fortios_firewall_address_example.yml
ansible-playbook examples/remove/fortios_firewall_address_example.yml

export ANSIBLE_LIBRARY=$(pwd)/output/${version}/ips
ansible-playbook examples/fortios_ips_sensor_example.yml
ansible-playbook examples/remove/fortios_ips_sensor_example.yml

export ANSIBLE_LIBRARY=$(pwd)/output/${version}/system
ansible-playbook examples/fortios_system_central_management_example.yml

ansible-playbook examples/fortios_system_sdn_connector_example.yml
ansible-playbook examples/remove/fortios_system_sdn_connector_example.yml

export ANSIBLE_LIBRARY=$(pwd)/output/${version}/webfilter
ansible-playbook examples/fortios_webfilter_profile_example.yml
ansible-playbook examples/remove/fortios_webfilter_profile_example.yml

ansible-playbook examples/fortios_webfilter_urlfilter_example.yml
ansible-playbook examples/remove/fortios_webfilter_urlfilter_example.yml