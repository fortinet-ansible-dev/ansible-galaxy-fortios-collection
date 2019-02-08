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

run_example antivirus fortios_antivirus_heuristic_example.yml
run_example antivirus fortios_antivirus_profile_example.yml
run_example antivirus fortios_antivirus_quarantine_example.yml
run_example antivirus fortios_antivirus_settings_example.yml
run_example application fortios_application_custom_example.yml
run_example application fortios_application_group_example.yml
run_example application fortios_application_list_example.yml
run_example application fortios_application_name_example.yml
run_example application fortios_application_rule_settings_example.yml
run_example authentication fortios_authentication_rule_example.yml
run_example authentication fortios_authentication_scheme_example.yml
run_example authentication fortios_authentication_setting_example.yml
run_example dlp fortios_dlp_filepattern_example.yml
run_example dlp fortios_dlp_fp_doc_source_example.yml
run_example dlp fortios_dlp_fp_sensitivity_example.yml
run_example dlp fortios_dlp_sensor_example.yml
run_example dlp fortios_dlp_settings_example.yml
run_example dnsfilter fortios_dnsfilter_domain_filter_example.yml
run_example dnsfilter fortios_dnsfilter_profile_example.yml
run_example endpoint_control fortios_endpoint_control_client_example.yml
run_example endpoint_control fortios_endpoint_control_forticlient_ems_example.yml
run_example endpoint_control fortios_endpoint_control_forticlient_registration_sync_example.yml
run_example endpoint_control fortios_endpoint_control_profile_example.yml
run_example endpoint_control fortios_endpoint_control_settings_example.yml
run_example extender_controller fortios_extender_controller_extender_example.yml
run_example firewall fortios_firewall_address_example.yml
run_example firewall fortios_firewall_address6_example.yml
run_example firewall fortios_firewall_address6_template_example.yml
run_example firewall fortios_firewall_addrgrp_example.yml
run_example firewall fortios_firewall_addrgrp6_example.yml
run_example firewall fortios_firewall_auth_portal_example.yml
run_example firewall fortios_firewall_central_snat_map_example.yml
run_example firewall fortios_firewall_dnstranslation_example.yml
run_example firewall fortios_firewall_DoS_policy6_example.yml
run_example firewall fortios_firewall_DoS_policy_example.yml
run_example firewall fortios_firewall_identity_based_route_example.yml
run_example firewall fortios_firewall_interface_policy6_example.yml
run_example firewall fortios_firewall_interface_policy_example.yml
run_example firewall fortios_firewall_internet_service_custom_example.yml
run_example firewall fortios_firewall_internet_service_example.yml
run_example firewall fortios_firewall_internet_service_group_example.yml
run_example firewall_ipmacbinding fortios_firewall_ipmacbinding_setting_example.yml
run_example firewall_ipmacbinding fortios_firewall_ipmacbinding_table_example.yml
run_example firewall fortios_firewall_ippool_example.yml
run_example firewall fortios_firewall_ippool6_example.yml
run_example firewall fortios_firewall_ip_translation_example.yml
run_example firewall fortios_firewall_ipv6_eh_filter_example.yml
run_example firewall fortios_firewall_policy_example.yml
run_example firewall fortios_firewall_policy46_example.yml
run_example firewall fortios_firewall_policy6_example.yml
run_example firewall fortios_firewall_policy64_example.yml
run_example firewall fortios_firewall_vip_example.yml
run_example firewall fortios_firewall_vip46_example.yml
run_example firewall fortios_firewall_vip6_example.yml
run_example firewall fortios_firewall_vip64_example.yml
run_example firewall fortios_firewall_vipgrp_example.yml
run_example firewall fortios_firewall_vipgrp6_example.yml
run_example firewall fortios_firewall_vipgrp46_example.yml
run_example firewall fortios_firewall_vipgrp64_example.yml
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
run_example webfilter fortios_webfilter_content_example.yml


echo -e "\n\n Results: \n  Success: "${success}"  Failed: "${failed}"\n"
