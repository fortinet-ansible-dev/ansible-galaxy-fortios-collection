# Ansible generator

Ansible Generator is an internal tool that is used to help in the process of generating Ansible modules for FortiGate appliances. 

It has to be fed with a Json Schema of the FortiGate whose modules are to be generated.


## Usage

Get a FortiOS schema in json format (REST GET http://<fgt_ip>/api/v2/cmdb?action=schema) and copy it to the root folder of this repo.

Name it: fgt_schema.json

Run:

`./generate.py`

Check the output in ansible_generator/output/vX.X.X
