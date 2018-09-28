#!/bin/bash

rm *.py
find ../output/ -name "*.py" -exec cp  {} . \;
echo -e "Run: \n\nexport ANSIBLE_LIBRARY=$(pwd)\n\nansible-playbook ../examples/*.yml\nansible-playbook ../examples/remove/*.yml
"
