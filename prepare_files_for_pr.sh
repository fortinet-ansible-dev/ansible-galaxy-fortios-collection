#!/bin/bash


# First, copy examples not included to examples directory, with a suffix (.not_validated)
cd ~/ansible_generator

find . -name "fortios_*example.yml.not_validated" -exec rm {} \;

files=$(find ./output -name "fortios_*example.yml")

for filename in $files; do

   file=$(basename $filename)
   path=$(dirname $filename)
   name=${file%.*}

   if [ -f ./examples/$file ]; then
     echo "File EXCLUDED: $file There is an example already created for it"
   else
     echo "File processed: $file"
     grep "state: \"present\"" $filename
     if [ $? -eq 0 ]; then
       echo "This file is a table $file"
       cp $filename ./examples/$file.not_validated
       cp $filename ./examples/remove/$file.not_validated
     else
       echo "This file is a struct $file"
       cp $filename ./examples/$file.not_validated
     fi
   fi
done


# Second, move each Ansible module to ansible dir and create a branch for it
cd ~/ansible_generator

files=$(find . -name "fortios_*.py")

for filename in $files; do

   file=$(basename $filename)
   path=$(dirname $filename)
   name=${file%.*}

   cd ~/ansible/
   git checkout devel
   git checkout -b new_module_for_$name
   cd ~/ansible_generator
   cp $filename ~/ansible/lib/ansible/modules/network/fortios
   echo Copied file $filename to ansible repo in branch new_module_for_$name

done
