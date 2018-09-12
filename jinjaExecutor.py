#!/usr/bin/python
from jinja2 import Template, Environment, FileSystemLoader
import json

def function():


  fgt_schema_file = open('fgt_schema.json').read()
  fgt_sch = json.loads(fgt_schema_file)['results']

  real_counter = 0
  for i, pn in enumerate(fgt_sch):
    if 'diagnose' not in pn['path'] and 'execute' not in pn['path']:
      print str(real_counter) + ": " + str(i)+": " + " " + pn['path']+'_'+pn['name']
      real_counter += 1


  current = fgt_sch[191]

  file_loader = FileSystemLoader('ansible_generator')
  env = Environment (loader=file_loader)

  template = env.get_template('doc.jinja')



  module_name = "webfilter"
  short_description = "Configure URL filter lists."
  description = ""
  path = current['path']
  name = current['name']

  output = template.render(**locals())
  print(output)


if __name__ == "__main__":
    function()

  



