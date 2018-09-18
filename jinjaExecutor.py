#!/usr/bin/python
from jinja2 import Template, Environment, FileSystemLoader
import json


def render_module(schema):
  file_loader = FileSystemLoader('ansible_templates')
  env = Environment (loader=file_loader, lstrip_blocks=False, trim_blocks=False)

  module_name = "webfilter"
  short_description = schema['schema']['help']
  description = ""
  path = schema['path']
  name = schema['name']

  current = schema

  file = open('output/fortios_' + path + '_' + name + '.py', 'w')

  template = env.get_template('doc.jinja')
  output = template.render(**locals())
  file.write(output)

  template = env.get_template('examples.jinja')
  output = template.render(**locals())
  file.write(output)

  template = env.get_template('return.jinja')
  output = template.render(**locals())
  file.write(output)

  template = env.get_template('code.jinja')
  output = template.render(**locals())
  file.write(output)

  print "File generated: " + 'output/fortios_' + path + '_' + name + '.py'

  file.close()


def function():


  fgt_schema_file = open('fgt_schema.json').read()
  fgt_sch = json.loads(fgt_schema_file)['results']

  real_counter = 0
  for i, pn in enumerate(fgt_sch):
    if 'diagnose' not in pn['path'] and 'execute' not in pn['path']:
      print str(real_counter) + ": " + str(i)+": " + " " + pn['path']+'_'+pn['name']
      render_module(fgt_sch[i])
      real_counter += 1

if __name__ == "__main__":

  function()
#  fgt_schema_file = open('fgt_schema.json').read()
#  fgt_sch = json.loads(fgt_schema_file)['results']
#  render_module(fgt_sch[191])

  



