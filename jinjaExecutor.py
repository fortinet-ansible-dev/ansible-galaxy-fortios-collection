#!/usr/bin/python
from jinja2 import Template, Environment, FileSystemLoader
import json


def render_module(schema, version):
  file_loader = FileSystemLoader('ansible_templates')
  env = Environment (loader=file_loader, lstrip_blocks=False, trim_blocks=False)

  short_description = schema['schema']['help']
  description = ""
  path = schema['path']
  name = schema['name']
  module_name = "fortios_" + path + "_" + name

  file = open('output/fortios_' + path + '_' + name + '.py', 'w')
  file_example = open('examples/fortios_' + path + '_' + name + '_example.yml', 'w')

  template = env.get_template('doc.jinja')
  output = template.render(**locals())
  file.write(output)

  template = env.get_template('examples.jinja')
  output = template.render(**locals())
  file.write(output)
  lines = output.splitlines(True)
  file_example.writelines(lines[2:-1])

  template = env.get_template('return.jinja')
  output = template.render(**locals())
  file.write(output)

  template = env.get_template('code.jinja')
  output = template.render(**locals())
  file.write(output)

  print "File generated: " + 'output/fortios_' + path + '_' + name + '.py'

  file.close()
  file_example.close()


def jinjaExecutor():


  fgt_schema_file = open('fgt_schema.json').read()
  fgt_schema = json.loads(fgt_schema_file)
  fgt_sch_results = fgt_schema['results']

  real_counter = 0
  for i, pn in enumerate(fgt_sch_results):
    if 'diagnose' not in pn['path'] and 'execute' not in pn['path']:
      print str(real_counter) + ": " + str(i)+": " + " " + pn['path']+'_'+pn['name']
      render_module(fgt_sch_results[i], fgt_schema['version'])
      real_counter += 1

if __name__ == "__main__":

  #fgt_schema_file = open('fgt_schema.json').read()
  #fgt_schema = json.loads(fgt_schema_file)
  #fgt_sch_results = fgt_schema['results']
  #render_module(fgt_sch_results[191], fgt_schema['version'])
  jinjaExecutor()

  



