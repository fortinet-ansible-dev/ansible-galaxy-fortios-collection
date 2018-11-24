#!/usr/bin/python
from jinja2 import Template, Environment, FileSystemLoader
import json
import autopep8
import os


def searchProperBreakableChar(line, startingPosition):
    breakableChars = " :.,;"
    for i in reversed(range(0, startingPosition)):
        if line[i] in breakableChars:
            return i
    return startingPosition


def numberOfInitialSpaces(line):
    return len(line)-len(line.lstrip())+2


def splitLargeLines(output):
    output = output.splitlines()
    for i in range(0, len(output)):
        line = output[i]
        if len(line) > 159:
            position = searchProperBreakableChar(line, 159)
            initialSpaces = " " * numberOfInitialSpaces(output[i])
            output.insert(i+1, initialSpaces + line[position:])
            output[i] = output[i][:position]
    output = '\n'.join(output)
    return output


def render_module(schema, version):

    file_loader = FileSystemLoader('ansible_templates')
    env = Environment(loader=file_loader,
                      lstrip_blocks=False, trim_blocks=False)

    short_description = schema['schema']['help'][:-1] + " in Fortinet's FortiOS and FortiGate."
    description = ""
    original_path = schema['path']
    original_name = schema['name']
    path = original_path.replace('-', '_')
    name = original_name.replace('-', '_')
    module_name = "fortios_" + path + "_" + name

    template = env.get_template('doc.jinja')
    output = template.render(**locals())

    template = env.get_template('examples.jinja')
    output += template.render(**locals())

    template = env.get_template('return.jinja')
    output += template.render(**locals())

    template = env.get_template('code.jinja')
    output += template.render(**locals())

    dir = 'output/' + version + '/' + path
    if not os.path.exists(dir):
        os.makedirs(dir)

    file = open('output/' + version + '/' + path + '/fortios_' + path + '_' + name + '.py', 'w')
    output = splitLargeLines(output)
    output = autopep8.fix_code(output, options={'aggressive': 1, 'max_line_length': 160})
    file.write(output)
    file.close()

    file_example = open('output/' + version + '/' + path + '/fortios_' + path +
                        '_' + name + '_example.yml', 'w')
    template = env.get_template('examples.jinja')
    output = template.render(**locals())
    lines = output.splitlines(True)
    file_example.writelines(lines[2:-1])
    file_example.close()

    print "\033[0mFile generated: " + 'output/' + version + '/\033[37mfortios_' + path + '_' + name + '.py'
    print "\033[0mFile generated: " + 'output/' + version + '/\033[37mfortios_' + path + '_' + name + '_example.yml'


def jinjaExecutor():

    fgt_schema_file = open('fgt_schema.json').read()
    fgt_schema = json.loads(fgt_schema_file)
    fgt_sch_results = fgt_schema['results']

    real_counter = 0
    for i, pn in enumerate(fgt_sch_results):
        if 'diagnose' not in pn['path'] and 'execute' not in pn['path']:
            print '\n\033[0mParsing schema:'
            print '\033[0mModule name: \033[92m' + pn['path']+'_'+pn['name']
            print '\033[0mIteration:\033[93m' + str(real_counter) + "\033[0m, Schema position: \033[93m" + str(i)
            render_module(fgt_sch_results[i], fgt_schema['version'])
            real_counter += 1


if __name__ == "__main__":

    fgt_schema_file = open('fgt_schema.json').read()
    fgt_schema = json.loads(fgt_schema_file)
    fgt_sch_results = fgt_schema['results']
    # render_module(fgt_sch_results[166], fgt_schema['version'])
    jinjaExecutor()
