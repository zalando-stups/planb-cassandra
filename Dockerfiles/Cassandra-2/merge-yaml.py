#!/usr/bin/env python
import sys
import yaml

#
# Usage: generate-config.py [YAML...]
#

def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')

yaml.SafeDumper.add_representer(type(None), represent_none)

config = {}
for arg in sys.argv[1:]:
    config = dict(config, **yaml.safe_load(arg))

yaml.safe_dump(config, sys.stdout, default_flow_style=False)
