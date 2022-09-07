"""
Wrapper over NDS loader.
- Nikki
"""

# Boilerplate
import os
import sys
if sys.version_info[0] != 3 or sys.version_info[1] < 10:
    Exception("Please update your python installation to 3.10.x or higher.")
script_name = os.path.basename(__file__)
script_path = os.path.realpath(__file__)
script_path = script_path.removesuffix(script_name) + "../nds"
sys.path.insert(0, script_path)
#

import loader

def accept_file(li, filename):
    return loader.accept_file_impl(li, filename)

def load_file(li, neflags, format):
    return loader.load_file_impl(li, neflags, format)