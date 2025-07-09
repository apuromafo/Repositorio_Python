#!/usr/bin/python

'''
Copyright 2009, The Android Open Source Project

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
'''

import argparse
import sys
import re
import subprocess
from subprocess import PIPE
from colorama import init, Fore, Style

init(autoreset=True)  # Inicializa colorama

__version__ = '2.1.0'

LOG_LEVELS = 'VDIWEF'
LOG_LEVELS_MAP = {LOG_LEVELS[i]: i for i in range(len(LOG_LEVELS))}
parser = argparse.ArgumentParser(description='Filter logcat by package name')
parser.add_argument('package', nargs='*', help='Application package name(s)')
parser.add_argument('-w', '--tag-width', metavar='N', dest='tag_width', type=int, default=23, help='Width of log tag')
parser.add_argument('-l', '--min-level', dest='min_level', type=str, choices=LOG_LEVELS + LOG_LEVELS.lower(), default='V', help='Minimum level to be displayed')
parser.add_argument('--current', dest='current_app', action='store_true', help='Filter logcat by current running app')
parser.add_argument('-o', '--output', dest='output_file', help='Output file for log')
args = parser.parse_args()

min_level = LOG_LEVELS_MAP[args.min_level.upper()]
package = args.package

# Configuración del comando adb
base_adb_command = ['adb']
if args.current_app:
    system_dump_command = base_adb_command + ["shell", "dumpsys", "activity", "activities"]
    system_dump = subprocess.Popen(system_dump_command, stdout=PIPE, stderr=PIPE).communicate()[0]
    running_package_name = re.search(r".*TaskRecord.*A[= ]([^ ^}]*)", str(system_dump)).group(1)
    package.append(running_package_name)

# Comando para logcat
adb_command = base_adb_command + ['logcat', '-v', 'brief']

# Filtrar las líneas
def colorize(level, message):
    if level == 'V':
        return f"{Fore.WHITE}{message}{Style.RESET_ALL}"
    elif level == 'D':
        return f"{Fore.BLUE}{message}{Style.RESET_ALL}"
    elif level == 'I':
        return f"{Fore.GREEN}{message}{Style.RESET_ALL}"
    elif level == 'W':
        return f"{Fore.YELLOW}{message}{Style.RESET_ALL}"
    elif level in ['E', 'F']:
        return f"{Fore.RED}{message}{Style.RESET_ALL}"
    return message

# Captura de salida
with open(args.output_file, 'w') if args.output_file else sys.stdout as output:
    adb = subprocess.Popen(adb_command, stdout=PIPE)

    while adb.poll() is None:
        line = adb.stdout.readline().decode('utf-8', 'replace').strip()
        if line:
            log_line = re.match(r'^([A-Z])/(.+?)\( *(\d+)\): (.*?)$', line)
            if log_line:
                level, tag, owner, message = log_line.groups()
                if LOG_LEVELS_MAP[level] >= min_level:
                    colored_message = colorize(level, message)
                    output.write(f"{colored_message}\n")
                    if args.output_file:
                        output.flush()