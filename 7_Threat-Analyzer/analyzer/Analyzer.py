import click
from fastapi import FastAPI
import pyshark
from Evtx import Evtx as evtx
import xml.etree.ElementTree as ET
import requests
import json
import re                           
import os                           

from styles import bcolors as sty   # cool cli output
from datetime import datetime       # event creation

import inspect                      # wrapper
from functools import wraps         # wrapper
import threading                    # logs


# Main grupa
@click.group()
def main():
    pass


### GLOBAL VARIABLES ###

files = {".txt": [], ".json": [], ".xml": [], ".evtx": [], ".pcap": []}

PCAP_OPTIONS = {"s": "show", "f": "filter"}

LOG_OPTIONS = {"n": "none", "g": "grep", "r": "regular expression"}

LOG_FILE        = "output/analyzer.log"

### Log handlers

def loggable(func):
    """
    Decorator to print function call details.

    This includes parameters names and effective values.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        func_args = inspect.signature(func).bind(*args, **kwargs).arguments
        func_args_str = ", ".join(map("{0[0]} = {0[1]!r}".format, func_args.items()))
        write_to_log(f"Executed {__file__.split('\\')[-1].split('.')[0]}.{func.__qualname__} ( {func_args_str} )")
        return func(*args, **kwargs)

    return wrapper

def create_logfile():
    if os.path.exists(LOG_FILE):
        return
    with open(LOG_FILE, 'w') as _:
        pass  
    
def write_to_log(message: str):
    log_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3] # trimming to miliseconds
    thread_id = threading.current_thread().ident
    message = f'[{log_time}] INFO [{thread_id}] - {message}\n'
    
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(message)

### Sending alerts to EventCollector ###

class Event:

    def __init__(self, rule_name: str, source_file: str, description: str) -> None:
        self.rule_name = rule_name
        self.source_file = source_file
        self.description = description
   
def send_data_to_collector(event: Event):
    url = "http://localhost:8000/upload"

    if requests.post(url, data=json.dumps(event.__dict__)).status_code == 200:
        print("Event successfully uploaded to Event Collector")
    else:
        print("Event upload failed - error on Server")

# TASK 1
@main.command()
@click.option(
    "-p", "--path", multiple=True, prompt="File path:", help="Enter file path"
)
@click.option(
    "-o",
    "--option",
    type=click.Choice(PCAP_OPTIONS.keys()),
    default="s",
    help="Available commands: s - show | f - filter",
)
@click.option(
    "-f",
    "--filter",
    default=None,
    help="Enter by what value you want to filter the pcap file",
)
@loggable
def pcap_analyze(path: str, option: str, filter: str) -> None:
    """View and filter content of .pcap files"""
    
    def stop_printing() -> bool:
        """Simple method checking whether user wants to stop the printing process

        Returns:
            bool: True, if user wants to stop the printing process, False otherwise
        """
        user_input = input("Press Q to quit or any other key to continue: ")
        return user_input.lower() == "q"

    check_files(path, ".pcap")
    opened_files_list = files[".pcap"]
    print(f"Printing contents of the following files: {', '.join(opened_files_list)}")
    if stop_printing:
        exit

    for file in opened_files_list:
        print("#" * 35 + file + "#" * 35)
        pcap_source = (
            pyshark.FileCapture(file)
            if option == "s"
            else pyshark.FileCapture(file, display_filter=filter)
        )
        with pcap_source as pcap:
            i = 0
            for packet in pcap:
                print(packet)
                i += 1
                if i == 9:
                    i = 0
                    if stop_printing():
                        break

        print(f"Finished printing {file}")
        if stop_printing():
            break

    print("Finished printing files")


# TASK 2
@main.command()
@click.option(
    "-p", "--path", multiple=True, prompt="File path:", help="Enter file path"
)
@click.option(
    "-o",
    "--option",
    type=click.Choice(LOG_OPTIONS.keys()),
    default="n",
    help="Available commands: n - none | g - grep | r - regular expression",
)
@click.option(
    "-a", 
    "--pattern", 
    default="[\\s\\S]*",
    help="Enter pattern you want to search by. Ignored if option = n"
)
@loggable
def log_analyze(path: str, option: str, pattern: str):
    """Search trough log files (XML/JSON/EVTX/TXT)"""
    extension_list = list(files.keys())
    check_files(path, extension_list)
    
    if ".evtx" in extension_list:
        for current_file in files[".evtx"]:
            with evtx.Evtx(current_file) as opened_file_operator:
                root = ET.Element("Events")
                for record in opened_file_operator.records():
                    xml = record.xml()
                    event_element = ET.fromstring(xml)
                    root.append(event_element)
            tree = ET.ElementTree(root)
            xml_file_name = f'{current_file[:-5]}-{hash(tree)}.xml'
            tree.write(
                xml_file_name, encoding="utf-8", xml_declaration=True
            )
            files[".xml"].append(xml_file_name)
        

    extension_list.remove('.evtx')
    extension_list.remove('.pcap')
    
    if option == "n":
        pattern = "[\\s\\S]*"

    for extension in extension_list:
        if option == "r":
            pattern = re.compile(pattern)
        for file in files[extension]:
            print(30*'#'+' ' +file+' '+30*'#')
            with open(file, "r") as f:
                for line in f:
                    if re.search(pattern, line):
                        print(line)


########
# TASK 3#
########
@main.command()
@click.option(
    "-p", 
    "--path",  
    multiple=True, 
    prompt="File path:",
    help="Path to file to apply the rules on"
    )
@click.option(
    "-r", 
    "--rules_names",   
    multiple=True,
    default=[], 
    help="Rules to apply on passed files"
)
@loggable
def apply_rules(path: list, rules_names: list):
    """Apply rules from detection_rules.py files to specified files"""
    RULES_SOURCE = 'detection_rules.py'
    LOADED_RULES = []
    loaded_methods = ""
    
    with open(RULES_SOURCE, 'r') as file:
        all_methods = file.read().splitlines() 
        
    for i in range(len(all_methods)):
        line = all_methods[i]
        if line.startswith('def '):
            # gets the method name
            def_split = line.split(' ')
            method_name = def_split[1].split('(')[0]
            
            if (method_name in rules_names) or (not rules_names):
                LOADED_RULES.append(method_name)
                # read method's body
                loaded_methods += line # add definition
                loaded_methods += '\n' # add definition
                for j in range(i+1, len(all_methods)):
                    next_line = all_methods[j]
                    if next_line.startswith('def '):
                        break
                    loaded_methods += next_line
                    loaded_methods += '\n'
                    
    if len(LOADED_RULES) == 0:
        print(f'Passed rules were not found. Aborting!')
        exit()
    
    if len(rules_names)>0 and len(rules_names) != len(LOADED_RULES):
        print(f'Some rules were {sty.WARNING}not found{sty.ENDC}.')
        print(f"Rules that were found are: {sty.OKBLUE}{f'{sty.ENDC},{sty.OKBLUE} '.join(LOADED_RULES)}{sty.ENDC}")
        user_input = input(f'Press Q to quit or any other key to continue: ')
        if user_input.lower() == 'q':
            exit()
            
    exec(loaded_methods, locals())
    check_files(path, files.keys())
    
    files_to_scan = []
    
    for extension in files.keys():
        for key in files[extension]:
            files_to_scan.append(key)
        

    write_to_log(f"Analyzer.apply_rules(): rules {', '.join([f"'{_}'" for _ in LOADED_RULES])} will be applied on {', '.join([f"'{_}'" for _ in files_to_scan])}")
    
    print(f"Rule(s) {sty.OKBLUE}{f'{sty.ENDC},{sty.OKBLUE} '.join(LOADED_RULES)}{sty.ENDC} will be applied on {sty.OKBLUE}{f'{sty.ENDC},{sty.OKBLUE} '.join(files_to_scan)}{sty.ENDC}")
    
    for rule_name in LOADED_RULES:
        print(f'Running {sty.OKGREEN}{rule_name}{sty.ENDC}')
        results = locals()[rule_name](**files)
        
        for event in results:
            cli_message = f'{sty.FAIL}[ALERT]{sty.ENDC} Rule {sty.OKBLUE}{rule_name}{sty.ENDC} detected an event in {sty.OKBLUE}{event["source"]}{sty.ENDC}: {event["description"]}'
            log_message = f"Analyzer.apply_rules(): Rule '{rule_name}' detected an event in '{event["source"]}': '{event["description"]}'"
            print(cli_message)
            write_to_log(log_message)                
            if event["action_alert"] == 'remote':
                send_data_to_collector(Event(rule_name, event["source"], event["description"]))
                log_message = f"Analyzer.apply_rules(): sent event (detected by '{rule_name}' in '{event["source"]}') to Event Collector'"
                write_to_log(log_message)             
                
                
        print(f'Executed {sty.OKGREEN}{rule_name}{sty.ENDC} on all files\n')


######################
####### TASK 4 #######
######################
@main.command()
@click.option(
    "-p", 
    "--path", 
    multiple=True, 
    prompt="File path:", 
    help="Enter file path"
)
@click.option(
    "-r",
    "--rule",
    multiple=True,
    prompt = "Rule/Rules to run: ",
    help="Enter a rule or rules to run",
)
@loggable
def sigma_analyze(path: str, rule: str):
    """"Analyze files with specified Sigma rules"""
    PATH_TO_ZIRCOLITE           = 'zircolite/zircolite.py'
    PATH_TO_ZIRCOLITE_CONFIG    = 'zircolite/config/fieldMappings.json'
    PATH_TO_ZIRCOLITE_RULES     = 'zircolite/rules/'
    PATH_TO_ZIRCOLITE_OUTPUT    = 'output/'
    PATH_TO_ZIRCOLITE_RESULTS   = f'output/zircolite-results-{datetime.now().strftime("%Y_%m_%d_AT_%H_%M_%S")}.txt'
    
    
    extension_list = list(files.keys())
    extension_list.remove(".txt")
    extension_list.remove(".pcap")
    
    check_files(path, extension_list)
    
    for _file in files[".evtx"]:
        for _rule in rule:
          
            if not os.path.isfile(_rule):
                print("Invalid path to rule / rule name!")
                break
                
            run_zircolite = f"python {PATH_TO_ZIRCOLITE} --config {PATH_TO_ZIRCOLITE_CONFIG} \
                    --outfile {PATH_TO_ZIRCOLITE_OUTPUT}zircolite_detected_events.json \
                        --logfile {PATH_TO_ZIRCOLITE_OUTPUT}zircolite.log \
                            --evtx {_file} \
                                --ruleset {_rule} > {PATH_TO_ZIRCOLITE_RESULTS}"
            
            os.system(run_zircolite)
            write_to_log(f"Analyzer.sigma-analyze(): executed '{run_zircolite}'")
            
            # pretty print for Windows
            os.system(f"type {PATH_TO_ZIRCOLITE_RESULTS.replace('/','\\')}")
            
            with open(PATH_TO_ZIRCOLITE_RESULTS, 'r') as file:
                zircolite_results = file.readlines()
                alert_list = []    
                for line in zircolite_results:
                    line = re.sub(r'\.*?m', "", line)
                    line = re.sub(r'\s{2,}', "", line)
                    line = line.strip()
                    alert_list.append(line)
            
            for alert in alert_list:
                log_message = f"Analyzer.sigma-analyze(): rule '{_rule}' detected an event in '{_file}': {alert}"
                write_to_log(log_message)
                    
            with open(PATH_TO_ZIRCOLITE_RESULTS, "w") as result_file:
                alert_list = "\n".join(alert_list)
                result_file.write(alert_list)
            
            
                    
            send_data_to_collector(Event(_rule, _file, alert_list))
            log_message = f"Analyzer.apply_rules(): sent event(s) (detected by '{_rule}' in '{_file}') to Event Collector'"
            write_to_log(log_message)             





######################
### FILES CHECKING ###
######################
def check_files(path, extensions_list):
    if len(path) >= 2:
        for path_loaded in path:
            __load_files(path_loaded, extensions_list)
    else:
        __load_files(path[0], extensions_list)


def __load_files(path, extensions_list):
    if os.path.isdir(path):
        for element in os.listdir(path):
            specific_element_path = os.path.join(path, element)
            if os.path.isfile(specific_element_path):
                file_name, extension = os.path.splitext(element)
                if extension in extensions_list:
                    files[extension].append(path + "\\" + file_name + extension)
            elif os.path.isdir(specific_element_path):
                __load_files(specific_element_path, extensions_list)
    else:
        file_name, extension = os.path.splitext(path)
        files[extension].append(file_name + extension)


if __name__ == "__main__":
    create_logfile()
    main()