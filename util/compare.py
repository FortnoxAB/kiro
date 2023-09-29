import os
import time
import re
import json
from util.send_slack_message import send_slack_message
from util.is_valid_ip import is_valid_ip

class port_object:
    portid = ""
    service_name = ""
    service_tunnel = ""

    def __init__(self, obj):
        self.portid = obj.get("portid") 
        self.service_name = get_value_if_key_exists(obj.get("service"), "name")
        self.service_tunnel = get_value_if_key_exists(obj.get("service"), "tunnel")


def find_files_to_compare(max_files: int):
    counter = 0
    files = []
    my_files = [filename for filename in os.listdir(".") if filename.startswith("netmon_")]
    for entry in sorted(my_files, reverse=True):
        counter = 1
        files.append(entry)
        if counter == max_files:
            break

    return files    


def find_portid_position(port_list, portid_to_find):
    position = -1
    for index, port in enumerate(port_list):
        if port["portid"] == portid_to_find:
            position = index
            break
    return position


def get_value_if_key_exists(object, key):
    if key in object:
        return object.get(key)
    return ""


def print_diff(current_ip, key, current_values, previous_values):
    if key in current_values:
        if key in previous_values:
            current_value = current_values.get(key)
            previous_value = previous_values.get(key)
            if current_value != previous_value:
                print("{}: {} changed from {} to {}".format(current_ip, key, previous_value, current_value))
        else:
            print("{}: {} added".format(current_ip, key))


def compare_files_as_json():
    files = find_files_to_compare(2)

    if len(files) < 2:
        print("Can not compare outputs, there not enough stored data")
        return
    
    current_result: dict = json.loads(open(files[0]).read())
    previous_result: dict = json.loads(open(files[1]).read())
    compare_dicts(previous_result,current_result)

def compare_dicts(previous_result,current_result):
    for current_ip, current_values in current_result.items():
        if is_valid_ip(current_ip) == False:
            continue
        if not current_ip in previous_result:
            print("{}: IP not found earlier".format(current_ip))
        
        previous_values = previous_result.get(current_ip,{})
        # Check hostname
        print_diff(current_ip, "hostname", current_values, previous_values)
        # Loop through all ports and their keys and values
        for current_port in current_values.get("ports",[]):
            c_port = port_object(current_port)

            # Find the position of the current port in previous result and validate
            position = find_portid_position(previous_values.get("ports",[]), c_port.portid)

            # Not found (no position) = new open port
            if position == -1:
                print("{}: New port {} found open (Name:{}, Tunnel:{})".format(current_ip, c_port.portid, c_port.service_name, c_port.service_tunnel))
                continue

            # Check existing values            
            p_port = port_object(previous_values.get("ports",[])[position])
            if c_port.service_name != p_port.service_name:
                print("{}: Port {} Service.Name changed from {} to {}".format(current_ip, c_port.portid, c_port.service_name, p_port.service_name))
            if c_port.service_tunnel != p_port.service_tunnel:
                print("{}: Port {} Service.Tunnel changed from {} to {}".format(current_ip, c_port.portid, c_port.service_tunnel, p_port.service_tunnel))

    for previous_ip, previous_values in previous_result.items():
        if is_valid_ip(previous_ip) == False:
            continue
        if not previous_ip in current_result:
            previous_hostname = get_value_if_key_exists(previous_values, "hostname")
            print("{}: IP no longer exist (Hostname: {})".format(previous_ip, previous_hostname))

        current_values = current_result.get(previous_ip,{})

        # Loop through all ports and their keys and values
        for previous_port in previous_values.get("ports",[]):
            port = port_object(previous_port)

            # Find previous port has been removed
            if find_portid_position(current_values.get("ports",[]), port.portid) == -1:
                print("{}: Old port {} not longer found open (Name:{}, Tunnel:{})".format(previous_ip, port.portid, port.service_name, port.service_tunnel))
                continue

    # Check if flags has changed
    if current_result['flags'] != previous_result['flags']:
        # If item is in previous result but not in current it will have been resolved
        for item in previous_result['flags']:
            if item not in current_result['flags']:
                print('Flag: ' + str(item) + ' has been resolved')
        # If item is in current result but not in previous it will be a new finding
        for item in current_result['flags']:
            if item not in previous_result['flags']:
                print('New flag found ' + str(item) + ' has been found')