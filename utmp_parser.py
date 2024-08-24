#!/usr/bin/python3
import argparse
import datetime
import io
import ipaddress
import os
import time 
import sys
import struct

def count_logins(utmp_entries):
    """
    Function counts the logins for each host found in the b|u|wtmp file specified as the input
    file. Function returns ip : # of logins. Function is great to get a quick snapshot of the 
    hosts most frequently logging into a system. Use this output for futher queries.

    :utmp_entries: a list of lists containing each utmp entry for further parsing.

    return: None
    """
    # debugging for new format
    # print([x for x in utmp_entries])

    # dict for ip, count of logins
    host_tracker = {}
    for record_field in utmp_entries:
        # handle all the crazy tmux output and normalize it to tmux 
        if 'tmux' in record_field[5]:
           if 'tmux' in host_tracker.keys():
               host_tracker['tmux'] += 1
           else:
               host_tracker['tmux'] = 1

        # dont care about reboot, shutdown, runlevel or DEAD 
        elif record_field[4] == 'reboot' or record_field[4] == 'shutdown' or record_field[4] == 'runlevel' or record_field[1] == '' or record_field[0] == 'DEAD':
            pass

        # check if in our dict, if yes inc val by 1, if not add
        elif record_field[5] in host_tracker.keys():
            host_tracker[record_field[5]] += 1
        else:
            host_tracker[record_field[5]] = 1

    sorted_host_records = dict(sorted(host_tracker.items(), key=lambda item: item[1], reverse=True))
    # debugging
    #print(sorted_host_records)

    # Find the maximum length of keys for uniform spacing
    max_key_length = max(len(key) for key in sorted_host_records.keys())

    # Print each key-value pair with uniform spacing
    for key, value in sorted_host_records.items():
        print("{:<{}} : {}".format(key, max_key_length, value))


def ip_timestamps(ip, utmp_entries):
    """
    Function returns back type of login and the timestamp for a specific ip address.

    :ip: the target ip we want to pull timestamps for 
    :utmp_entries: a list of lists with all the entries from the parsed file

    :return: None
    """
    
    time_type = {}
    for record_entry in utmp_entries:
        # we have a match with our target ip 
        if record_entry[5] == ip or 'tmux' in record_entry[5] and ip == 'tmux':
            time_type[record_entry[9]] = record_entry[0]
        # else is not needed, added for readability
        else:
            pass
    
    # debugging to see the dict
    # print(time_type)
    sorted_by_timestamp = dict(sorted(time_type.items(), key=lambda item: item[0], reverse=True))

    max_key_length = max(len(key) for key in sorted_by_timestamp.keys())

    for key, value in sorted_by_timestamp.items():
        print("{:<{}} : {}".format(key, max_key_length, value))



def working_hrs(start_time, end_time, utmp_entries):
    """
    Function takes user defined working hours and searches for any logon events that
    occur outside of these working hours. Function will return the entire struct entry
    for these potentially anomolous login events.

    :start_time: the start of the working day 
    :end_time: the end of the working day
    :utmp_entries: the list of utmp entries to iterate over

    :return: None
    """
    # going to capture the susp entire entry
    suspect_logins = []
    for record_entry in utmp_entries:
        time = record_entry[9].split(" ")[1]
        # debugging
        # print(time)
        normalized_time = int("".join(time.split(":")[0:2]))
        # debugging
        # print(normalized_time)
        # this is true if our login falls in between the working hours...i.e. we dont care about it 
        if int(start_time) < normalized_time and int(end_time) > normalized_time or record_entry[0] == 'DEAD' or record_entry[0] == 'RUN_LVL' or record_entry[0] == 'BOOT_TIME':
            pass
        else:
            suspect_logins.append(record_entry)
    for i in suspect_logins:
        print(i)


def parseutmp(utmp_filesize, utmp_file):
    
    # list of lists, containing all the u|b|wtmp entries 
    parsed_file = []

    STATUS = {
        0: 'EMPTY',
        1: 'RUN_LVL',
        2: 'BOOT_TIME',
        3: 'NEW_TIME',
        4: 'OLD_TIME',
        5: 'INIT',
        6: 'LOGIN',
        7: 'USER',
        8: 'DEAD',
        9: 'ACCOUNTING'}
        
    # list for each record in file 
    record_field = []

    # start at beginning of file 
    offset = 0
    # while we are smaller than the size of file, do
    while offset < utmp_filesize:
        utmp_file.seek(offset)
        # get the type of record
        record_type = struct.unpack("<L", utmp_file.read(4))[0]
        for k, v in STATUS.items():
            if record_type == k:
                # set the correct type 
                record_type = v
        # pid started
        pid = struct.unpack("<L", utmp_file.read(4))[0]
        line = utmp_file.read(32).decode("utf-8", "replace").split('\0', 1)[0]
        id_val = utmp_file.read(4).decode("utf-8", "replace").split('\0', 1)[0]
        # username used
        user = utmp_file.read(32).decode("utf-8", "replace").split('\0', 1)[0]
        # from ip 
        host = utmp_file.read(256).decode("utf-8", "replace").split('\0', 1)[0]
        term = struct.unpack("<H", utmp_file.read(2))[0]
        exit_val = struct.unpack("<H", utmp_file.read(2))[0]
        session = struct.unpack("<L", utmp_file.read(4))[0]
        sec = struct.unpack("<L", utmp_file.read(4))[0]
        # take time and format to local time, time in file is going to be the box time 
        # of where the file came from, only UTC or localtime make sense here 
        sec = time.strftime("%Y/%m/%d %H:%M:%S", time.localtime(float(sec)))
        usec = struct.unpack("<L", utmp_file.read(4))[0]
        # also the from ip, dont need it twice
        addr = ipaddress.IPv4Address(struct.unpack(">L", utmp_file.read(4))[0])
    
        # the values we currently care about
        record_field.extend([record_type, pid, line, id_val, user, host, term, exit_val, session, sec, usec, addr]) 
    
        # debugging
        # print(record_field)
        
        parsed_file.append(record_field) 
        
       
        # reclear the entry for parsing the next one
        record_field = []
        # jump forward 384 to the next record 
        offset += 384

    utmp_file.close()
    return parsed_file 


if __name__ == '__main__':

    # set our encoding 
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    start_working = None
    end_working = None 

    parser = argparse.ArgumentParser(description="utmp parser")
    parser.add_argument("-f", "--file", help="specified input b|w|utmp file to parse", required=True, dest="file")
    parser.add_argument("-c", "--count", help="prints the ips and the amount of logins", action="store_true", required=False, dest="count")
    parser.add_argument("-i", "--ip", help="print timestamps of logins from specific ip", required=False, dest="ip")
    parser.add_argument("-w", "--workinghours", help="normal working hours, returns login results outside of your range, format -w 0900-1700", required=False, dest="working")
    args = parser.parse_args()

    input_file = args.file
    if args.count:
        count = True
    else:
        count = False
    if args.ip:
        tgt_ip = args.ip
    else: 
        tgt_ip = None
    if args.working:
        # count on the user messing up the 0900-1700 format...input val
        if "-" not in args.working or ":" in args.working or " " in args.working or len(args.working) != 9:
            print("[!] Working hours format: -w 0800-1600")
            sys.exit(2)
        try:
            working_hours = args.working
            start_working = working_hours.split("-")[0]
            end_working = working_hours.split("-")[1]
            # debugging 
            #print(start_working)
            #print(end_working)
        except:
            print("halp")

    # check exists
    if os.path.exists(input_file):
        with open(input_file, "rb") as utmp_file:
            # get file size 
            utmp_filesize = os.path.getsize(input_file)
          
            # call function to parse and get our list of lists.
            entries = parseutmp(utmp_filesize, utmp_file)
            
            if count == True:
                count_logins(entries)
            
            if tgt_ip:
                ip_timestamps(tgt_ip, entries)

            if start_working != None and end_working != None:
                working_hrs(start_working, end_working, entries)
    else:
        # file not found 
        print("No input file found")
        sys.exit(1)
