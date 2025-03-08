def example(**kwargs):
    def generate_test_event(file: str) -> dict:
        return {
            'action_alert': 'local',
            'source': file,
            'description': f'Test event for {file}'
        }

    events = []

    for evtx in kwargs['.evtx']:
        events.append(generate_test_event(evtx))
    for xml in kwargs['.xml']:
        events.append(generate_test_event(xml))
    for json in kwargs['.json']:
        events.append(generate_test_event(json))
    for txt in kwargs['.txt']:
        events.append(generate_test_event(txt))
    for pcap in kwargs['.pcap']:
        events.append(generate_test_event(pcap))

    # if condition==True:
    #     action_alert = "..." # akcja: "local", "remote"
    #     description = "Alert ..."
    # else:
    #     action_alert = None
    #     description = None

    return events


def icmp_scan(**kwargs):
    import pyshark
    import pandas as pd
    import re
    import functools

    def is_private_addr(ip: str):
        class_A = re.compile(r"^10.\d{1,3}.d{1,3}.\d{1,3}$")
        class_B = re.compile(r"^172.\d(1[6-9]|2[0-9]|3[0-1]).[0-9]{1,3}.[0-9]{1,3}$")
        class_C = re.compile(r"^192.168.\d{1,3}.\d{1,3}$")

        is_private = class_A.match(ip) or class_B.match(ip) or class_C.match(ip)
        return is_private is not None

    def is_private_pool_traffic(col_src, col_dst):
        return (col_src.apply(is_private_addr) | col_dst.apply(is_private_addr))

    def split_ip(ip: str):
        return tuple(int(part) for part in ip.split('.'))

    def compare_ips(ip1: str, ip2: str):
        ip1 = split_ip(ip1)
        ip2 = split_ip(ip2)
        for octet1, octet2 in zip(ip1, ip2):
            if octet1 < octet2:
                return -1
            elif octet1 > octet2:
                return 1
        return 1

    def is_next_ip(ip1: str, ip2: str):
        ip1 = split_ip(ip1)
        ip2 = split_ip(ip2)

        for octet1, octet2 in zip(ip1, ip2):
            if octet1 != octet2:
                return octet2 - octet1 == 1

        return False

    def group_ips(ip_list):
        first_ip = last_ip = None
        ranges = []
        for ip1, ip2 in zip(ip_list[:-1], ip_list[1:]):
            if is_next_ip(ip1, ip2):
                if first_ip is None:
                    first_ip = ip1
                    last_ip = ip2
                else:
                    last_ip = ip2
            else:
                if first_ip != None:
                    ranges.append(f'{first_ip}-{last_ip}')
                    first_ip = last_ip = None
                else:
                    ranges.append(f'{ip1}')

        if first_ip != None:
            ranges.append(f'{first_ip}-{last_ip}')
            first_ip = last_ip = None
        else:
            ranges.append(f'{ip2}')

        return ranges

    def generate_alert(ip_range: str):
        if '-' not in ip_range:
            return False
        ip1, ip2 = ip_range.split('-')

        return not is_next_ip(ip1, ip2)

    ## "main"

    events = []  # input {'action_alert': local/remote, 'source': file triggering the event, 'description': event description}

    for evtx in kwargs['.evtx']:
        # print(f'{evtx}: .evtx extension is not supported by this rule. Pass .pcap files')
        pass
    for xml in kwargs['.xml']:
        # print(f'{xml}:  .xml extension is not supported by this rule. Pass .pcap files')
        pass
    for json in kwargs['.json']:
        # print(f'{json}: .json extension is not supported by this rule. Pass .pcap files')
        pass
    for txt in kwargs['.txt']:
        # print(f'{txt}:  .txt extension is not supported by this rule. Pass .pcap files')
        pass
    for pcap in kwargs['.pcap']:

        source = []
        destination = []
        pcap_source = pyshark.FileCapture(pcap, display_filter="icmp")

        for packet in pcap_source:
            if packet.icmp.type == '8':  # echo request
                source.append(packet.ip.src)
                destination.append(packet.ip.dst)

        src = 'Source'
        dst = 'Destination'

        df = pd.DataFrame(
            {
                src: source,
                dst: destination,
            }
        )

        df = df.loc[is_private_pool_traffic(df[src], df[dst])]
        sus_srcs = df[src].unique()

        for source in sus_srcs:
            scanned_ips = df.loc[df[src] == source][dst].unique()
            scanned_ips = sorted(scanned_ips, key=functools.cmp_to_key(compare_ips))
            scanned_ranges = group_ips(scanned_ips)
            for ip_range in scanned_ranges:
                if generate_alert(ip_range):
                    event = {
                        'action_alert': 'remote',
                        'source': pcap,
                        'description': f'Possible scanning activity detected! {source} sent ICMP requests to the following hosts: {ip_range}'
                    }
                    events.append(event)

    return events


def updated_today(**kwargs):
    from datetime import date
    from Evtx import Evtx as evtx
    import xml.etree.ElementTree as ET

    events = []

    def generate_event(file: str) -> dict:
        return {
            'action_alert': 'local',
            'source': file,
            'description': f'{file} has record(s) added today'
        }

    def contains_string(file: str, to_search: str) -> bool:
        with open(file, 'r') as f:
            lines = f.read()
            return to_search in lines

    def handle_file(file, date_string) -> bool:
        if contains_string(file, date_string):
            events.append(generate_event(file))

    today = date.today()

    evtx_datestring = f'TimeCreated SystemTime="2020-03-21'
    for evtx_file in kwargs['.evtx']:
        with evtx.Evtx(evtx_file) as opened_file_operator:
            root = ET.Element("Events")
            for record in opened_file_operator.records():
                xml = record.xml()
                event_element = ET.fromstring(xml)
                root.append(event_element)
        file_contents = ET.tostring(root, encoding="unicode")
        if evtx_datestring in file_contents:
            events.append(generate_event(evtx_file))

    xml_datestring = f'TimeCreated SystemTime="{today}'
    for xml in kwargs['.xml']:
        handle_file(xml, xml_datestring)

    json_datestring = f'"SystemTime": "{today}'
    for json in kwargs['.json']:
        handle_file(json, json_datestring)

    txt_datestring = today.strftime("%b  %d")
    for txt in kwargs['.txt']:
        handle_file(txt, txt_datestring)

    for pcap in kwargs['.pcap']:
        # print(f'detection_rules.updated_today() {pcap}:  .pcap extension is not supported by this rule due to large execution time.')
        pass

    return events


def ip_source(**kwargs):
    import scapy.all as scapy
    import csv
    import pandas as pd
    import os
    import requests
    import time
    from pycountry_convert import country_alpha2_to_continent_code, country_name_to_country_alpha2
    import pycountry

    def _create_data_frame(pcap_file):
        packets = scapy.rdpcap(pcap)
        with open('data.csv', 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(
                ["No.", "Time", "Source IP", "Destination IP", "Protocol", "Source Port", "Destination Port", "Length"])
            for packet_number, pkts in enumerate(packets):
                time = pkts.time
                source_ip = pkts['IP'].src
                destination_ip = pkts['IP'].dst
                protocol = pkts['IP'].proto
                ethernet_header = (len(pkts))
                if 'TCP' in pkts:
                    source_port = pkts['TCP'].sport
                    destination_port = pkts['TCP'].dport
                elif 'UDP' in pkts:
                    source_port = pkts['UDP'].sport
                    destination_port = pkts['UDP'].dport
                else:
                    source_port = ""
                    destination_port = ""
                writer.writerow(
                    [packet_number + 1, time, source_ip, destination_ip, protocol, source_port, destination_port,
                     ethernet_header])

        df = pd.read_csv('data.csv', sep=',')
        if os.path.exists('data.csv'):
            os.remove('data.csv')
        return df

    def _find_most_frequent_ips(data_frame):
        ips = df['Source IP'].value_counts()
        most_frequent_ips = ips.reset_index()
        most_frequent_ips.columns = ['Source IP', 'Count']
        most_frequent_ips = most_frequent_ips.head(10)
        print("Most frequent IPs:")
        print(most_frequent_ips)

        return most_frequent_ips

    def _match_ips_with_countries(most_frequent_ips):
        countries = []
        ips_successful = []
        countCol = []
        for index, row in most_frequent_ips.iterrows():
            source_ip_from_ips = row['Source IP']
            time.sleep(0.5)
            response = requests.get("http://ip-api.com/json/" + str(source_ip_from_ips)).json()
            if response['status'] != 'fail':
                countries.append(response['country'])
                ips_successful.append(response['query'])
                countCol.append(
                    most_frequent_ips.loc[most_frequent_ips['Source IP'] == response['query'], 'Count'].values[0])

        ips_with_countries = pd.DataFrame({'Source IP': ips_successful, 'Count': countCol, 'Country': countries})
        print("IPs with countries:")
        print(ips_with_countries)
        return ips_with_countries

    def _sort_by_country(ips_with_countries):
        countries_sum = ips_with_countries.groupby('Country')['Count'].sum()
        countries_sum_with_col = countries_sum.reset_index()
        countries_sum_with_col.columns = ['Country', 'Count']
        countries_count_sorted = countries_sum_with_col.sort_values('Count', ascending=False)
        print(countries_count_sorted)
        return countries_count_sorted

    events = []

    for evtx in kwargs['.evtx']:
        # print(f'{evtx}: .evtx extension is not supported by this rule. Pass .pcap files')
        pass
    for xml in kwargs['.xml']:
        # print(f'{xml}:  .xml extension is not supported by this rule. Pass .pcap files')
        pass
    for json in kwargs['.json']:
        # print(f'{json}: .json extension is not supported by this rule. Pass .pcap files')
        pass
    for txt in kwargs['.txt']:
        # print(f'{txt}:  .txt extension is not supported by this rule. Pass .pcap files')
        pass
    for pcap in kwargs['.pcap']:
        df = _create_data_frame(pcap)
        most_frequent_ips = _find_most_frequent_ips(df)
        ips_with_countries = _match_ips_with_countries(most_frequent_ips)
        sorted_countries = _sort_by_country(ips_with_countries)

        your_country = "PL"

        your_continent = country_alpha2_to_continent_code(your_country)

        suspicious_locations = []

        for index, row in sorted_countries.iterrows():
            country_from_sorted = row['Country']
            country = pycountry.countries.search_fuzzy(country_from_sorted)
            country = country[0].alpha_2
            calculated_cont = country_alpha2_to_continent_code(country)
            if calculated_cont not in ["EU", your_continent]:
                suspicious_locations.append(country_from_sorted)
                print("SUSPICIOUS SOURCE LOCATION FROM COUNTRY: ", country_from_sorted)

        print("Suspicious activities:")
        for localization in suspicious_locations:
            choosen = ips_with_countries[ips_with_countries['Country'] == localization][['Source IP', 'Count']]
            for _, row in choosen.iterrows():
                print("[+] localization : " + str(localization) + " : Source IP : " + str(
                    row['Source IP']) + " : Packets : " + str(row['Count']))
                event = {
                    'action_alert': 'local',
                    'source': pcap,
                    'description': f'Suspicious activitie detected! localization : {str(localization)} : Source IP : {str(row['Source IP'])} : Packets : {str(row['Count'])}'
                }
                events.append(event)

    return events


def passwd_modification(**kwargs):
    import re

    regular_expressions = {r"^(?=.*\bcp\b)(?=\b.*etc/passwd\b).*$"}
    events = []

    def generate_event(file: str, line_number: int) -> dict:
        return {
            'action_alert': 'remote',
            'source': file,
            'description': f'Passwd configuration file modification detected in {file} at line {line_number}'
        }

    def matches_regex(line: str) -> bool:
        for regex in regular_expressions:
            pattern = re.compile(regex)
            # return True if any of the regexes matches
            if bool(pattern.match(line)):
                return True
        return False # return false if none of regexes matches

    def handle_file(file):
        with open(file, 'r') as f:
            line_number = 0  # initializing line numbering
            lines = f.readlines()
            for line in lines:
                line_number += 1
                if matches_regex(line):
                    events.append(generate_event(file, line_number))

    for evtx in kwargs['.evtx']:
        pass
    for xml in kwargs['.xml']:
        pass
    for json in kwargs['.json']:
        pass
    for txt in kwargs['.txt']:
        handle_file(txt)
    for pcap in kwargs['.pcap']:
        pass

    return events
