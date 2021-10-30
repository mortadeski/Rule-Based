import json
import os
import requests
import csv
import logging


def potential_servers_and_vulnerabilities(servers, vulnerabilities):
    """
    :param servers: List of all servers received from the remote server
    :param vulnerabilities: List of all vulnerabilities received from the remote server
    :return: Returns the lists after checking that each server and vulnerabilities (separately) comply with the rules
    """

    with open('rules.csv') as csv_file:
        csv_reader = csv.reader(csv_file, delimiter=',')
        for row in csv_reader:
            if not row:  # for empty rows
                continue
            elif row[0] == 'server':
                servers = constraints_handling(row[1:], servers)
            elif row[0] == 'vulnerability':
                vulnerabilities = constraints_handling(row[1:], vulnerabilities)

    return servers, vulnerabilities


def constraints_handling(rule, lst):
    """
    :param rule: Restrictions. rule[0] refer to field, rule[1] refer to operator and rule[2] refer to value
    :param lst: Objects that need to be checked to see if the restrictions applies to them
    :return:all All objects to which the restriction applies
    """
    rule[2] = str(rule[2])
    for obj in list(lst):
        try:
            # rule[2] = type(obj[rule[0]])(rule[2])  # converting to same type
            obj[rule[0]] = str(obj[rule[0]])  # converting to same type to compere
        except:
            lst.remove(obj)
            continue  # 2 cases: rule[0] is not a filed, or they cant convert to the same type. In any case it does
            # not follow the rule.
        # string compere
        if rule[1] == 'eq':
            if obj[rule[0]] != rule[2]:
                lst.remove(obj)
        elif rule[1] == 'lt':
            if obj[rule[0]] >= rule[2]:
                lst.remove(obj)
        elif rule[1] == 'gt':
            if obj[rule[0]] <= rule[2]:
                lst.remove(obj)

    return lst


def make_pairs(servers, vulnerabilities):
    """
    :param servers: All servers after checking the rules on them
    :param vulnerabilities: All vulnerabilities after checking the rules on them
    :return: List of lists - every list contain server details and vulnerability details according to correlation based on operating system and version
    """

    servers_by_os = servers_per_os(servers)
    all_pairs = []
    for vul in vulnerabilities:
        if not field_in_dict(['affects'], vul):
            continue
        separator = vul['affects'].split('_', 1)  # Assuming the first "_" is separator between os and version
        if len(separator) < 2:
            continue
        vul_os_details = (separator[0], separator[1])
        if vul_os_details in servers_by_os:
            for serv in servers_by_os[vul_os_details]:
                if field_in_dict(['name', 'risk'], vul) and field_in_dict(['hostname', 'ip'], serv):  # Assuming I
                    # need all the fields to write to the log file
                    all_pairs.append([vul['name'], vul['risk'], serv['hostname'], serv['ip']])

    return all_pairs


def write_to_log(all_pairs):
    """

    :param all_pairs: List of lists - every list contain server details and vulnerability details according to correlation based on operating system and version
    """
    if len(all_pairs) == 0:  # no alerts
        if os.path.isfile("logfile.log"):
            os.remove("logfile.log")
        return
    logging.basicConfig(filename="logfile.log", level=logging.INFO, filemode="w+")
    for pair in all_pairs:
        alert = "vulnerability " + str(pair[0]) + " with risk " + str(pair[1]) + " discovered on " + str(pair[2]) + " " + str(pair[3])
        logging.info(alert)


def servers_per_os(servers):
    """

    :param servers: All the servers that need to be sorted by operating system and rough
    :return:Dictionary. key is tuple (operating system, version) and the value is a list of the servers that related to tuple
    """
    all_os = {}
    for server in servers:
        if field_in_dict(['os', 'osVersion'], server):
            server_os_details = (server['os'], server['osVersion'])
            if server_os_details in all_os:
                all_os[server_os_details] += [server]
            else:
                all_os[server_os_details] = [server]
    return all_os


def field_in_dict(fields, the_dict):
    """

    :param fields: list of fields names
    :param the_dict: dictionary to chek with the fildes
    :return: True if fields are keys in the_dict, False otherwise
    """
    # There are objects that do not have all the fields
    for f in fields:
        if f not in the_dict:
            return False
    return True


def get_all_vulnerabilities():
    vulnerabilities = []
    end = False
    start_id = 1
    amount = 2000
    while not end:
        encode = json.dumps({'startId': start_id, 'amount': amount})
        r_vulnerabilities = requests.post('http://interview.vulcancyber.com:3000/vulns', data=encode)
        v = r_vulnerabilities.json()
        vulnerabilities += v
        if len(v) < amount + 1:
            end = True
        else:
            start_id += amount

    return vulnerabilities


if __name__ == '__main__':
    # 1.get all servers
    r_servers = requests.get('http://interview.vulcancyber.com:3000/servers', headers={'Authorization': 'Aa123456!'})
    all_servers = r_servers.json()

    # 2.get all vulnerabilities
    all_vulnerabilities = get_all_vulnerabilities()

    # 3. Adjustment to rules
    relevant_servers, relevant_vulnerabilities = potential_servers_and_vulnerabilities(all_servers, all_vulnerabilities)

    # 4. correlation between servers and vulnerabilities
    pairs = make_pairs(relevant_servers, relevant_vulnerabilities)
    write_to_log(pairs)
