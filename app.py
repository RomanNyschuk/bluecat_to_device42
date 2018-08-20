__version__ = 0.6

import sys

from proteus.api import ProteusClientApi
from proteus.api.dns import DNS
import os
import re
import imp
import base64
import codecs
import requests

all_vrfs = 0
all_subnets = 0
all_ips = 0

added_vrfs = 0
added_subnets = 0
added_ips = 0

updated_vrfs = 0
updated_subnets = 0
updated_ips = 0

duplicated_vrfs = 0
duplicated_subnets = 0
duplicated_ips = 0

skipped_ips = 0
skipped_subnets = 0

conf = imp.load_source('conf', 'conf')

if conf.SKIP_HTTPS_ERR:
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

print conf.PR_URL

class Logger:
    def __init__(self, logfile, stdout):
        print '[!] Version %s' % __version__
        self.logfile = logfile
        self.stdout = stdout
        self.check_log_file()

    def check_log_file(self):
        while 1:
            if os.path.exists(self.logfile):
                reply = raw_input("[!] Log file already exists. Overwrite or append [O|A]? ")
                if reply.lower().strip() == 'o':
                    with open(self.logfile, 'w'):
                        pass
                    break
                elif reply.lower().strip() == 'a':
                    break
            else:
                break
        if conf.DEBUG and os.path.exists(conf.DEBUG_LOG):
            with open(conf.DEBUG_LOG, 'w'):
                pass

    def writer(self, msg):
        if conf.LOGFILE and conf.LOGFILE != '':
            with codecs.open(self.logfile, 'a', encoding='utf-8') as f:
                msg = msg.decode('UTF-8', 'ignore')
                f.write(msg + '\r\n')  # \r\n for notepad
        if self.stdout:
            try:
                print msg
            except:
                print msg.encode('ascii', 'ignore') + ' # < non-ASCII chars detected! >'

    @staticmethod
    def debugger(msg):
        if conf.DEBUG_LOG and conf.DEBUG_LOG != '':
            with codecs.open(conf.DEBUG_LOG, 'a', encoding='utf-8') as f:
                title, message = msg
                row = '\n-----------------------------------------------------\n%s\n%s' % (title, message)
                f.write(row + '\r\n\r\n')  # \r\n for notepad

class Device42Rest:
    def __init__(self, url, username, password):
        self.base_url = url
        self.username = username
        self.password = password

    def uploader(self, data, url):
        payload = data
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(self.username + ':' + self.password),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        if 'custom_fields' in url:
            r = requests.put(url, data=payload, headers=headers, verify=False)
        else:
            r = requests.post(url, data=payload, headers=headers, verify=False)
        msg = str(payload)
        logger.writer(msg)
        msg = 'Status code: %s' % str(r.status_code)
        logger.writer(msg)
        msg = str(r.text)
        logger.writer(msg)

        try:
            return r.json()
        except Exception as e:
            print '\n[*] Exception: %s' % str(e)
            pass

    def fetcher(self, url):
        headers = {
            'Authorization': 'Basic ' + base64.b64encode(self.username + ':' + self.password),
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        r = requests.get(url, headers=headers, verify=False)
        msg = 'Status code: %s' % str(r.status_code)
        writer(msg)
        msg = str(r.text)
        logger.writer(msg)
        return r.text

    def post_vrf(self, data):
        global added_vrfs, updated_vrfs, duplicated_vrfs
        url = self.base_url + '/api/1.0/vrf_group/'
        msg = '\r\nPosting data to %s ' % url
        logger.writer(msg)
        response = self.uploader(data, url)
        if response['msg'][3] and response['msg'][4]:
            added_vrfs += 1
        elif response['msg'][3] and not response['msg'][4]:
            updated_vrfs += 1
        elif not response['msg'][3] and not response['msg'][4]:
            duplicated_vrfs += 1
        return response

    def post_vlan(self, data):
        url = self.base_url + '/api/1.0/vlans/'
        msg = '\r\nPosting data to %s ' % url
        logger.writer(msg)
        return self.uploader(data, url)

    def post_subnet(self, data):
        global added_subnets, updated_subnets, duplicated_subnets
        url = self.base_url + '/api/1.0/subnets/'
        msg = '\r\nPosting data to %s ' % url
        logger.writer(msg)
        response = self.uploader(data, url)
        if 'gateway' not in data and response['msg'][3] and response['msg'][4]:
            added_subnets += 1
        elif 'gateway' not in data and response['msg'][3] and not response['msg'][4]:
            updated_subnets += 1
        elif 'gateway' not in data and not response['msg'][3] and not response['msg'][4]:
            duplicated_subnets += 1
        return response

    def post_ip(self, data):
        global added_ips, updated_ips, duplicated_ips
        url = self.base_url + '/api/ip/'
        msg = '\r\nPosting IP data to %s ' % url
        logger.writer(msg)
        response = self.uploader(data, url)
        if response['msg'][3] and response['msg'][4]:
            added_ips += 1
        elif response['msg'][3] and not response['msg'][4]:
            updated_ips += 1
        elif not response['msg'][3] and not response['msg'][4]:
            duplicated_ips += 1

if __name__ == '__main__':
    logger = Logger(conf.LOGFILE, conf.STDOUT)
    vrf_nans = []

    d42_rest = Device42Rest(
        conf.D42_URL,
        conf.D42_USER,
        conf.D42_PWD)

    pc = ProteusClientApi(
        conf.PR_URL,
        conf.PR_USER,
        conf.PR_PWD)

    pc.login()

    # {__pr_id__: __d42_id__ }
    vrf_group_mapping = {}
    host_record_mapping = {}

    # migrate vrf
    for container in pc._get_entities(0, 'Configuration', 0, 9999999)[0]:
        for dns_view in pc._get_entities(container[0], 'View', 0, 999999):
           for dns_zone in  pc._get_entities(dns_view[1][0][0], 'Zone', 0, 999999):
               for host_record in pc._get_entities( dns_zone[1][0][0], 'HostRecord', 0, 999999):
                    for host_record_object in host_record[1]:
                        try: 
                            host_record_ips = re.search(r"addresses=(.*?)\|", host_record_object[2]).group(1).split(',')
                        except Exception as e:
                            continue
 
                        try:
                            host_record_name = re.search(r"absoluteName=(.*?)\|", host_record_object[2]).group(1)
                        except:
                            continue

                        for ip in host_record_ips:
                            host_record_mapping.update({ip: host_record_name})

        all_vrfs += 1
        if container[2] is not None and 'customertriple' in container[2]:
            vrf_group_name = container[2][15:-1]
        else:
            vrf_group_name = container[1]

        if vrf_group_name == 'NAN':
            vrf_nans.append(container[1])

        vrf_group = d42_rest.post_vrf({
            'name': vrf_group_name.encode('ascii', 'ignore').decode('ascii') if vrf_group_name else None
        })

        vrf_group_mapping.update({str(container[0]): str(vrf_group['msg'][1])})

    # migrate ip4 blocks
    for vrf in vrf_group_mapping:
        all_blocks = []
        block_entities = pc._get_entities(vrf, 'IP4Block', 0, 9999)

        def blocks_reccursion(blocks):
            for block in blocks:
                if len(block) == 2:
                    all_blocks.append(block[1][0])
                else:
                    all_blocks.append(block)
                try: blocks_reccursion(pc._get_entities(block[0], 'IP4Block', 0, 9999))
                except: blocks_reccursion(pc._get_entities(block[0], 'IP4Block', 0, 9999)[0])

        if not block_entities:
           continue

        blocks_reccursion(block_entities[0])

        if len(all_blocks) > 0:
            for ip4_block in all_blocks:
                all_subnets += 1
                regexr = re.search(r"CIDR=(.*?)\|", ip4_block[2])
                if not regexr:
                    print "skip %s" % ip4_block
                    continue
                network_cidr = regexr.group(1)
                network = network_cidr.split('/')[0]
                mask_bits = network_cidr.split('/')[1]
                subnet_name = ip4_block[1].encode('ascii', 'ignore').decode('ascii') if ip4_block[1] else None

                skipped = False
                if subnet_name:
                    for x in conf.SKIP.split(','):
                        if x.lower() in subnet_name.lower():
                            skipped = True
                            continue

                if skipped:
                    skipped_subnets += 1
                    continue

                d42_rest.post_subnet({
                    'network': network,
                    'mask_bits': mask_bits,
                    'name': subnet_name,
                    'vrf_group_id': vrf_group_mapping[vrf],
                    'auto_add_ips': 'yes' if conf.AUTO_ADD_IPS else 'no'
                })

                # migrage ip4 networks
                network_entities = pc._get_entities(ip4_block[0], 'IP4Network', 0, 9999)

                if len(network_entities) > 0:
                    for ip4_network in network_entities[0]:
                        all_subnets += 1
                        vlan = None

                        regexr = re.search(r"CIDR=(.*?)\|", ip4_network[2])
                        if not regexr:
                            print "skip %s" % ip4_network
                            continue
                        network_cidr = regexr.group(1)
                        network = network_cidr.split('/')[0]
                        mask_bits = network_cidr.split('/')[1]
                        subnet_name = ip4_network[1].encode('ascii', 'ignore').decode('ascii') if ip4_network[1] else None

                        try:
                            vlan_number_string = re.search(r"VLAN=(.*?)\|", ip4_network[2]).group(1)
                        except:
                            vlan_number_string = None

                        vlan_id = None
                        if vlan_number_string:
                           vlan = d42_rest.post_vlan({
                               'number': vlan_number_string
                           })
                           vlan_id = vlan['msg'][1]

                        skipped = False
                        if subnet_name:
                            for x in conf.SKIP.split(','):
                                if x.lower() in subnet_name.lower():
                                    skipped = True
                                    continue

                        if skipped:
                            skipped_subnets += 1
                            continue

                        subnet = d42_rest.post_subnet({
                            'network': network,
                            'mask_bits': mask_bits,
                            'name': subnet_name,
                            'vrf_group_id': vrf_group_mapping[vrf],
                            'parent_vlan_id': vlan_id if vlan_id else '',
                            'auto_add_ips': 'yes' if conf.AUTO_ADD_IPS else 'no'
                        })

                        # migrate ips
                        subnet_id = subnet['msg'][1]
                        ip_entities = pc._get_entities(ip4_network[0], 'IP4Address', 0, 999999)

                        if len(ip_entities) > 0:
                            for ip in ip_entities[0]:
                                all_ips += 1
                                target_ip = re.search(r"address=(.*?)\|", ip[2]).group(1)
                                if conf.IP_LABEL_FROM_DNS:
                                    if target_ip in host_record_mapping:
                                        label = host_record_mapping[target_ip]
                                    else: 
                                        label = ip[1].encode('ascii', 'ignore').decode('ascii') if ip[1] else None
                                else:
                                    label = ip[1].encode('ascii', 'ignore').decode('ascii') if ip[1] else None
         
                                skipped = False
                                if label:
                                    for x in conf.SKIP.split(','):
                                        if x.lower() in label.lower():
                                            skipped = True
                                            continue

                                if skipped:
                                    skipped_ips += 1
                                    continue

                                if 'GATEWAY' in ip[2]:
                                    d42_rest.post_subnet({
                                        'network': network,
                                        'mask_bits': mask_bits,
                                        'name': ip4_network[1].encode('ascii', 'ignore').decode('ascii') if ip4_network[1] else None,
                                        'vrf_group_id': vrf_group_mapping[vrf],
                                        'gateway': target_ip
                                    })
                                    d42_rest.post_ip({
                                        'ipaddress': target_ip,
                                        'label': label,
                                        'subnet': subnet_id,
                                        'vrf_group_id': vrf_group_mapping[vrf],
                                        'available': 'no'
                                    })
                                else:
                                    d42_rest.post_ip({
                                        'ipaddress': target_ip,
                                        'label': label,
                                        'subnet': subnet_id,
                                        'vrf_group_id': vrf_group_mapping[vrf],
                                        'tags': 'Proteus-Import'
                                    })

    print "Total vrfs found : %s" % all_vrfs
    print "Total vrfs added : %s" % added_vrfs
    print "Total vrfs updated : %s" % updated_vrfs
    print "Total vrfs duplicated : %s" % duplicated_vrfs

    print "Total subnets found : %s" % all_subnets
    print "Total subnets added : %s" % added_subnets
    print "Total subnets updated : %s" % updated_subnets
    print "Total subnets duplicated : %s" % duplicated_subnets
    print "Total subnets skipped : %s" % skipped_subnets

    print "Total ips found : %s" % all_ips
    print "Total ips added : %s" % added_ips
    print "Total ips updated : %s" % updated_ips
    print "Total ips duplicated : %s" % duplicated_ips
    print "Total ips skipped : %s" % skipped_ips

    print "VRF NAN's : %s" % vrf_nans
