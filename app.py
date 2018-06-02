__version__ = 0.2

import sys

from proteus.api import ProteusClientApi
import os
import imp
import base64
import codecs
import requests

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
        msg = unicode(payload)
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
        url = self.base_url + '/api/1.0/vrf_group/'
        msg = '\r\nPosting data to %s ' % url
        logger.writer(msg)
        return self.uploader(data, url)

    def post_vlan(self, data):
        url = self.base_url + '/api/1.0/vlans/'
        msg = '\r\nPosting data to %s ' % url
        logger.writer(msg)
        return self.uploader(data, url)

    def post_subnet(self, data):
        url = self.base_url + '/api/1.0/subnets/'
        msg = '\r\nPosting data to %s ' % url
        logger.writer(msg)
        return self.uploader(data, url)

    def post_ip(self, data):
        url = self.base_url + '/api/ip/'
        msg = '\r\nPosting IP data to %s ' % url
        logger.writer(msg)
        self.uploader(data, url)

if __name__ == '__main__':
    logger = Logger(conf.LOGFILE, conf.STDOUT)

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

    # migrate vrf
    for container in pc._get_entities(0, 'Configuration', 0, 999)[0]:
        if container[2] is not None and 'customertriple' in container[2]:
            vrf_group_name = container[2][15:-1]
        else:
            vrf_group_name = container[1]

        vrf_group = d42_rest.post_vrf({
            'name': vrf_group_name
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

        blocks_reccursion(block_entities[0])

        if len(all_blocks) > 0:
            for ip4_block in all_blocks:
                print ip4_block
                ip4_block_network_data = ip4_block[2].split('|')[0].split('/')
                if 'CIDR' not in ip4_block_network_data[0]:
                    ip4_block_network_data = ip4_block[2].split('|')[1].split('/')

                    if 'CIDR' not in ip4_block_network_data[0]:
                        ip4_block_network_data = ip4_block[2].split('|')[2].split('/')

                network = ip4_block_network_data[0].split('=')[1]
                mask_bits = ip4_block_network_data[1]

                d42_rest.post_subnet({
                    'network': network,
                    'mask_bits': mask_bits,
                    'name': ip4_block[1],
                    'vrf_group_id': vrf_group_mapping[vrf],
                    'auto_add_ips': 'yes'
                })

                # migrage ip4 networks
                network_entities = pc._get_entities(ip4_block[0], 'IP4Network', 0, 9999)

                if len(network_entities) > 0:
                    for ip4_network in network_entities[0]:
                        print ip4_network
                        vlan = None
                        try:
                            ip4_network_network_data = ip4_network[2].split('|')[0].split('/')

                            if 'CIDR' not in ip4_network_network_data[0]:
                                ip4_network_network_data = ip4_network[2].split('|')[1].split('/')

                                if 'CIDR' not in ip4_network_network_data[0]:
                                   ip4_network_network_data = ip4_network[2].split('|')[2].split('/')

                            network = ip4_network_network_data[0].split('=')[1]
                            mask_bits = ip4_network_network_data[1]
                        except:
                            ip4_network_network_data = ip4_network[2].split('|')[1].split('/')

                            if 'CIDR' not in ip4_network_network_data[0]:
                                ip4_network_network_data = ip4_network[2].split('|')[1].split('/')

                                if 'CIDR' not in ip4_network_network_data[0]:
                                   ip4_network_network_data = ip4_network[2].split('|')[2].split('/')

                            network = ip4_network_network_data[0].split('=')[1]
                            mask_bits = ip4_network_network_data[1]

                            vlan_number_string = ip4_network[2].split('|')[0]
                            if 'VLAN' not in vlan_number_string:
                               vlan_number_string = ip4_network[2].split('|')[1]
                               if 'VLAN' not in vlan_number_string:
                                   vlan_number_string = ip4_network[2].split('|')[2]

                            vlan = d42_rest.post_vlan({
                               'number': vlan_number_string.split('=')[1]
                            })
                            vlan_id = vlan['msg'][1]

                        subnet = d42_rest.post_subnet({
                            'network': network,
                            'mask_bits': mask_bits,
                            'name': ip4_network[1],
                            'vrf_group_id': vrf_group_mapping[vrf],
                            'parent_vlan_id': vlan_id if vlan else '',
                            'auto_add_ips': 'no'
                        })


                        # migrate ips
                        subnet_id = subnet['msg'][1]
                        ip_entities = pc._get_entities(ip4_network[0], 'IP4Address', 0, 999999)

                        if len(ip_entities) > 0:
                            for ip in ip_entities[0]:
                                ip_obj = ip[2].split('|')[0].split('=')
                                if ip_obj[0] == 'address':
                                    target_ip = ip_obj[1]
                                else:
                                    target_ip = ip[2].split('|')[1].split('=')[1]

                                if 'GATEWAY' in ip[2]:
                                    d42_rest.post_subnet({
                                        'network': network,
                                        'mask_bits': mask_bits,
                                        'name': ip4_network[1],
                                        'vrf_group_id': vrf_group_mapping[vrf],
                                        'gateway': target_ip
                                    })
                                    d42_rest.post_ip({
                                        'ipaddress': target_ip,
                                        'label': ip[1],
                                        'subnet': subnet_id,
                                        'vrf_group_id': vrf_group_mapping[vrf],
                                        'available': 'no'
                                    })
                                else:
                                    d42_rest.post_ip({
                                        'ipaddress': target_ip,
                                        'label': ip[1],
                                        'subnet': subnet_id,
                                        'vrf_group_id': vrf_group_mapping[vrf],
                                        'tags': 'Proteus-Import'
                                    })
