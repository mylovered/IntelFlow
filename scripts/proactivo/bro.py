'''
Created on Apr 7, 2015

@author: Javier Richard Quinto Ancieta
'''
import requests, json
import json
import sys
import logging
import os
import sys
baseUrl = 'http://192.168.122.4:8080/controller/nb/v2'
containerName = 'default/'
ethTypeIp = 0x800
ipTypeTcp = 0x6
ipTypeUdp = 0x11

# Parse actionstr 
def parse_action(actions):
  action_str = ''
  for act in actions:
    actionType = act['type']
    if actionType == 'OUTPUT':
      action_str += '(' + 'TYPE:' + actionType + ' NODE:' + act['port']['node']['id'] + ',PORT:' + act['port']['id'] + ')'
    elif actionType == 'SET_DL_DST':
      action_str += '(' + 'TYPE:' + actionType + ' ADDRESS:' + act['address'] + ')'
  return action_str

# Parse matchstr
def parse_match(match_field):
    match_str = ''
    for match in match_field:
        match_type = match['type']
        match_str += '(' + 'TYPE:' + match_type + ' VALUE:' + match['value'] + ' )'

    return match_str

def post_dict(url, d):

    r = requests.put(url, json.dumps(d), headers={'Content-Type' : 'application/json'}, auth=('admin', 'admin'))
#    print(d)
    return r
# Post flow to controller
def post_flow(nodeid, new_flow, flowname):
    req_str = baseUrl + '/flowprogrammer/default/node/OF/' + nodeid + '/staticFlow/' + flowname
    logging.debug('req_str %s', req_str)
    post_dict(req_str, new_flow)
#    print(new_flow)
# Builds and returns flow
def build_flow(nodeid, flowname, ethertype='', destip='',dstport='', ipcos='', ipprot='', srcip='', installflag='', inputport='', outnodeconn='', outdstmac='', priority='', vlan='', innodeconn=''):
    newflow = {}
    newflow['name'] = flowname
    if (installflag != ''):
        newflow['installInHw'] = installflag
    else:
        newflow['installInHw'] = 'true'
    newflow['node'] = {u'id': nodeid, u'type': u'OF'}
    if (srcip != ''):
        newflow['nwSrc'] = srcip
    if (destip != ''):
        newflow['nwDst'] = destip
    if (dstport != ''):
        newflow['tpDst'] = dstport
    if (ethertype != ''):
        newflow['etherType'] = ethertype
    if (ipcos != ''):
        newflow['tosBits'] = ipcos
    if (ipprot != ''):
        newflow['protocol'] = ipprot
    if (priority != ''):
        newflow['priority'] = priority
    if (vlan != ''):
        newflow['vlanId'] = vlan
    node = {}
    node['id'] = nodeid
    node['type'] = 'OF'
    newflow['node'] = node
# # Generating a DROP
## -----------------
    actions1 = 'DROP'
    newflow['actions'] = [actions1]
    return newflow
#################
# START OF MAIN PROGRAM
# Setup logging
LEVELS = {'debug': logging.DEBUG,
          'info': logging.INFO,
          'warning': logging.WARNING,
          'error': logging.ERROR,
          'critical': logging.CRITICAL}

if len(sys.argv) > 1:
    level_name = sys.argv[1]
    level = LEVELS.get(level_name, logging.NOTSET)
    logging.basicConfig(level=level)

if __name__ == "__main__":
    # Test flow addition 
    array = []
    def test_flow_add():
        install = 'true'
######
# INTELIGENCIA
        a = '/usr/local/bro/bin/bro-cut < /home/bro1/INTEL/infrastructure_scan.intel'
#        a = '/usr/local/bro/bin/bro-cut < /home/bro1/intel4.log'
        b = os.popen(a).read()
        c = open('inteligencia1.log', 'w')
        c.write(b)
        c = 'inteligencia1.log'
#        fname='test4'
        nodeid = '00:00:36:4d:14:6a:de:43'
        j=1
        with open(c, "r") as file:
            data = file.readlines()
            lstflow = []
            for line in data:
                x = []
                m = []
                m = [indicator, indicator_type, source, desc, url, impact, severity, confidence] = line.split()
################
#                print(data)           
                nodeconnector = 1
                ether_type = 0x800
                dst_mac = 'e2:0b:ac:94:a9:db'
                if ((line.split())[1] == "Intel::ADDR"):
                     indicator == (line.split())[0];
                     if not lstflow.__contains__(indicator):
                        lstflow.append(indicator)
                        priori = 500 + j
                        fname = ('flow%s' %j)
                        j+=1
                        x = new_flow = build_flow(nodeid=nodeid, flowname=fname, ethertype=ether_type, installflag=install, srcip=indicator, priority=priori, outdstmac=dst_mac)
                        array.append(x)
                print('newflow',array)
            for i in range(1, (len(array) + 1)):
                post_flow(nodeid, array[i - 1], array[i - 1]['name'])

    print ('-----REST API LIBRARY MENU-----')
    print ('15. Test flow addition')
    test_flow_add()
