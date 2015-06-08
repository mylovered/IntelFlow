'''
Created on Apr 7, 2015

@author: richardqa2
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

# Post request
# d = []
# newflow=[]
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
#        install_flag = input('Enter install flag:')
#        if (install_flag == '1'):
        install = 'true'
#        else:
#            install = 'false'

######
# INTELIGENCIA
        a = '/usr/local/bro/bin/bro-cut < /home/bro1/logs-bro/current/intel.log'
#        a = '/usr/local/bro/bin/bro-cut < /home/bro1/intel4.log'
        b = os.popen(a).read()
        c = open('inteligencia.log', 'w')
        c.write(b)
        c = 'inteligencia.log'
#        fname='test4'
        nodeid = '00:00:aa:f0:42:6c:04:43'
        j=1
        with open(c, "r") as file:
            data = file.readlines()
            lstflow = []
            for line in data:
                x = []
                m = []
                m = [ts, uid, src_ip, src_port, dst_ip, dst_port, fuid, file_mime_type, file_desc, seenindicator, seenindicator_type, seenwhere, sources, q, r] = line.split()
################
#                print(data)           
                nodeconnector = 1
                ether_type = 0x800
                dst_mac = 'e2:0b:ac:94:a9:db'
#                lstflow=[]
#                print(ln(data)) 
#                print((data[0].split())[4])
#                print(data[1])                  
#                for j in range(0, len(data)):                    
                if ((line.split())[10] == "Intel::ADDR" and (line.split())[11] == "Conn::IN_ORIG"):
                     dst_ip == (line.split())[4];
                     src_ip == (line.split())[2];
                     srcdst = dst_ip + ',' + src_ip
                     if not lstflow.__contains__(srcdst):
                        lstflow.append(srcdst)
                        #if srcdst == lstflow[0]:   
#                        print("test2")
#                     if(lstflow.contained(dst_ip + "," + src_ip)==falso)
#                     if(lstflow)
#                     if(dst_ip == (line.split())[4] and src_ip == (line.split())[2]):
                        priori = 500 + j
                        fname = ('flow%s' %j)
                        j+=1
                        x = new_flow = build_flow(nodeid=nodeid, flowname=fname, ethertype=ether_type, installflag=install, srcip=seenindicator, destip=dst_ip, priority=priori, outdstmac=dst_mac)
                        array.append(x)
                elif ((line.split())[10] == "Intel::ADDR" and (line.split())[11] == "Conn::IN_RESP"):
                     dst_ip == (line.split())[4];
                     src_ip == (line.split())[2];
                     srcdst = dst_ip + ',' + src_ip
                     print("Test")
                     if not lstflow.__contains__(srcdst):
                        lstflow.append(srcdst)
                        priori = 100 + j
                        fname = ('flow%s' %(100+j))
                        ip_prot = 6
                        x = new_flow = build_flow(nodeid=nodeid, flowname=fname, ethertype=ether_type, installflag=install, srcip=src_ip, destip=seenindicator, ipprot=ip_prot, dstport = dst_port, priority=priori, outdstmac=dst_mac)
                        array.append(x)
                elif ((line.split())[10] == "Intel::URL" and (line.split())[11] == "HTTP::IN_URL"):
                     dst_ip == (line.split())[4];
                     src_ip == (line.split())[2];
                     srcdst = dst_ip + ',' + src_ip
                     if not lstflow.__contains__(srcdst):
                        priori = 200 + j
                        fname = ('flow%s' %(200+j))
                        ip_prot = 6
                        x = new_flow = build_flow(nodeid=nodeid, flowname=fname, ethertype=ether_type, installflag=install, srcip=src_ip, destip=dst_ip, ipprot=ip_prot, dstport = dst_port, priority=priori, outdstmac=dst_mac)
                        array.append(x)
                elif ((line.split())[10] == "Intel::DOMAIN" and (line.split())[11] == "HTTP::IN_HOST_HEADER"):
                     dst_ip == (line.split())[4];
                     src_ip == (line.split())[2];
                     srcdst = dst_ip + ',' + src_ip
                     if not lstflow.__contains__(srcdst):
                        priori = 300 + j
                        fname = ('flow%s' %(300+j))
                        ip_prot = 6
                        x = new_flow = build_flow(nodeid=nodeid, flowname=fname, ethertype=ether_type, installflag=install, srcip=src_ip, destip=dst_ip, ipprot=ip_prot, dstport = dst_port, priority=priori, outdstmac=dst_mac)
                        array.append(x)
                print('newflow',array)
            for i in range(1, (len(array) + 1)):
                post_flow(nodeid, array[i - 1], array[i - 1]['name'])

    print ('-----REST API LIBRARY MENU-----')
    print ('15. Test flow addition')
    test_flow_add()
