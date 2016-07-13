import requests
import json
import pyshark

hue_ip_addr = hue_id = ''
user_ids = []

def find_hue():
   global hue_ip_addr, hue_id
   hue_info_request = requests.get('https://www.meethue.com/api/nupnp')

   hue_info = json.loads(hue_info_request.text)

   if len(hue_info) > 0:
      hue_info = hue_info[0]
      if 'internalipaddress' in hue_info:
         hue_ip_addr = hue_info['internalipaddress']
         print 'Hue ip address:', hue_ip_addr
      else:
         print 'Could not find Hue ip address'
      if 'id' in hue_info:
         hue_id = hue_info['id']
         print 'Hue id:', hue_id
      else:
         print 'Could not find Hue id'
   else:
      print 'Bad response'

def set_light(on):
   global hue_ip_addr, user_ids
   if hue_ip_addr == '':
      print 'No Hue ip address'
      return
   if not len(user_ids) < 1:
      requests.put('http://' + hue_ip_addr + '/api/' + user_ids[0] + '/groups/1/action', data=json.dumps({'on': on}))

find_hue()

capture_filter = 'tcp and dst port 80 and host ' + hue_ip_addr
capture = pyshark.LiveCapture(interface='en0', only_summaries=True, bpf_filter=capture_filter)

for packet in capture.sniff_continuously():
   info = packet.info.split(' ')
   if len(info) >= 2:
      if info[0] == 'GET' or info[0] == 'PUT':
         header = info[1].split('/')
         if len(header) >= 1:
            del header[0]
         if len(header) >= 2 and header[0] == 'api' and header[1] != 'nouser':
            print 'Found username:', header[1]
            if not header[1] in user_ids:
               user_ids.append(header[1])
               print user_ids
   #print 'Just arrived:', packet.info