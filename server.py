#!/usr/bin/env python

import os
import sys

file_path = os.path.dirname(__file__)
sys.path.append(file_path+"/src/")

import ssl
import logging
import json
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

import logs as lgg
import devices as devs
import answers as ans
import setfiles as sf

true = True
false = False

# Dialog ID
id_dialog = ""
# sec
_client_secret = ""
_client_id = ""

# Tokens
acc_token = secrets.token_urlsafe(32)
ref_token = secrets.token_urlsafe(32)
code_t = secrets.token_urlsafe(32)

#devices
json_devices = {}

# Logs
root = logging.getLogger()
root.setLevel(logging.DEBUG)
handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.DEBUG)
handler.setFormatter(lgg.CustomFormatter())
fh = logging.FileHandler(file_path+"/logs/full.log")
fh.setLevel(logging.INFO)
fh.setFormatter(lgg.CustomFormatter())
root.addHandler(handler)
root.addHandler(fh)

def update_tokens():
  global ref_token
  global acc_token

  acc_token = secrets.token_urlsafe(32)
  ref_token = secrets.token_urlsafe(32)

  # Data to be written
  dictionary = {
      "token": str(acc_token),
      "refresh_token": str(ref_token)
  }
  
  # Serializing json
  json_object = json.dumps(dictionary, indent=4)
  
  # Writing to sample.json
  with open(file_path+"/tokens.json", "w") as outfile:
      outfile.write(json_object)
def read_tokens():
  global ref_token
  global acc_token

  # Opening JSON file
  with open(file_path+"/tokens.json", 'r') as openfile:
  
      # Reading from json file
      json_object = json.load(openfile)

  ref_token = json_object['refresh_token']
  acc_token = json_object['token']


class testHTTPServer_RequestHandler(BaseHTTPRequestHandler):

  # HEAD
  def do_HEAD(self):
    result = urlparse(self.path)

    # Provider check
    if result.path == "/v1.0":
      #print("> CHECK\n")
      root.warning("> CHECK: %s\n", result.path)

      self.send_response(200)
      self.end_headers()
    else:
      self.send_response(405)
      self.end_headers()

  #POST
  def do_POST(self):
    global acc_token
    global ref_token
    global code_t
    global json_devices

    try:
      result = urlparse(self.path)
    except:
      self.send_response(500)
      self.end_headers()
      root.error("\nFail urlparse in POST\n")
      return
    
    content_length = int(self.headers['Content-Length']) # <--- Gets the size of data
    content_type = self.headers['Content-Type'] # <--- Get content type
    post_data = self.rfile.read(content_length) # <--- Gets the data itself

    root.warning("> POST: %s\n", result.path)
    root.debug("- >> HEADERS:\n%s", self.headers)
    root.debug("- >> DATA:\n%s", post_data.decode('utf-8'))

    json_str = "{}"

    if content_length != 0:
      if content_type != "application/json":
        try:
          json_str = json.dumps(parse_qs(post_data.decode('utf-8')))
        except:
          json_str = "{}"
          self.send_response(500)
          self.end_headers()
          root.error("\nFail parse JSON in POST\n")
          return
      else:
        json_str = post_data.decode('utf-8')
      
      
      try:
        # Convert JSON String to Python
        json_req = json.loads(json_str)
      except:
        self.send_response(500)
        self.end_headers()
        root.error("\nFail convert JSON in POST\n")
        return
      #root.debug("- >> JSON: %s\n", json_str)
    else:
      json_str = "{}"
      root.warning("- >> Content is zero!")

    # get new token for auth user
    if result.path == "/oauth/token":
      # check
      if json_req['code'][0] != code_t:
        self.send_response(404)
        root.error("- << bad code: %s\n", json_req['code'][0])
      elif json_req['client_secret'][0] != _client_secret:
        self.send_response(404)
        root.error("- << bad client secret\n")
      elif json_req['grant_type'][0] != "authorization_code":
        self.send_response(404)
        root.error("- << bad grant type\n")
      elif json_req['client_id'][0] != _client_id:
        self.send_response(404)
        root.error("- << bad client id\n")
      else:
        # OK
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('X-Request-Id', self.headers.get("X-Request-Id"))

        answer = {
          "access_token": str(acc_token),
          "expires_in": 300,
          "token_type": "Bearer",
          "refresh_token": str(ref_token)
        }

        self.send_header('Content-Length', str(len(json.dumps(answer).encode())))
        self.end_headers()

        self.wfile.write(json.dumps(answer).encode())
        root.warning("- << send tokens\n")
        return
      
      self.end_headers()
      return
    
    elif result.path == "/oauth/update":
      #check
      if json_req['client_secret'][0] != _client_secret:
        self.send_response(404)
        root.error("- << bad client secret: %s\n", json_req['client_secret'][0])
      elif json_req['grant_type'][0] != "refresh_token":
        self.send_response(404)
        root.error("- << bad grant_type: %s\n", json_req['grant_type'][0])
      elif json_req['client_id'][0] != _client_id:
        self.send_response(404)
        root.error("- << bad client_id: %s\n", json_req['client_id'][0])
      elif json_req['refresh_token'][0] != ref_token:
        self.send_response(404)
        root.error("- << bad refresh_token: %s\n", json_req['refresh_token'][0])
      else:
        
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('X-Request-Id', self.headers.get("X-Request-Id"))

        update_tokens()

        answer = {
            "access_token": str(acc_token),
            "expires_in": 300,
            "token_type": "Bearer",
            "refresh_token": str(ref_token)
          }

        self.send_header('Content-Length', str(len(json.dumps(answer).encode())))

        self.end_headers()
        self.wfile.write(json.dumps(answer).encode())
        root.warning("- << send NEW tokens\n")
        return
      
      self.end_headers()
      return
    elif result.path == "/neodim/iot/v1.0/user/unlink":
      if self.headers.get("Authorization") != "Bearer " + acc_token:
        self.send_response(403)
        self.end_headers()
        root.error("- >> unlink fail! %s \n", self.headers.get("Authorization"))
        return
      
      self.send_response(200)
      self.send_header('Content-type', 'application/json')
      _answ = {
        "request_id": str(self.headers.get("X-Request-Id"))
      }
      self.send_header('X-Request-Id', self.headers.get("X-Request-Id"))
      self.send_header('Content-Length', str(len(json.dumps(_answ).encode())))
      self.end_headers()

      self.wfile.write(json.dumps(_answ).encode())
      
      root.warning("- >> unlink - reqid[%s] from %s\n", self.headers.get("X-Request-Id"), acc_token)

      update_tokens()

      return
    elif result.path == "/neodim/iot/v1.0/user/devices/action":
      self.send_response(200)
      self.send_header('Content-type', 'application/json')
      self.send_header('X-Request-Id', self.headers.get("X-Request-Id"))

      #root.debug(json.dumps(json_req, indent=4))

      _ans = ans._answer_act
      _ansdev = ans._ans_dev
      _buffer = '{ "devices": ['

      _ans["request_id"] = self.headers.get("X-Request-Id")

      #root.debug(json.dumps(json_devices['devices'], indent=4))

      for item in json_devices['devices']:
        for ditem in json_req['payload']['devices']:
          if item['id'] == ditem['id']:
            root.debug("- Find %s device", ditem['id'])
            _ansdev['devices'][0]['id'] = ditem['id']
            _ansdev['devices'][0]['capabilities'][0]['state']['action_result']['status'] = "DONE"
            _ansdev['devices'][0]['capabilities'][0]['type'] = ditem['capabilities'][0]['type']
            _ansdev['devices'][0]['capabilities'][0]['state']['instance'] = ditem['capabilities'][0]['state']['instance']
            _ansdev['devices'][0]['capabilities'][0]['state']['value'] = ditem['capabilities'][0]['state']['value']
            break
        if _ansdev != ans._ans_dev:
          root.error("- Unknown %s device", item['id'])
          _ansdev['devices'][0]['capabilities'][0]['state']['action_result']['status'] = "ERROR"
          _ansdev['devices'][0]['id'] = item['id']
          _ansdev['devices'][0]['capabilities'][0]['state']['action_result']['error_code'] = "DEVICE_NOT_FOUND"
          _ansdev['devices'][0]['capabilities'][0]['state']['action_result']['error_message'] = "Device ID not found in your list"
          _ans['payload']['devices'].append(_ansdev['devices'])
        else:
          root.debug(json.dumps(_ansdev, indent=4))
          #_ans['payload']['devices'].append(_ansdev['devices'][0])
          #_ans['payload']['devices'] += _ansdev['devices']
          _buffer += json.dumps(_ansdev['devices'][0]) + ", "
          _ansdev = ans._ans_dev


          #if _ansdev['capabilities'][0]['state']['instance'] == "on":
          #  #if json_req['payload']['devices'][0]['capabilities'][0]['state']['value']:
          ##  if _ansdev['capabilities'][0]['state']['value']:
          #    root.debug("%s LED ON", item["id"])
          #  else: root.debug("%s LED OFF", item["id"])
          #elif _ansdev['capabilities'][0]['state']['instance'] == "brightness":
          #  root.debug("%s LED %s persent", item["id"], _ansdev['capabilities'][0]['state']['value']) 

      #if _ansdev['capabilities'][0]['state']['action_result']['status'] != "DONE":
      #  _ansdev['capabilities'][0]['state']['action_result']['error_code'] = "DEVICE_NOT_FOUND"
      #  _ansdev['capabilities'][0]['state']['action_result']['error_message'] = "Device ID not found in your list"

      _buffer = _buffer[:-2]
      _buffer += "]}"

      root.debug(_buffer)

      sendlist = json.loads(_buffer)
      _ans['payload']['devices'] = sendlist['devices']
      _answer = json.dumps(_ans).encode()
      root.debug(json.dumps(_ans, indent=4))

      self.send_header('Content-Length', str(len(_answer)))
      self.end_headers()
      self.wfile.write(_answer)

      root.info("- >> action\n")
      return
    elif result.path == "/neodim/iot/v1.0/user/devices/query":
      self.send_response(200)
      self.send_header('Content-type', 'application/json')
      self.send_header('X-Request-Id', self.headers.get("X-Request-Id"))
      
      _answer = json.dumps(json_devices).encode()

      root.debug(json.dumps(json_devices, indent=4))

      self.send_header('Content-Length', str(len(_answer)))
      self.end_headers()
      self.wfile.write(_answer)

      #device_list = {"devices": []}

      #device_list["devices"].append(ans.build_device_query("test_dev2"))

      #for item in json_req["devices"]:
      #  root.debug(" - find dev: %s", item["id"])
      #  device_list["devices"].append(ans.build_device_query(item["id"]))
      #  root.debug(device_list)

      #ans._answer_q["payload"].update(device_list)

      #root.debug()

      return
    else:
      self.send_response(405)
      self.send_header('Content-type', 'application/x-www-form-urlencoded')
      self.end_headers()

      root.debug("- >> BAD PATH\n")

    return

  # GET
  def do_GET(self):
    global acc_token
    global ref_token
    global code_t
    global json_devices

    result = urlparse(self.path)
    
    root.warning("> GET: %s\n", result.path)
    root.debug("- >> QUERY:\n%s", result.query)
    root.debug("- >> HEADERS:\n%s", self.headers)

    resp = parse_qs(result.query)

    # Convert JSON String to Python
    json_req = json.loads(json.dumps(resp))
    root.debug("- >> JSON: %s\n", json.dumps(resp))
    
    if result.path == "/dialog/auth":
      global code_t
      code_t = secrets.token_urlsafe(32)
      self.send_response(301)
      new_path = json_req['redirect_uri'][0] + "?state=" + json_req['state'][0] + "&code=" + str(code_t)
      self.send_header('Location', new_path)
      self.end_headers()

      root.info("- << 301 redirect\n")

      return
    elif result.path == "/neodim/iot/v1.0/user/devices":
      self.send_response(200)
      self.send_header('Content-type', 'application/json')
      self.send_header('X-Request-Id', self.headers.get("X-Request-Id"))
      self.end_headers(),

      #device list
      answer_list = ans._answer_dl
      answer_list["request_id"] = self.headers.get("X-Request-Id")
      answer_list["payload"]["user_id"] = "Neodim"
      
      answer_list["payload"]["devices"] = json_devices["devices"]

      #root.debug(json.dumps(answer_list, indent=4))

      self.wfile.write(json.dumps(answer_list).encode())

      root.info("- reqid[%s] << send device list\n", answer_list["request_id"])

      return
    else:
       # Send response status code
       self.send_response(405)
       # Send headers
       self.send_header('Content-type','text/plain; charset=utf-8')
       self.end_headers()

       root.debug("- << BAD PATH\n")


    return

def run():
  global acc_token
  global ref_token
  global code_t
  global id_dialog
  global _client_secret
  global _client_id
  global json_devices
  
  root.info("Starting server . . .")
  root.info("Work path: %s", file_path)

  # Server settings
  server_address = ('192.168.1.39', 8000)
  httpd = HTTPServer(server_address, testHTTPServer_RequestHandler)

  # get settings
  json_settings = sf.check_setup_file(file_path)
  id_dialog = json_settings['id_dialog']
  _client_id = json_settings['client_id']
  _client_secret = json_settings['client_secret']

  root.debug("Settings:\n - dialog: %s\n - client ID: %s\n - client_secret: %s", id_dialog, _client_id, _client_secret)
  root.warning("PEMs:\n - %s,\n - %s", json_settings['pem']['public'], json_settings['pem']['private'])
  # restore tokens
  if os.path.isfile(file_path+"/tokens.json"):
    root.info("Read tokens...")
    read_tokens()
  else:
    root.warning("Token file is not exist! Create new")
    update_tokens()

  root.debug("\nToken: %s\nRefresh: %s", acc_token, ref_token)

  if os.path.isfile(file_path+"/devices.json"):
    root.info("Read list of devices...")
    with open(file_path+"/devices.json") as json_file:
      json_devices = json.load(json_file)
    
    for itemdevs in json_devices["devices"]:
      root.debug("Find %s device", itemdevs["id"])

  else:
    root.error("Device file is not exist! Exit...")
    return 1

  root.info("Trying run...")

  try:
      httpd.socket = ssl.wrap_socket(httpd.socket, certfile=file_path+json_settings['pem']['public'], keyfile=file_path+json_settings['pem']['private'], server_side=True)
      httpd.serve_forever()
      root.info("OK!\n")
  except KeyboardInterrupt:
      httpd.server_close()
      root.error("ERROR!\n")

run()