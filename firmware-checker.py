import requests
import json
import os
import smtplib
from optparse import OptionParser
from tabulate import tabulate

#Global Central Options

#Base URL for Central API Gateway
base_url = ''
#Client ID from the Central API Gateway configuration
client_id = ''
#Client Secret from the Central API Gateway configuraion
client_secret = ''
#Refresh Token from the Central API Gateway configuration
refresh_token = ''
grant_type = 'refresh_token'

#Global Mail Server Options

#hostname or IP of the mail server
mail_server = 'smtp.gmail.com'
#Port of the Mailserver
mail_server_port = 465
#Username to authenticate at the Mailserver
mail_user = ''
#Password to authenticate at the Mailserver
mail_password = ''
#Sender address of the notification mail
mail_sender = ''
#Receiver address of the notification mail
mail_receiver = ''

parser = OptionParser()
parser.add_option('--base_url', dest='base_url', help='Base URL for Central API Gateway')
parser.add_option('--client_id', dest='client_id', help='Client ID from the Central API Gateway configuration')
parser.add_option('--client_secret', dest='client_secret', help='Client Secret from the Central API Gateway configuraion')
parser.add_option('--refresh_token', dest='refresh_token', help='Refresh Token from the Central API Gateway configuration')

parser.add_option('--mail_server', dest='mail_server', help='hostname or IP of the mail server')
parser.add_option('--mail_server_port', dest='mail_server_port', help='Port of the Mailserver')
parser.add_option('--mail_user', dest='mail_user', help='Username to authenticate at the Mailserver')
parser.add_option('--mail_password', dest='mail_password', help='Password to authenticate at the Mailserver')
parser.add_option('--mail_sender', dest='mail_sender', help='Sender address of the notification mail')
parser.add_option('--mail_receiver', dest='mail_receiver', help='Receiver address of the notification mail')

(options, args) = parser.parse_args()

if (options.base_url):
    base_url = options.base_url
if (options.client_id):
    client_id = options.client_id
if (options.client_secret):
    client_secret = options.client_secret
if (options.refresh_token):
    refresh_token = options.refresh_token

if (options.mail_server):
    mail_server = options.mail_server
if (options.mail_server_port):
    mail_server_port = options.mail_server_port
if (options.mail_user):
    mail_user = options.mail_user
if (options.mail_password):
    mail_password = options.mail_password
if (options.mail_sender):
    mail_sender = options.mail_sender
if (options.mail_receiver):
    mail_receiver = options.mail_receiver


def send_mail(my_list):
    server = smtplib.SMTP_SSL(host=mail_server,port=mail_server_port)
    server.login(mail_user, mail_password)
    server.ehlo()
    msg = "Subject:Central Device Firmware Update Notification\n" + \
    "From:" + mail_sender + "\n" + \
    "To:" + mail_receiver + "\n"
    msg = msg + tabulate(my_list, headers='keys')
    server.sendmail(mail_sender, mail_receiver, msg)
    server.close


def check_error(response):
    if 'error' in response:
        print(response['error'])
        if 'error_description' in response:
            print(response['error_description'])
        if 'status_code' in response:
            print(response['status_code'])
        return True
    return False

def api_call_post(url, payload):
    response = requests.post(url, payload)
    json_data = json.loads(response.text)
    if check_error(json_data):
        print(response.url)
        print(response.reason)
        print(response.request)
        print(response.status_code)
        exit(0)
    return json_data

def api_call_get(url, payload):
    response = requests.get(url, payload)
    json_data = json.loads(response.text)
    if check_error(json_data):
        print(response.url)
        print(response.reason)
        print(response.request)
        print(response.status_code)
        exit(0)
    return json_data
if not refresh_token:
    if os.path.isfile('token.json'):
        with open ('token.json', 'r') as token_file:
            if os.path.getsize('token.json') > 0:
                data = json.load(token_file)
                refresh_token = data['refresh_token']
        token_file.close()
if not refresh_token:
    exit(0)

payload = {'client_id' : client_id, 'client_secret' : client_secret, 'grant_type': grant_type, 'refresh_token' : refresh_token}

url = base_url + '/oauth2/token'

response = api_call_post(url, payload)

with open('token.json', 'w') as token_file:
    json.dump(response, token_file)
token_file.close()

access_token = response['access_token']

url = base_url + '/firmware/v1/devices'
device_type = {'HP', 'MAS', 'CONTROLLER'}
need_update_list = []
for x in device_type:
    payload = {'access_token' : access_token, 'device_type' : x}
    response = api_call_get(url, payload)
    devices = response['devices']
    for device in devices:
        if device['upgrade_required']:
            update = {}
            update['name'] = device['hostname']
            update['type'] = x
            update['firmware_version'] = device['firmware_version']
            update['recommended'] = device['recommended']
            need_update_list.append(update)

url = base_url + '/firmware/v1/swarms'
payload = {'access_token' : access_token, 'limit' : 1000}
response = api_call_get(url, payload)
swarms = response['swarms']
for swarm in swarms:
    if swarm['upgrade_required']:
            update = {}
            update['name'] = swarm['swarm_name']
            update['type'] = 'Swarm'
            update['firmware_version'] = swarm['firmware_version']
            update['recommended'] = swarm['recommended']
            need_update_list.append(update)

if len(need_update_list) > 0:
    send_mail(need_update_list)
    exit(0)