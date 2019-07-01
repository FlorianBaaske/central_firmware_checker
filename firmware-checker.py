import requests
import json
import os
import smtplib
import atexit
from optparse import OptionParser
from tabulate import tabulate

#Global Central Options

#Base URL for Central API Gateway
base_url = ''
#Central Customer ID
customerID = ''
#Client ID from the Central API Gateway configuration
client_id = ''
#Client Secret from the Central API Gateway configuraion
client_secret = ''
#Refresh Token from the Central API Gateway configuration
refresh_token = ''
##Central Username
username = ''
#Central User Password
password = ''
#Central CSRF Token
csrf = ''
#Central Session
csession = ''
#Central Authentication Code
authCode = ''
#Central Access Token
access_token = ''
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
parser.add_option('--customer_id', dest='customerID', help='Your Customer ID from Central')
parser.add_option('--client_id', dest='client_id', help='Client ID from the Central API Gateway configuration')
parser.add_option('--client_secret', dest='client_secret', help='Client Secret from the Central API Gateway configuraion')
parser.add_option('--refresh_token', dest='refresh_token', help='Refresh Token from the Central API Gateway configuration')
parser.add_option('--central_username', dest='username', help='Central Username')
parser.add_option('--central_password', dest='password', help='Central password')

parser.add_option('--mail_server', dest='mail_server', help='hostname or IP of the mail server')
parser.add_option('--mail_server_port', dest='mail_server_port', help='Port of the Mailserver')
parser.add_option('--mail_user', dest='mail_user', help='Username to authenticate at the Mailserver')
parser.add_option('--mail_password', dest='mail_password', help='Password to authenticate at the Mailserver')
parser.add_option('--mail_sender', dest='mail_sender', help='Sender address of the notification mail')
parser.add_option('--mail_receiver', dest='mail_receiver', help='Receiver address of the notification mail')

(options, args) = parser.parse_args()

if (options.base_url):
    base_url = options.base_url
if (options.customerID):
    customerID = options.customerID
if (options.client_id):
    client_id = options.client_id
if (options.client_secret):
    client_secret = options.client_secret
if (options.refresh_token):
    refresh_token = options.refresh_token
if (options.username):
    username = options.username
if (options.password):
    password = options.password

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


def userAuthentication():
    global username
    global password
    global csrf
    global csession

    url = '/oauth2/authorize/central/api/login'
    oauthURL = base_url + url
    params = {'client_id': client_id}
    headers = {'Content-type': 'application/json'}

    if len(username) == 0:
        print('username:', end='')
        username = input()

    if len(password) == 0:
        print('password:', end='')
        password = input()

    payload = {'username': username, 'password': password}

    resp = requests.post(oauthURL, params=params, data=json.dumps(payload), headers=headers)

    print(resp.url)
    print(resp)

    csrf = resp.cookies['csrftoken']
    csession = resp.cookies['session']



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

def postRequest(url, payload, params):

    postURL = base_url + url

    sesk = 'session=' + csession

    headers = {'X-CSRF-TOKEN':csrf, 'Content-type': 'application/json', 'Cookie':sesk}

    resp = requests.post(postURL, params=params, data=json.dumps(payload), headers=headers)
    print(resp.url)
    print(resp)

    return resp.json()


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

def deleteRquest(url, payload):
    deleteURL = base_url + url
    
    payload['access_token'] = access_token 
    sesk = 'session=' + csession

    headers = {'X-CSRF-TOKEN':csrf, 'Content-type': 'application/json', 'Cookie':sesk}

    if url == '/oauth2/api/tokens':
        resp = requests.delete(deleteURL, data=json.dumps(payload), headers=headers)
    else:
        resp = requests.delete(deleteURL, params=payload)

    print(resp.url)
    print(resp)

def cleanup():
    print('clean UP')
    deleteRquest('/oauth2/api/tokens', {'customer_id': customerID})
    

atexit.register(cleanup)

print('authenticate user')
userAuthentication()

print ('get authentication code')
data = postRequest('/oauth2/authorize/central/api', {'customer_id': customerID}, {'client_id': client_id, 'response_type': 'code', 'scope': 'all'})
authCode = data['auth_code']

print('get access token')
data = postRequest('/oauth2/token', {'customer_id': customerID}, {'client_id': client_id, 'grant_type': 'authorization_code', 'client_secret': client_secret, 'code': authCode})
access_token = data['access_token']

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