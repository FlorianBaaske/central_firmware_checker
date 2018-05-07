# central_firmware_checker will check with the help of the Central API, if a new recommended firmware for 
Usage: firmware-checker.py [options]

Options:
  -h, --help            show this help message and exit
  --base_url=BASE_URL   Base URL for Central API Gateway
  --client_id=CLIENT_ID
                        Client ID from the Central API Gateway configuration
  --client_secret=CLIENT_SECRET
                        Client Secret from the Central API Gateway
                        configuraion
  --refresh_token=REFRESH_TOKEN
                        Refresh Token from the Central API Gateway
                        configuration
  --mail_server=MAIL_SERVER
                        hostname or IP of the mail server
  --mail_server_port=MAIL_SERVER_PORT
                        Port of the Mailserver
  --mail_user=MAIL_USER
                        Username to authenticate at the Mailserver
  --mail_password=MAIL_PASSWORD
                        Password to authenticate at the Mailserver
  --mail_sender=MAIL_SENDER
                        Sender address of the notification mail
  --mail_receiver=MAIL_RECEIVER
                        Receiver address of the notification mail