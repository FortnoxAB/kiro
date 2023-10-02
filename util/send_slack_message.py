import requests
import json

def send_slack_message(webhook_url, message, channel="#general"):
    headers = {'Content-type': 'application/json'}
    payload = {'text': message, 'channel': channel}
    response = requests.post(webhook_url, headers=headers, data=json.dumps(payload))
    if response.status_code != 200:
        raise ValueError(f'Request to Slack returned an error {response.status_code}, the response is:\n{response.text}')
