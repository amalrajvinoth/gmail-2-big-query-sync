import base64
import datetime
import logging
import os
import time

from google.auth.transport.requests import Request
from google.cloud import bigquery
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build


def init_logger():
    log_format = os.uname().nodename + ' - %(asctime)s - %(levelname)s - %(message)s'
    logging.basicConfig(
        format=log_format,
        datefmt='%y-%m-%d %H:%M:%S')
    logging.getLogger().setLevel(logging.INFO)


def validate_env():
    required_env_vars = ['DESK_APP_AUTH_KEY', 'JSON_KEY_FILE', 'SENDER_EMAIL', "BIGQUERY_TABLE"]
    for env_var in required_env_vars:
        if env_var not in os.environ:
            raise Exception(f"Required environment variable {env_var} is not set.")


def read_env():
    global desk_app_auth_key, big_query_table_id, gmail_query, big_query_client
    desk_app_auth_key = os.environ.get('DESK_APP_AUTH_KEY')
    sender_email = os.environ.get('SENDER_EMAIL')
    json_key_file = os.environ.get('JSON_KEY_FILE')
    big_query_table_id = os.environ.get('BIGQUERY_TABLE')
    # Define your Gmail query parameters
    gmail_query = sender_email + " has:attachment filename:txt"
    big_query_client = bigquery.Client.from_service_account_json(json_key_file)


def get_gmail_service():
    token_file = "token.json"
    # If modifying these scopes, delete the file token.json.
    gmail_scopes = ["https://www.googleapis.com/auth/gmail.readonly"]
    creds = None

    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, gmail_scopes)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                desk_app_auth_key, gmail_scopes
            )
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(token_file, "w") as token:
            token.write(creds.to_json())

    return build("gmail", "v1", credentials=creds)


# Function to scan Gmail attachments and upload to BigQuery
def scan_gmail_attachments_to_bigquery(gmail_service):
    logging.info("scan_gmail_attachments_to_bigquery: scanning for attachments")
    try:
        response = gmail_service.users().messages().list(userId='me', q=gmail_query).execute()
        messages = response.get('messages', [])
        for message in messages:
            user_id = 'me'
            msg_id = message['id']
            msg = gmail_service.users().messages().get(userId=user_id, id=msg_id).execute()
            msg_date = datetime.datetime.fromtimestamp(int(msg['internalDate']) / 1000.0)

            if is_attachment_exist(big_query_table_id, "email_timestamp", msg_date):
                logging.info(f"skipping as attachment already existing with timestamp: {msg_date}")
                return

            for part in msg['payload']['parts']:
                if part['filename'] and 'text' in part['mimeType']:
                    attachment_id = part['body']['attachmentId']
                    data = fetch_attachment_data(gmail_service, user_id, msg_id, attachment_id)
                    rows_to_insert = [{
                        "contents": data,
                        "file_name": part['filename'],
                        "timestamp": datetime.datetime.now(),
                        "email_timestamp": msg_date
                    }]  # Modify this according to your schema
                    table = big_query_client.get_table(big_query_table_id)  # Fetch the table schema
                    schema = table.schema
                    errors = big_query_client.insert_rows(big_query_table_id, rows_to_insert,
                                                          selected_fields=schema)  # Insert data into BigQuery
                    if not errors:
                        logging.info("Data uploaded successfully.")
                    else:
                        logging.exception("Encountered errors: {}".format(errors))
    except Exception as e:
        logging.exception("failed to scan emails: ", e)


def is_attachment_exist(table_id, condition_column, condition_value):
    try:
        select_query = f"""
                SELECT COUNT(*)
                FROM `{table_id}`
                WHERE {condition_column} = "{condition_value}"
            """
        query_job = big_query_client.query(select_query)  # Start the query

        results = query_job.result()  # Get the results

        for row in results:
            return row[0] != 0
    except Exception as e:
        logging.exception("failed to check attachment exist: ", e)
        return False


def fetch_attachment_data(gmail_service, user_id, message_id, attachment_id):
    try:
        attachment = gmail_service.users().messages().attachments().get(
            userId=user_id, messageId=message_id, id=attachment_id
        ).execute()

        data = base64.urlsafe_b64decode(attachment['data'].encode('UTF-8'))
        return data

    except Exception as e:
        logging.exception("An error occurred while fetching attachment data: ", e)
        return None


# Main method to run the script
def main():
    read_env()
    gmail_service = get_gmail_service()
    while True:
        logging.info("main: scanning for attachments")
        scan_gmail_attachments_to_bigquery(gmail_service)
        time.sleep(900)  # 15 minutes in seconds


if __name__ == "__main__":
    validate_env()
    init_logger()
    main()
