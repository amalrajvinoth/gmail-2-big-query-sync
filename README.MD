# Gmail Attachment to BigQuery Uploader

This Python script enables the extraction of attachments from Gmail emails and uploads the data to a specified BigQuery table. It leverages the Gmail API and the Google Cloud BigQuery service for seamless integration and data management.

## Setup Instructions

1. Install the necessary Python dependencies using the following command:

```bash
pip install -r requirements.txt
```
2. Set up the required environment variables in a .env file:
```shell
SERVICE_ACCOUNT_KEY_PATH=your_service_account_key_path
GMAIL_CREDENTIALS=your_gmail_credentials
```
3. Run the script using the following command:
```shell
python gmail_to_bigquery.py
```

## Functionality
- Connects to the Gmail API to retrieve emails with specific attachment criteria.
- Downloads the attachments and processes the data.
- Inserts the processed data into the specified BigQuery table.