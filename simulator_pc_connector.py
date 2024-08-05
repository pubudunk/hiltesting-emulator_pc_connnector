import boto3
import json
from datetime import datetime, UTC
import random
import time
import pickle
import os
from boto3.session import Session
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

# Configuration
identity_pool_id = 'us-east-1:128a3c5b-f4b0-45e7-bee4-4302060554ab'
region_name = 'us-east-1'
table_name_test_cases = 'hiltesting-test-cases'
table_name_test_results = 'hiltesting-test-results'
queue_url = 'https://sqs.us-east-1.amazonaws.com/381492230851/hiltesting-test-execution-event'
lambda_function_name = 'hiltesting-websocket-web-client-update-handler'
credentials_file = 'aws_credentials.pkl'

def assume_role_with_web_identity():
    cognito_client = boto3.client('cognito-identity', region_name=region_name)
    
    if os.path.exists(credentials_file):
        with open(credentials_file, 'rb') as f:
            credentials = pickle.load(f)
            if credentials['expiration'] > datetime.now(UTC):
                return credentials
    
    # Get existing Cognito Identity ID from file, if available
    identity_id = None
    if os.path.exists(credentials_file):
        with open(credentials_file, 'rb') as f:
            credentials = pickle.load(f)
            identity_id = credentials['identity_id']
    
    # If there's no identity_id or it's not valid, create new identity
    if not identity_id:
        response = cognito_client.get_id(
            IdentityPoolId=identity_pool_id
        )
        identity_id = response['IdentityId']
    
    # Fetch new credentials for the existing or new identity
    response = cognito_client.get_credentials_for_identity(
        IdentityId=identity_id
    )
    credentials = response['Credentials']

    credentials_dict = {
        'identity_id': identity_id,
        'access_key_id': credentials['AccessKeyId'],
        'secret_access_key': credentials['SecretKey'],
        'session_token': credentials['SessionToken'],
        'expiration': credentials['Expiration']
    }
    
    with open(credentials_file, 'wb') as f:
        pickle.dump(credentials_dict, f)
    
    return credentials_dict

def get_boto3_client(service_name, credentials):
    session = Session(
        aws_access_key_id=credentials['access_key_id'],
        aws_secret_access_key=credentials['secret_access_key'],
        aws_session_token=credentials['session_token'],
        region_name=region_name
    )
    return session.client(service_name)

def process_test_case(test_case):
    # Simulate test execution
    time.sleep(2)  # Simulate 2 seconds of testing
    return random.choice(['pass', 'fail', 'not-executed'])

def main():
    try:
        credentials = assume_role_with_web_identity()

        dynamodb = get_boto3_client('dynamodb', credentials)
        sqs = get_boto3_client('sqs', credentials)
        lambda_client = get_boto3_client('lambda', credentials)

        print('waiting for tests...')

        while True:
            # Poll SQS for new messages
            response = sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20  # Long polling
            )

            messages = response.get('Messages', [])
            if not messages:
                continue

            for message in messages:
                body = json.loads(message['Body'])
                test_execution_id = body.get('testExecutionId', '')

                print(f'new test execution request received id: {test_execution_id}')

                # Retrieve test cases from DynamoDB
                response = dynamodb.get_item(
                    TableName=table_name_test_cases,
                    Key={'testExecutionId': {'S': test_execution_id}}
                )
                tests = json.loads(response.get('Item', {}).get('tests', {}).get('S', '[]'))

                print(f'executing tests: {tests}')

                # Execute tests
                results = []
                for test in tests:
                    test_result = process_test_case(test)
                    results.append({
                        'id': test['id'],
                        'name': test['name'],
                        'result': test_result
                    })

                print(f'test results: {results}')

                # Save test results to DynamoDB
                dynamodb.put_item(
                    TableName=table_name_test_results,
                    Item={
                        'testExecutionId': {'S': test_execution_id},
                        'timestamp': {'S': datetime.now(UTC).isoformat() + 'Z'},
                        'results': {'S': json.dumps(results)}
                    }
                )

                # Invoke Lambda function to send results
                lambda_client.invoke(
                    FunctionName=lambda_function_name,
                    InvocationType='Event',
                    Payload=json.dumps({'testExecutionId': test_execution_id})
                )

                print('notified aws of test results')

                # Delete message from SQS after processing
                sqs.delete_message(
                    QueueUrl=queue_url,
                    ReceiptHandle=message['ReceiptHandle']
                )

    except (NoCredentialsError, PartialCredentialsError) as e:
        print(f"Error obtaining temporary credentials: {e}")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
