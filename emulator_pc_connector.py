import boto3
import json
from datetime import datetime, UTC
import random
import time
import pickle
import os
from boto3.session import Session
from botocore.exceptions import NoCredentialsError, PartialCredentialsError
import emulator
import sys
import traceback

# Configuration
identity_pool_id = 'us-east-1:128a3c5b-f4b0-45e7-bee4-4302060554ab'
region_name = 'us-east-1'
table_name_test_cases = 'hiltesting-test-cases'
table_name_test_results = 'hiltesting-test-results'
queue_url = 'https://sqs.us-east-1.amazonaws.com/381492230851/hiltesting-test-execution-event'
lambda_function_name = 'hiltesting-websocket-web-client-update-handler'
credentials_file = 'aws_credentials.pkl'

def assume_role_with_web_identity():
    """
    Assumes a role with web identity using AWS Cognito to get temporary credentials.

    This function checks if valid credentials are available in a local file. If not, it fetches
    a new Cognito Identity ID and obtains temporary credentials for that identity. The credentials
    are then saved to the file for future use.

    Returns:
        dict: A dictionary containing AWS credentials including `identity_id`, `access_key_id`,
              `secret_access_key`, `session_token`, and `expiration`.
    """
        
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
    """
    Creates a Boto3 client for a specified AWS service using temporary credentials.

    Args:
        service_name (str): The name of the AWS service to create a client for (e.g., 'dynamodb', 'sqs', 'lambda').
        credentials (dict): A dictionary containing AWS credentials including `access_key_id`,
                             `secret_access_key`, and `session_token`.

    Returns:
        boto3.client: A Boto3 client for the specified AWS service.
    """

    session = Session(
        aws_access_key_id=credentials['access_key_id'],
        aws_secret_access_key=credentials['secret_access_key'],
        aws_session_token=credentials['session_token'],
        region_name=region_name
    )
    return session.client(service_name)


def update_results(results, test_cases):
    """
    Updates the results list of dictionaries to add the test case name string

    Args:
        results (list): List of test results received from emulator. Each test result is a dictionary
                            with keys 'id', 'len', 'data' and 'result'
        test_cases (list): List of test cases used for exection. Each test case is a dictionary
                            with keys 'id', 'len', 'data' (relating to TLV format) and 'name'

    Returns:
        boto3.client: Updated results list of dictionaries
    """
    id_to_name = {int(test['id']): test['name'] for test in test_cases}

    for result in results:
        result_id = result['id']
        result['name'] = id_to_name.get(result_id, "Unknown")  # Default to "Unknown" if ID not found

    return results

def process_test_case(test_case):
    # Simulate test execution
    time.sleep(2)  # Simulate 2 seconds of testing
    return random.choice(['pass', 'fail', 'not-executed'])

def main():
    """
    Main function to start the test emulator.

    Initializes the serial port, retrieves AWS credentials, sets up AWS service clients,
    and processes test cases retrieved from an SQS queue. The results of the tests are stored
    in DynamoDB, and a Lambda function is invoked to notify AWS of the test results.
    """


    print('Test emulator starting...')

    # Initialize serial port
    ser = emulator.init_serial(sys.argv[1])

    try:
        credentials = assume_role_with_web_identity()

        dynamodb = get_boto3_client('dynamodb', credentials)
        sqs = get_boto3_client('sqs', credentials)
        lambda_client = get_boto3_client('lambda', credentials)

        print('Waiting for tests...')

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

                print(f'New test execution request received id: {test_execution_id}')

                # Retrieve test cases from DynamoDB
                response = dynamodb.get_item(
                    TableName=table_name_test_cases,
                    Key={'testExecutionId': {'S': test_execution_id}}
                )
                tests_json = response.get('Item', {}).get('tests', {}).get('S', '[]')
                tests = json.loads(tests_json)

                test_cases = [{'id': test['id'], 'len': test.get('len', ''), 'data': test.get('data', ''), 'name': test.get('name', '')} for test in tests]

                print(f'Executing tests: {tests}')
                #print(f'executing tests: {test_cases}')
                
                reply_packet = emulator.send_tests(test_cases)
                results = emulator.process_reply_packet(reply_packet)
                results = update_results(results, test_cases)
                           
                print(f'Test results: {results}')

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
        traceback.print_exc()
    except Exception as e:
        print(f"An error occurred: {e}")
        traceback.print_exc()

if __name__ == "__main__":
    main()
