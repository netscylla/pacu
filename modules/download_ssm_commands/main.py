#!/usr/bin/env python3
import argparse
import base64
import boto3
from botocore.exceptions import ClientError
from functools import partial
import os



module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'download_ssm_commands',

    # Name and any other notes about the author
    'author': 'John @ Netscylla',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Downloads command data issued to EC2 instances from SSM.',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # Description about what the module does and how it works
    'description': 'This module will take a list of EC2 instance IDs and request then download the SSM Command associated with each instance. All of the data will be saved to ./sessions/[session_name]/downloads/command_data.txt.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['EC2'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['enum_ec2_instances'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--instance-ids'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument('--instance-ids', required=False, default=None, help='One or more (comma separated) EC2 instance IDs with their regions in the format instance_id@region. Defaults to all EC2 instances.')


def help():
    return [module_info, parser.format_help()]


def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    fetch_data = pacu_main.fetch_data
    ######

    instances = []

    # Check permissions before doing anything
    try:
        client = boto3.client(
            'ssm',
            region_name='us-east-1',
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token
        )
        dryrun = client.list_commands(
            InstanceId='1'
        )
    except ClientError as e:
        if not str(e).find('UnauthorizedOperation') == -1:
            print('Dry run failed, the current AWS account does not have the necessary permissions to run "list_commands".\nExiting module.')
            return

    if args.instance_ids is not None:
        for instance in args.instance_ids.split(','):
            instances.append({
                'InstanceId': instance.split('@')[0],
                'Region': instance.split('@')[1]
            })
    else:
        if fetch_data(['EC2', 'Instances'], 'enum_ec2', '--instances') is False:
            print('Pre-req module not run successfully. Exiting...')
            return
        instances = session.EC2['Instances']

    if not os.path.exists(f'sessions/{session.name}/downloads/'):
        os.makedirs(f'sessions/{session.name}/downloads/')

    for instance in instances:
        client = boto3.client(
            'ssm',
            region_name=instance['Region'],
            aws_access_key_id=session.access_key_id,
            aws_secret_access_key=session.secret_access_key,
            aws_session_token=session.session_token
        )

        cmd_data = client.list_commands(
            InstanceId=instance['InstanceId']
        )

        if (len(cmd_data['Commands']) > 0):
            #'Commands' in cmd_data.keys():
            for element in range(0, len(cmd_data['Commands'])):
                formatted_cmd_data = '{}@{}:\n{}\n{}\n'.format(
                    instance['InstanceId'],
                    instance['Region'],
                    cmd_data['Commands'][element]['CommandId'],
                    cmd_data['Commands'][element]['Parameters']['commands']
                )

                print(formatted_cmd_data)

                with open(f'sessions/{session.name}/downloads/command_data.txt', 'a+') as data_file:
                    data_file.write(formatted_cmd_data)


                cmd_data_response = client.get_command_invocation(
                    InstanceId=instance['InstanceId'],
                    CommandId=cmd_data['Commands'][element]['CommandId']
                )
                if 'StandardOutputContent' in cmd_data_response.keys():
                    print(cmd_data_response['StandardOutputContent'])
                    formatted_rcmd_data = '{}@{}:\n{}\n{}\n{}\n'.format(
                        instance['InstanceId'],
                        instance['Region'],
                        cmd_data['Commands'][element]['CommandId'],
                        cmd_data['Commands'][element]['Parameters']['commands'],
                        cmd_data_response['StandardOutputContent']
                    )
                    with open(f'sessions/{session.name}/downloads/command_data_response.txt', 'a+') as data_file:
                        data_file.write(formatted_rcmd_data)
                else:
                    print(f"{instance['InstanceId']}@{instance['Region']}: No cmd response data")

        else:
            print(f"{instance['InstanceId']}@{instance['Region']}: No cmd data")

    print(f'{os.path.basename(__file__)} completed.')
    return
