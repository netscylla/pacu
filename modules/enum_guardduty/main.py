#!/usr/bin/env python3
import argparse
from botocore.exceptions import ClientError
import datetime


module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'enum_guardduty',

    # Name and any other notes about the author
    'author': 'netscylla <wolverine@netscylla.com>',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'recon_enum_with_keys',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Enumerates data About GuardDuty',

    # Full description about what the module does and how it works
    'description': 'Determines information about the AWS GuardDuty',

    # A list of AWS services that the module utilizes during its execution
    'services': ['Guardduty'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': [],

    # External resources that the module depends on. Valid options are either a GitHub URL (must end in .git) or single file URL.
    'external_dependencies': [],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': [],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])

parser.add_argument(
    '--regions',
    required=False,
    default=None,
    help='One or more (comma separated) AWS regions in the format "us-east-1". Defaults to all available regions.'
)
parser.add_argument(
    '--global-region',
    required=False,
    default=False,
    action='store_true',
    help='Flag to enumerate GuardDuty information for all regions.'
)

# Main is the first function that is called when this module is executed
def main(args, pacu_main):
    session = pacu_main.get_active_session()

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)
    print = pacu_main.print
    get_regions = pacu_main.get_regions
    regions = get_regions('guardduty') if args.regions is None else args.regions.split(',')

    ######

    for region in regions:
        print("Cheching Guardduty in: " + region)
        sts_client = pacu_main.get_boto3_client('sts')
        response = sts_client.get_caller_identity()
        key_arn = response['Arn']
        account_id = response['Account']

        gd_client = pacu_main.get_boto3_client('guardduty',region)
        detectors = gd_client.list_detectors()

        for detector in detectors['DetectorIds']:
            print("Found detector: %s" % detector)
            threatlists=gd_client.list_threat_intel_sets(DetectorId=detector)
            for threatlist in threatlists['ThreatIntelSetIds']:
                print("Found Threatlist: %s" % threatlist)
                threatlist_data=gd_client.get_threat_intel_set(DetectorId=detector,ThreatIntelSetId=threatlist)
                formatted_gdcmd_data = 'Found: {} {} {} {}'.format(
                    threatlist_data['Name'],
                    threatlist_data['Location'],
                    threatlist_data['Format'],
                    threatlist_data['Status']
                )
                print(formatted_gdcmd_data)

            iplists=gd_client.list_ip_sets(DetectorId=detector)
            for iplist in iplists['IpSetIds']:
                print("Found Whitelist: %s" % iplist)
                iplist_data=gd_client.get_ip_set(DetectorId=detector,IpSetId=iplist)
                formatted_gdcmd_data = 'Found: {} {} {} {}'.format(
                    iplist_data['Name'],
                    iplist_data['Location'],
                    iplist_data['Format'],
                    iplist_data['Status']
                )
                print(formatted_gdcmd_data)
