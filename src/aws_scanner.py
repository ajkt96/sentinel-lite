"""AWS IAM Scanner Implementation"""

import boto3
from typing import List, Dict


class AWSIAMScanner:

    def __init__(self, region="us-east-1"):
        self.iam_client = boto3.client('iam', region_name=region)
        self.account_id = None

    def connect(self) -> bool:
        try:
            sts = boto3.client('sts')
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            print(f"Connected to AWS Account: {self.account_id}")
            return True
        except Exception as e:
            print(f"Error connecting to AWS: {e}")
            return False

    def list_all_roles(self) -> List[str]:
        try:
            roles = []
            paginator = self.iam_client.get_paginator('list_roles')
            for page in paginator.paginate():
                roles.extend([r['RoleName'] for r in page['Roles']])
            return roles
        except Exception as e:
            print(f"Error listing roles: {e}")
            return []

    def get_role_policies(self, role_name: str) -> Dict:
        try:
            policies = {}
            attached = self.iam_client.list_attached_role_policies(RoleName=role_name)
            policies['attached'] = [p['PolicyName'] for p in attached['AttachedPolicies']]
            inline = self.iam_client.list_role_policies(RoleName=role_name)
            policies['inline'] = inline['PolicyNames']
            return policies
        except Exception as e:
            print(f"Error getting policies for {role_name}: {e}")
            return {}


if __name__ == "__main__":
    scanner = AWSIAMScanner()
    if scanner.connect():
        roles = scanner.list_all_roles()
        print(f"Found {len(roles)} roles")
        for role in roles[:5]:
            print(f"  - {role}")
