import boto3
import json
from datetime import datetime
import sys

def get_name_from_tags(tags):
    """Extract the Name from AWS resource tags"""
    if not tags:
        return "Unnamed"
    
    for tag in tags:
        if tag.get('Key') == 'Name':
            return tag.get('Value')
    
    return "Unnamed"

def get_profile_and_account_info():
    """Prompt for AWS profile and confirm account details"""
    # Get list of available profiles
    import botocore.session
    session = botocore.session.Session()
    profiles = session.available_profiles
    
    if not profiles:
        print("No AWS profiles found. Please configure AWS CLI first using 'aws configure'.")
        sys.exit(1)
    
    # Display available profiles
    print("Available AWS profiles:")
    for i, profile in enumerate(profiles, 1):
        print(f"{i}. {profile}")
    
    # Prompt for profile selection
    while True:
        try:
            if len(profiles) == 1:
                print(f"\nOnly one profile available, using '{profiles[0]}'")
                profile_name = profiles[0]
                break
            else:
                selection = input("\nEnter profile number or name (or press Enter for default): ")
                
                if not selection:
                    profile_name = "default"
                    break
                
                if selection.isdigit() and 1 <= int(selection) <= len(profiles):
                    profile_name = profiles[int(selection) - 1]
                    break
                elif selection in profiles:
                    profile_name = selection
                    break
                else:
                    print("Invalid selection. Please try again.")
        except Exception as e:
            print(f"Error: {str(e)}")
    
    # Create session with selected profile
    try:
        session = boto3.Session(profile_name=profile_name)
        sts = session.client('sts')
        
        # Get account info
        identity = sts.get_caller_identity()
        account_id = identity['Account']
        iam_arn = identity['Arn']
        user_id = identity['UserId']
        
        # Display account information for confirmation
        print("\nAWS Account Information:")
        print(f"Profile: {profile_name}")
        print(f"Account ID: {account_id}")
        print(f"IAM ARN: {iam_arn}")
        
        # Confirm account
        confirmation = input("\nIs this the correct account? (yes/no): ").lower()
        if confirmation not in ['y', 'yes']:
            print("Aborting operation.")
            sys.exit(0)
        
        return session, account_id
        
    except Exception as e:
        print(f"Error connecting to AWS with profile '{profile_name}': {str(e)}")
        sys.exit(1)

def get_vpc_information(session):
    """Get detailed VPC information using the provided boto3 session"""
    # Initialize boto3 EC2 client with the session
    ec2 = session.client('ec2')
    
    # Get all VPCs
    vpc_response = ec2.describe_vpcs()
    
    # Dictionary to store all VPC information
    vpc_info = {}
    
    # Get all DHCP options sets
    dhcp_options_response = ec2.describe_dhcp_options()
    dhcp_options = {opt['DhcpOptionsId']: opt for opt in dhcp_options_response['DhcpOptions']}
    
    # Get all VPC endpoints
    try:
        endpoints_response = ec2.describe_vpc_endpoints()
        endpoints = {}
        for endpoint in endpoints_response.get('VpcEndpoints', []):
            vpc_id = endpoint['VpcId']
            if vpc_id not in endpoints:
                endpoints[vpc_id] = []
            endpoints[vpc_id].append(endpoint)
    except Exception as e:
        print(f"Warning: Could not retrieve VPC endpoints: {str(e)}")
        endpoints = {}
    
    # Get all peering connections
    try:
        peering_response = ec2.describe_vpc_peering_connections()
        peering_connections = {}
        for conn in peering_response.get('VpcPeeringConnections', []):
            accepter_vpc = conn['AccepterVpcInfo']['VpcId']
            requester_vpc = conn['RequesterVpcInfo']['VpcId']
            
            if accepter_vpc not in peering_connections:
                peering_connections[accepter_vpc] = []
            if requester_vpc not in peering_connections:
                peering_connections[requester_vpc] = []
                
            peering_connections[accepter_vpc].append(conn)
            if accepter_vpc != requester_vpc:  # Avoid duplicate if peering with self
                peering_connections[requester_vpc].append(conn)
    except Exception as e:
        print(f"Warning: Could not retrieve VPC peering connections: {str(e)}")
        peering_connections = {}
    
    # Get Network ACLs
    nacl_response = ec2.describe_network_acls()
    nacls = {}
    for nacl in nacl_response['NetworkAcls']:
        vpc_id = nacl['VpcId']
        if vpc_id not in nacls:
            nacls[vpc_id] = []
        nacls[vpc_id].append(nacl)
    
    # Get security groups
    sg_response = ec2.describe_security_groups()
    security_groups = {}
    for sg in sg_response['SecurityGroups']:
        vpc_id = sg['VpcId']
        if vpc_id not in security_groups:
            security_groups[vpc_id] = []
        security_groups[vpc_id].append(sg)
    
    # Get NAT gateways
    try:
        nat_response = ec2.describe_nat_gateways()
        nat_gateways = {}
        for nat in nat_response.get('NatGateways', []):
            vpc_id = nat['VpcId']
            if vpc_id not in nat_gateways:
                nat_gateways[vpc_id] = []
            nat_gateways[vpc_id].append(nat)
    except Exception as e:
        print(f"Warning: Could not retrieve NAT gateways: {str(e)}")
        nat_gateways = {}
    
    # Get internet gateways
    igw_response = ec2.describe_internet_gateways()
    internet_gateways = {}
    for igw in igw_response['InternetGateways']:
        for attachment in igw.get('Attachments', []):
            vpc_id = attachment.get('VpcId')
            if vpc_id:
                internet_gateways[vpc_id] = igw
    
    # Get flow logs
    try:
        flow_logs_response = ec2.describe_flow_logs()
        flow_logs = {}
        for flow_log in flow_logs_response.get('FlowLogs', []):
            resource_id = flow_log.get('ResourceId')
            if resource_id and resource_id.startswith('vpc-'):
                if resource_id not in flow_logs:
                    flow_logs[resource_id] = []
                flow_logs[resource_id].append(flow_log)
    except Exception as e:
        print(f"Warning: Could not retrieve flow logs: {str(e)}")
        flow_logs = {}
    
    # Get instances for subnet mapping
    instances_response = ec2.describe_instances()
    subnet_instances = {}
    for reservation in instances_response.get('Reservations', []):
        for instance in reservation.get('Instances', []):
            subnet_id = instance.get('SubnetId')
            if subnet_id:
                if subnet_id not in subnet_instances:
                    subnet_instances[subnet_id] = []
                subnet_instances[subnet_id].append({
                    'InstanceId': instance['InstanceId'],
                    'InstanceType': instance.get('InstanceType', 'N/A'),
                    'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
                    'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
                    'State': instance.get('State', {}).get('Name', 'N/A'),
                    'Tags': instance.get('Tags', [])
                })
    
    # Iterate through each VPC
    for vpc in vpc_response['Vpcs']:
        vpc_id = vpc['VpcId']
        
        # Get DNS settings
        dns_settings = {
            'EnableDnsSupport': False, 
            'EnableDnsHostnames': False
        }
        
        try:
            dns_support = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute='enableDnsSupport')
            dns_hostnames = ec2.describe_vpc_attribute(VpcId=vpc_id, Attribute='enableDnsHostnames')
            dns_settings['EnableDnsSupport'] = dns_support.get('EnableDnsSupport', {}).get('Value', False)
            dns_settings['EnableDnsHostnames'] = dns_hostnames.get('EnableDnsHostnames', {}).get('Value', False)
        except Exception as e:
            print(f"Warning: Could not retrieve DNS settings for VPC {vpc_id}: {str(e)}")
        
        vpc_info[vpc_id] = {
            'VpcId': vpc_id,
            'CidrBlock': vpc['CidrBlock'],
            'State': vpc['State'],
            'IsDefault': vpc['IsDefault'],
            'DhcpOptionsId': vpc.get('DhcpOptionsId'),
            'DhcpOptions': dhcp_options.get(vpc.get('DhcpOptionsId'), {}),
            'Ipv6CidrBlockAssociationSet': vpc.get('Ipv6CidrBlockAssociationSet', []),
            'CidrBlockAssociationSet': vpc.get('CidrBlockAssociationSet', []),
            'InstanceTenancy': vpc.get('InstanceTenancy'),
            'Tags': vpc.get('Tags', []),
            'DnsSettings': dns_settings,
            'Endpoints': endpoints.get(vpc_id, []),
            'PeeringConnections': peering_connections.get(vpc_id, []),
            'NetworkAcls': nacls.get(vpc_id, []),
            'SecurityGroups': security_groups.get(vpc_id, []),
            'NatGateways': nat_gateways.get(vpc_id, []),
            'InternetGateway': internet_gateways.get(vpc_id, {}),
            'FlowLogs': flow_logs.get(vpc_id, []),
            'Subnets': []
        }
    
    # Get all subnets
    subnet_response = ec2.describe_subnets()
    
    # Get all route tables
    route_tables_response = ec2.describe_route_tables()
    
    # Create a lookup dictionary for route tables
    route_tables = {}
    subnet_to_route_table = {}
    
    # Process all route tables
    for rt in route_tables_response['RouteTables']:
        rt_id = rt['RouteTableId']
        vpc_id = rt['VpcId']
        
        # Extract routes information
        routes = []
        for route in rt['Routes']:
            route_info = {
                'DestinationCidrBlock': route.get('DestinationCidrBlock', 'N/A'),
                'DestinationIpv6CidrBlock': route.get('DestinationIpv6CidrBlock', 'N/A'),
                'GatewayId': route.get('GatewayId', 'N/A'),
                'NatGatewayId': route.get('NatGatewayId', 'N/A'),
                'InstanceId': route.get('InstanceId', 'N/A'),
                'VpcPeeringConnectionId': route.get('VpcPeeringConnectionId', 'N/A'),
                'TransitGatewayId': route.get('TransitGatewayId', 'N/A'),
                'LocalGatewayId': route.get('LocalGatewayId', 'N/A'),
                'CarrierGatewayId': route.get('CarrierGatewayId', 'N/A'),
                'NetworkInterfaceId': route.get('NetworkInterfaceId', 'N/A'),
                'VpcEndpointId': route.get('VpcEndpointId', 'N/A'),
                'State': route.get('State', 'N/A'),
                'Origin': route.get('Origin', 'N/A')
            }
            # Remove N/A values for cleaner output
            routes.append({k: v for k, v in route_info.items() if v != 'N/A'})
        
        route_table_info = {
            'RouteTableId': rt_id,
            'VpcId': vpc_id,
            'Routes': routes,
            'Tags': rt.get('Tags', []),
            'Associations': rt.get('Associations', [])
        }
        
        route_tables[rt_id] = route_table_info
        
        # Map subnets to this route table
        for assoc in rt.get('Associations', []):
            if 'SubnetId' in assoc:
                subnet_to_route_table[assoc['SubnetId']] = rt_id
    
    # Get Network ACL associations for subnets
    subnet_to_nacl = {}
    for vpc_id, nacl_list in nacls.items():
        for nacl in nacl_list:
            for assoc in nacl.get('Associations', []):
                if 'SubnetId' in assoc:
                    subnet_to_nacl[assoc['SubnetId']] = nacl['NetworkAclId']
    
    # Add subnets to their respective VPCs
    for subnet in subnet_response['Subnets']:
        vpc_id = subnet['VpcId']
        subnet_id = subnet['SubnetId']
        
        if vpc_id in vpc_info:
            # Get the route table for this subnet
            route_table_id = subnet_to_route_table.get(subnet_id, 'No explicit association')
            
            # Find the main route table for the VPC if the subnet doesn't have an explicit association
            if route_table_id == 'No explicit association':
                for rt_id, rt_info in route_tables.items():
                    if rt_info['VpcId'] == vpc_id:
                        for assoc in rt_info.get('Associations', []):
                            if assoc.get('Main', False):
                                route_table_id = rt_id
                                break
            
            subnet_info = {
                'SubnetId': subnet_id,
                'CidrBlock': subnet['CidrBlock'],
                'AvailabilityZone': subnet['AvailabilityZone'],
                'AvailabilityZoneId': subnet.get('AvailabilityZoneId', 'N/A'),
                'State': subnet['State'],
                'Tags': subnet.get('Tags', []),
                'MapPublicIpOnLaunch': subnet.get('MapPublicIpOnLaunch', False),
                'AssignIpv6AddressOnCreation': subnet.get('AssignIpv6AddressOnCreation', False),
                'Ipv6CidrBlockAssociationSet': subnet.get('Ipv6CidrBlockAssociationSet', []),
                'AvailableIpAddressCount': subnet.get('AvailableIpAddressCount', 0),
                'DefaultForAz': subnet.get('DefaultForAz', False),
                'CustomerOwnedIpv4Pool': subnet.get('CustomerOwnedIpv4Pool', 'N/A'),
                'MapCustomerOwnedIpOnLaunch': subnet.get('MapCustomerOwnedIpOnLaunch', False),
                'OutpostArn': subnet.get('OutpostArn', 'N/A'),
                'NetworkAclId': subnet_to_nacl.get(subnet_id, 'Default NACL'),
                'RouteTableId': route_table_id,
                'RouteTable': route_tables.get(route_table_id, {}) if route_table_id != 'No explicit association' else 'Using Main Route Table',
                'Instances': subnet_instances.get(subnet_id, [])
            }
            
            # Remove N/A values for cleaner output
            subnet_info = {k: v for k, v in subnet_info.items() if v != 'N/A'}
            
            vpc_info[vpc_id]['Subnets'].append(subnet_info)
    
    return vpc_info

def print_vpc_info(vpc_info, account_id):
    print("\n" + "="*120)
    print("AWS VPC INFORMATION REPORT".center(120))
    print(f"Account ID: {account_id}".center(120))
    print("Generated at: " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("="*120)
    
    for vpc_id, vpc_data in vpc_info.items():
        vpc_name = get_name_from_tags(vpc_data.get('Tags', []))
        print(f"\n{'='*60} VPC: {vpc_name} ({vpc_id}) {'='*60}")
        print(f"CIDR Block: {vpc_data['CidrBlock']}")
        print(f"State: {vpc_data['State']}")
        print(f"Is Default: {vpc_data['IsDefault']}")
        
        # Print additional CIDR blocks if any
        if vpc_data.get('CidrBlockAssociationSet'):
            print("Additional CIDR Blocks:")
            for cidr_assoc in vpc_data['CidrBlockAssociationSet']:
                print(f"  - {cidr_assoc.get('CidrBlock', 'N/A')} ({cidr_assoc.get('State', 'N/A')})")
        
        # Print IPv6 CIDR blocks if any
        if vpc_data.get('Ipv6CidrBlockAssociationSet'):
            print("IPv6 CIDR Blocks:")
            for ipv6_cidr_assoc in vpc_data['Ipv6CidrBlockAssociationSet']:
                print(f"  - {ipv6_cidr_assoc.get('Ipv6CidrBlock', 'N/A')} ({ipv6_cidr_assoc.get('State', 'N/A')})")
        
        print(f"Instance Tenancy: {vpc_data.get('InstanceTenancy', 'default')}")
        print(f"DHCP Options ID: {vpc_data.get('DhcpOptionsId', 'N/A')}")
        
        # Print DNS settings
        dns_settings = vpc_data.get('DnsSettings', {})
        print(f"DNS Support: {'Enabled' if dns_settings.get('EnableDnsSupport', False) else 'Disabled'}")
        print(f"DNS Hostnames: {'Enabled' if dns_settings.get('EnableDnsHostnames', False) else 'Disabled'}")
        
        # Print DHCP Options details if available
        dhcp_options = vpc_data.get('DhcpOptions', {})
        if dhcp_options and 'DhcpConfigurations' in dhcp_options:
            print("\nDHCP Options:")
            for config in dhcp_options['DhcpConfigurations']:
                key = config.get('Key', 'N/A')
                values = ', '.join([v.get('Value', 'N/A') for v in config.get('Values', [])])
                print(f"  {key}: {values}")
        
        # Print VPC tags
        if vpc_data.get('Tags'):
            print("\nVPC Tags:")
            for tag in vpc_data['Tags']:
                print(f"  - {tag['Key']}: {tag['Value']}")
        
        # Print Internet Gateway
        if vpc_data.get('InternetGateway'):
            igw = vpc_data['InternetGateway']
            igw_id = igw.get('InternetGatewayId', 'N/A')
            igw_name = get_name_from_tags(igw.get('Tags', []))
            if igw_name != "Unnamed":
                print(f"\nInternet Gateway: {igw_name} ({igw_id})")
            else:
                print(f"\nInternet Gateway: {igw_id}")
            
            if 'Tags' in igw and igw['Tags']:
                print("  Tags:")
                for tag in igw['Tags']:
                    if tag['Key'] != 'Name':  # Skip Name tag as we already displayed it
                        print(f"    - {tag['Key']}: {tag['Value']}")
        
        # Print NAT Gateways
        nat_gateways = vpc_data.get('NatGateways', [])
        if nat_gateways:
            print(f"\nNAT Gateways ({len(nat_gateways)}):")
            for i, nat in enumerate(nat_gateways, 1):
                nat_id = nat.get('NatGatewayId', 'N/A')
                nat_name = get_name_from_tags(nat.get('Tags', []))
                if nat_name != "Unnamed":
                    print(f"  {i}. NAT Gateway: {nat_name} ({nat_id})")
                else:
                    print(f"  {i}. NAT Gateway ID: {nat_id}")
                    
                print(f"     State: {nat.get('State', 'N/A')}")
                print(f"     Subnet ID: {nat.get('SubnetId', 'N/A')}")
                print(f"     Public IP: {nat.get('NatGatewayAddresses', [{}])[0].get('PublicIp', 'N/A') if nat.get('NatGatewayAddresses') else 'N/A'}")
                print(f"     Private IP: {nat.get('NatGatewayAddresses', [{}])[0].get('PrivateIp', 'N/A') if nat.get('NatGatewayAddresses') else 'N/A'}")
                if nat.get('Tags'):
                    print("     Tags:")
                    for tag in nat['Tags']:
                        if tag['Key'] != 'Name':  # Skip Name tag as we already displayed it
                            print(f"       - {tag['Key']}: {tag['Value']}")
        
        # Print VPC Endpoints
        endpoints = vpc_data.get('Endpoints', [])
        if endpoints:
            print(f"\nVPC Endpoints ({len(endpoints)}):")
            for i, endpoint in enumerate(endpoints, 1):
                endpoint_id = endpoint.get('VpcEndpointId', 'N/A')
                endpoint_name = get_name_from_tags(endpoint.get('Tags', []))
                if endpoint_name != "Unnamed":
                    print(f"  {i}. Endpoint: {endpoint_name} ({endpoint_id})")
                else:
                    print(f"  {i}. Endpoint ID: {endpoint_id}")
                    
                print(f"     Type: {endpoint.get('VpcEndpointType', 'N/A')}")
                print(f"     Service Name: {endpoint.get('ServiceName', 'N/A')}")
                print(f"     State: {endpoint.get('State', 'N/A')}")
                if endpoint.get('Tags'):
                    print("     Tags:")
                    for tag in endpoint['Tags']:
                        if tag['Key'] != 'Name':  # Skip Name tag as we already displayed it
                            print(f"       - {tag['Key']}: {tag['Value']}")
        
        # Print VPC Peering Connections
        peering_connections = vpc_data.get('PeeringConnections', [])
        if peering_connections:
            print(f"\nVPC Peering Connections ({len(peering_connections)}):")
            for i, peering in enumerate(peering_connections, 1):
                peering_id = peering.get('VpcPeeringConnectionId', 'N/A')
                peering_name = get_name_from_tags(peering.get('Tags', []))
                if peering_name != "Unnamed":
                    print(f"  {i}. Peering: {peering_name} ({peering_id})")
                else:
                    print(f"  {i}. Peering ID: {peering_id}")
                    
                print(f"     Status: {peering.get('Status', {}).get('Code', 'N/A')}")
                accepter_vpc_id = peering.get('AccepterVpcInfo', {}).get('VpcId', 'N/A')
                accepter_cidr = peering.get('AccepterVpcInfo', {}).get('CidrBlock', 'N/A')
                print(f"     Accepter VPC: {accepter_vpc_id} ({accepter_cidr})")
                requester_vpc_id = peering.get('RequesterVpcInfo', {}).get('VpcId', 'N/A')
                requester_cidr = peering.get('RequesterVpcInfo', {}).get('CidrBlock', 'N/A')
                print(f"     Requester VPC: {requester_vpc_id} ({requester_cidr})")
                if peering.get('Tags'):
                    print("     Tags:")
                    for tag in peering['Tags']:
                        if tag['Key'] != 'Name':  # Skip Name tag as we already displayed it
                            print(f"       - {tag['Key']}: {tag['Value']}")
        
        # Print Flow Logs
        flow_logs = vpc_data.get('FlowLogs', [])
        if flow_logs:
            print(f"\nVPC Flow Logs ({len(flow_logs)}):")
            for i, flow_log in enumerate(flow_logs, 1):
                flow_log_id = flow_log.get('FlowLogId', 'N/A')
                print(f"  {i}. Flow Log ID: {flow_log_id}")
                print(f"     Log Destination: {flow_log.get('LogDestination', 'N/A')}")
                print(f"     Log Format: {flow_log.get('LogFormat', 'N/A')}")
                print(f"     Traffic Type: {flow_log.get('TrafficType', 'N/A')}")
                print(f"     Deliver Logs Status: {flow_log.get('DeliverLogsStatus', 'N/A')}")
        
        # Print Network ACLs
        nacls = vpc_data.get('NetworkAcls', [])
        if nacls:
            print(f"\nNetwork ACLs ({len(nacls)}):")
            for i, nacl in enumerate(nacls, 1):
                nacl_id = nacl.get('NetworkAclId', 'N/A')
                nacl_name = get_name_from_tags(nacl.get('Tags', []))
                if nacl_name != "Unnamed":
                    print(f"  {i}. Network ACL: {nacl_name} ({nacl_id})")
                else:
                    print(f"  {i}. Network ACL ID: {nacl_id}")
                    
                print(f"     Is Default: {nacl.get('IsDefault', False)}")
                
                # Print inbound entries
                inbound = [entry for entry in nacl.get('Entries', []) if not entry.get('Egress', False)]
                if inbound:
                    print(f"     Inbound Rules ({len(inbound)}):")
                    for rule in sorted(inbound, key=lambda x: x.get('RuleNumber', 0)):
                        print(f"       - Rule #{rule.get('RuleNumber', 'N/A')}: {rule.get('CidrBlock', 'N/A')} "
                              f"{rule.get('Protocol', 'N/A')} {rule.get('PortRange', {}).get('From', '*')}-"
                              f"{rule.get('PortRange', {}).get('To', '*')} {rule.get('RuleAction', 'N/A')}")
                
                # Print outbound entries
                outbound = [entry for entry in nacl.get('Entries', []) if entry.get('Egress', False)]
                if outbound:
                    print(f"     Outbound Rules ({len(outbound)}):")
                    for rule in sorted(outbound, key=lambda x: x.get('RuleNumber', 0)):
                        print(f"       - Rule #{rule.get('RuleNumber', 'N/A')}: {rule.get('CidrBlock', 'N/A')} "
                              f"{rule.get('Protocol', 'N/A')} {rule.get('PortRange', {}).get('From', '*')}-"
                              f"{rule.get('PortRange', {}).get('To', '*')} {rule.get('RuleAction', 'N/A')}")
                
                # Print associations
                if nacl.get('Associations'):
                    print("     Associated Subnets:")
                    for assoc in nacl['Associations']:
                        print(f"       - {assoc.get('SubnetId', 'N/A')}")
        
        # Print Security Groups summary
        security_groups = vpc_data.get('SecurityGroups', [])
        if security_groups:
            print(f"\nSecurity Groups ({len(security_groups)}):")
            for i, sg in enumerate(security_groups, 1):
                sg_name = sg.get('GroupName', 'N/A')
                sg_id = sg.get('GroupId', 'N/A')
                print(f"  {i}. {sg_name} ({sg_id})")
                print(f"     Description: {sg.get('Description', 'N/A')}")
                
                # Print inbound rules summary
                if sg.get('IpPermissions'):
                    print(f"     Inbound Rules: {len(sg['IpPermissions'])}")
                
                # Print outbound rules summary
                if sg.get('IpPermissionsEgress'):
                    print(f"     Outbound Rules: {len(sg['IpPermissionsEgress'])}")
        
        # Print Subnets
        print("\n" + "-"*60 + " SUBNETS " + "-"*60)
        if vpc_data['Subnets']:
            for i, subnet in enumerate(vpc_data['Subnets'], 1):
                subnet_id = subnet['SubnetId']
                subnet_name = get_name_from_tags(subnet.get('Tags', []))
                print(f"\n  {i}. Subnet: {subnet_name} ({subnet_id})")
                print(f"     CIDR Block: {subnet['CidrBlock']}")
                print(f"     Availability Zone: {subnet['AvailabilityZone']} ({subnet.get('AvailabilityZoneId', 'N/A')})")
                print(f"     State: {subnet['State']}")
                print(f"     Available IPs: {subnet.get('AvailableIpAddressCount', 'N/A')}")
                print(f"     Auto-assign Public IP: {'Yes' if subnet.get('MapPublicIpOnLaunch', False) else 'No'}")
                print(f"     Default for AZ: {'Yes' if subnet.get('DefaultForAz', False) else 'No'}")
                
                # Print IPv6 information if available
                ipv6_set = subnet.get('Ipv6CidrBlockAssociationSet', [])
                if ipv6_set:
                    print("     IPv6 CIDR Blocks:")
                    for ipv6_assoc in ipv6_set:
                        print(f"       - {ipv6_assoc.get('Ipv6CidrBlock', 'N/A')} ({ipv6_assoc.get('State', 'N/A')})")
                
                print(f"     Auto-assign IPv6: {'Yes' if subnet.get('AssignIpv6AddressOnCreation', False) else 'No'}")
                
                # Print customer owned IP information if available
                if subnet.get('CustomerOwnedIpv4Pool'):
                    print(f"     Customer Owned IPv4 Pool: {subnet['CustomerOwnedIpv4Pool']}")
                    print(f"     Map Customer Owned IP: {'Yes' if subnet.get('MapCustomerOwnedIpOnLaunch', False) else 'No'}")
                
                if subnet.get('OutpostArn'):
                    print(f"     Outpost ARN: {subnet['OutpostArn']}")
                
                if subnet.get('Tags'):
                    print("     Tags:")
                    for tag in subnet['Tags']:
                        if tag['Key'] != 'Name':  # Skip Name tag as we already displayed it
                            print(f"       - {tag['Key']}: {tag['Value']}")
                
                # Print Network ACL
                nacl_id = subnet.get('NetworkAclId', 'Default')
                nacl_name = "Default"
                for nacl in vpc_data.get('NetworkAcls', []):
                    if nacl.get('NetworkAclId') == nacl_id:
                        nacl_name = get_name_from_tags(nacl.get('Tags', []))
                        break
                if nacl_name != "Unnamed" and nacl_name != "Default":
                    print(f"     Network ACL: {nacl_name} ({nacl_id})")
                else:
                    print(f"     Network ACL: {nacl_id}")
                
                # Print routing information
                route_table_id = subnet['RouteTableId']
                route_table_name = "Unknown"
                if isinstance(subnet['RouteTable'], dict) and 'Tags' in subnet['RouteTable']:
                    route_table_name = get_name_from_tags(subnet['RouteTable']['Tags'])
                    
                if route_table_name != "Unnamed" and route_table_name != "Unknown":
                    print(f"     Route Table: {route_table_name} ({route_table_id})")
                else:
                    print(f"     Route Table: {route_table_id}")
                
                if isinstance(subnet['RouteTable'], dict) and 'Routes' in subnet['RouteTable']:
                    print("     Routes:")
                    for j, route in enumerate(subnet['RouteTable']['Routes'], 1):
                        # Handle both IPv4 and IPv6 destination blocks
                        if 'DestinationCidrBlock' in route:
                            dest = route['DestinationCidrBlock']
                            dest_type = "IPv4"
                        elif 'DestinationIpv6CidrBlock' in route:
                            dest = route['DestinationIpv6CidrBlock']
                            dest_type = "IPv6"
                        else:
                            dest = "Unknown"
                            dest_type = "Unknown"
                        
                        print(f"       {j}. Destination: {dest} ({dest_type})")
                        
                        # Print the target (only one will be non-N/A)
                        target_type = "Unknown"
                        target_value = "Unknown"
                        
                        if 'GatewayId' in route:
                            target_value = route['GatewayId']
                            if target_value.startswith('igw-'):
                                target_type = "Internet Gateway"
                            elif target_value == 'local':
                                target_type = "Local"
                            else:
                                target_type = "Gateway"
                        elif 'NatGatewayId' in route:
                            target_type = "NAT Gateway"
                            target_value = route['NatGatewayId']
                        elif 'InstanceId' in route:
                            target_type = "EC2 Instance"
                            target_value = route['InstanceId']
                        elif 'VpcPeeringConnectionId' in route:
                            target_type = "VPC Peering"
                            target_value = route['VpcPeeringConnectionId']
                        elif 'TransitGatewayId' in route:
                            target_type = "Transit Gateway"
                            target_value = route['TransitGatewayId']
                        elif 'LocalGatewayId' in route:
                            target_type = "Local Gateway"
                            target_value = route['LocalGatewayId']
                        elif 'CarrierGatewayId' in route:
                            target_type = "Carrier Gateway"
                            target_value = route['CarrierGatewayId']
                        elif 'NetworkInterfaceId' in route:
                            target_type = "Network Interface"
                            target_value = route['NetworkInterfaceId']
                        elif 'VpcEndpointId' in route:
                            target_type = "VPC Endpoint"
                            target_value = route['VpcEndpointId']
                        
                        print(f"          Target: {target_value} ({target_type})")
                        
                        if 'State' in route:
                            print(f"          State: {route['State']}")
                        
                        if 'Origin' in route:
                            print(f"          Origin: {route['Origin']}")
                
                # Print instances in the subnet
                instances = subnet.get('Instances', [])
                if instances:
                    print(f"     Instances ({len(instances)}):")
                    for j, instance in enumerate(instances, 1):
                        instance_id = instance['InstanceId']
                        instance_name = get_name_from_tags(instance.get('Tags', []))
                        if instance_name != "Unnamed":
                            print(f"       {j}. {instance_name} ({instance_id})")
                        else:
                            print(f"       {j}. Instance: {instance_id}")
                            
                        print(f"          Type: {instance.get('InstanceType', 'N/A')}")
                        print(f"          Private IP: {instance.get('PrivateIpAddress', 'N/A')}")
                        
                        if instance.get('PublicIpAddress', 'N/A') != 'N/A':
                            print(f"          Public IP: {instance['PublicIpAddress']}")
                        
                        print(f"          State: {instance.get('State', 'N/A')}")
                
                print("")
        else:
            print("  No subnets found for this VPC")
        
        print("="*120)

def main():
    try:
        print("\n" + "="*80)
        print("AWS VPC INFORMATION SCRIPT".center(80))
        print("="*80)
        
        # Get AWS profile and account ID
        session, account_id = get_profile_and_account_info()
        
        print("\nFetching VPC information...")
        vpc_info = get_vpc_information(session)
        
        if not vpc_info:
            print("No VPCs found in this account.")
            sys.exit(0)
            
        print(f"Found {len(vpc_info)} VPCs. Generating report...")
        
        # Generate timestamp for filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create a text file to capture the console output
        text_filename = f"vpc_report_{account_id}_{timestamp}.txt"
        json_filename = f"vpc_information_{account_id}_{timestamp}.json"
        
        # Open the text file for writing
        with open(text_filename, 'w') as text_file:
            # Redirect stdout to the file temporarily
            original_stdout = sys.stdout
            sys.stdout = text_file
            
            # Print VPC information to the file
            print_vpc_info(vpc_info, account_id)
            
            # Restore stdout
            sys.stdout = original_stdout
        
        # Print to console as well
        print_vpc_info(vpc_info, account_id)
        
        # Save to a JSON file
        with open(json_filename, 'w') as f:
            json.dump(vpc_info, f, indent=2, default=str)
            
        print(f"\nDetailed text report saved to: {text_filename}")
        print(f"JSON data saved to: {json_filename}")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\nError: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()