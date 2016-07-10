#!/usr/bin/python
import re
import os
import boto3
import urllib
from pybloom import BloomFilter

class FeedURL(object):
    def __init__(self):
        self.feeds = self.get_feeds()

    def get_feeds(self):
        feeds = [
            { 'feed' : 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt' , 'name' : 'emerging-Block-IPs.txt'},
            { 'feed' : 'http://rules.emergingthreats.net/blockrules/compromised-ips.txt' , 'name' : 'compromised-ips.txt'},
            { 'feed' : 'http://www.binarydefense.com/banlist.txt' , 'name' : 'binarydefense-banlist.txt'},
            { 'feed' : 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist' , 'name' : 'zeus-tracker.txt'},
            { 'feed' : 'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist', 'name' : 'palevo-tracker.txt'},
            { 'feed' : 'http://malc0de.com/bl/IP_Blacklist.txt', 'name' : 'Malc0de-blacklist.txt' }
        ]
        return feeds

class Feed(object):
    def __init__(self):
        self.feeds = FeedURL().get_feeds()

    def is_ip(self, ip):
        list = []
        pat = re.compile("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}")
        test = pat.match(ip)
        if test:
            list.append(ip)
        else:
            pass
        return list

    def download_file(self, feed, name):
        feedfile = urllib.URLopener()
        feedfile.retrieve(feed, name)

    def fetch_feeds(self):
        for feed in self.feeds:
            self.download_file(feed['feed'], feed['name'])

    def tokenize_feeds(self, feed_file):
        content = None
        with open(feed_file) as f:
            content = f.readlines()
        return content

    def parse_feeds(self):
        blocklist = []
        for feed in self.feeds:
            feed_blocklist = [{ 'name' : feed['name'], 'ips' : []}]
            content = self.tokenize_feeds(feed['name'])
            for line in content:
                if self.is_ip(line):
                    feed_blocklist[0]['ips'].append(line.rstrip())
            blocklist.append(feed_blocklist)
        return blocklist

class DataStore(object):
    def __init__(self):
        self.blacklist = Feed().parse_feeds()
        self.bloom = BloomFilter(capacity=6000, error_rate=0.001)
        self.generate_bloom()

    def generate_bloom(self):
        for blacklist in self.blacklist[0]:
            for ip in blacklist['ips']:
                self.bloom.add(ip)

    def is_threat(self, ip):
        search = ip in self.bloom
        return search


### This class currently isn't very useful due to a limitation in AWS VPC Network ACLs
### Maximum of 20 rules per acl
class SecurityGroups(object):
    def __init__(self):
        self.client = boto3.client('ec2')
        self.regions = self.get_all()
        self.vpcs = self.vpcs_by_region()

    def get_all(self):
        availRegions = []
        regions = self.client.describe_regions()
        for region in regions['Regions']:
            availRegions.append(region['RegionName'])
        return availRegions

    def get_vpc(self, client):
        response = client.describe_vpcs()
        return response

    def vpcs_by_region(self):
        vpcs = []
        for region in self.regions:
            client = boto3.client('ec2', region)
            region_vpcs = self.get_vpc(client)
            vpcs.append(
                {'region': region, 'networks' : region_vpcs}
            )
        return vpcs

    def __vpc_resource(self, region, vpc_id):
        ec2 = boto3.resource('ec2', region)
        vpc = ec2.Vpc(vpc_id)
        return vpc

    def __create_acl(self, vpc_resource, vpc_id):
        network_acl = vpc_resource.create_network_acl()
        return network_acl

    def __set_tags(self, region, network_acl):
        client = boto3.client('ec2', region)
        client.create_tags(
            Resources=[network_acl.id],
            Tags=[
                {
                    'Key': 'ThreatResponse',
                    'Value': 'ThreatFeeds'
                },
            ])

    def __to_cidr(self, ip_block):
        if '/' in ip_block:
            return ip_block
        else:
            return ipblock + "/32"

    def __create_rule(self, network_acl, ip_block, rule_number):
        response = network_acl.create_entry(
            RuleNumber=rule_number,
            Protocol='-1',
            RuleAction='deny',
            Egress=True,
            CidrBlock=self.__to_cidr(ip_block),
            IcmpTypeCode={
                'Type': -1,
                'Code': -1
            },
            PortRange={
                'From': 0,
                'To': 65535
            }
        )
        return response

    def __egress_rule(self, network_acl, ip_block='0.0.0.0/0', rule_number):
        response = network_acl.create_entry(
            RuleNumber=rule_number,
            Protocol='-1',
            RuleAction='allow',
            Egress=True,
            CidrBlock=self.__to_cidr(ip_block),
            IcmpTypeCode={
                'Type': -1,
                'Code': -1
            },
            PortRange={
                'From': 0,
                'To': 65535
            }
        )
        return response

    def all_blacklist_to_rules(self, vpc_id, region):
        vpc = self.__vpc_resource(region, vpc_id)
        rules = Feed().parse_feeds()
        rule_number = 1
        for rule in rules[0]:
            for ip in rule['ips']:
                try:
                    self.__create_rule(acl, ip, rule_number)
                    rule_number = rule_number + 1
                except:
                    pass


if __name__=='__main__':
    blocklist = Feed().parse_feeds()
    datastorage = DataStore()
    datastorage.generate_bloom()
    #print '222.174.5.0/24' in datastorage.bloom
    #print Feed().is_ip('4.2.2.2')
    print SecurityGroups().all_blacklist_to_rules('vpc-2e8cf74a', 'us-west-2')
