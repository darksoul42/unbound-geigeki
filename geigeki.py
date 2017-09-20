#! /usr/bin/python
# Unbound Attack Interception "Geigeki" module
# 
# Author: Stephane LAPIE <stephane.lapie@asahinet.com>
# Copyright (c) 2017 AsahiNet, Inc.
# All rights reserved.

import socket, errno
import select
import threading
import traceback
import sys
import time
import ipaddress

DEBUG = False
GEIGEKI_HEADER = "ASN-DDoS-geigeki: "

THRESHOLD_TIME = 300
PURGE_DELAY = 60

DOMAIN_ATTACK_THRESHOLD = 20
NORMAL_THRESHOLD = 500
FAIL_THRESHOLD = 450
ANY_THRESHOLD = 10
RRSET_THRESHOLD = 500
CNAME_THRESHOLD = 500

CLIENT_ATTACK_THRESHOLD = 200
DDOS_NORMAL_THRESHOLD = 5
DDOS_FAIL_THRESHOLD = 3
DDOS_ANY_THRESHOLD = 2
DDOS_RRSET_THRESHOLD = 50
DDOS_CNAME_THRESHOLD = 50

# Indices for accessing statistics arrays
QUERY_COUNT_INDEX = 0
FAIL_COUNT_INDEX = 1
ANY_COUNT_INDEX = 2
RRSET_COUNT_INDEX = 3
CNAME_COUNT_INDEX = 4

# Default value for initializing an array, and minimum values for thresholds when decrementing
DEFAULT_MINIMUMS = [ 0, 0, 0, 0, 0 ]

# If a client queries a domain that much, he shall be viewed as attacking
CLIENTDOMAIN_THRESHOLDS = [ NORMAL_THRESHOLD, FAIL_THRESHOLD, ANY_THRESHOLD, RRSET_THRESHOLD, CNAME_THRESHOLD ]
# If a client sends that much queries as a total, he shall be viewed as attacking
CLIENT_THRESHOLDS = [x * DOMAIN_ATTACK_THRESHOLD for x in CLIENTDOMAIN_THRESHOLDS]
# Thresholds for tentatively identifying individuals who might be participating in a DDoS
DDOS_CLIENTDOMAIN_THRESHOLDS = [ DDOS_NORMAL_THRESHOLD, DDOS_FAIL_THRESHOLD, DDOS_ANY_THRESHOLD, DDOS_RRSET_THRESHOLD, DDOS_CNAME_THRESHOLD ]
#DDOS_CLIENT_THRESHOLDS = [x * DOMAIN_ATTACK_THRESHOLD for x in DDOS_CLIENTDOMAIN_THRESHOLDS]
# If a domain receives that much queries as a total, it is being DDoSed
DDOS_DOMAIN_THRESHOLDS = [x * CLIENT_ATTACK_THRESHOLD for x in DDOS_CLIENTDOMAIN_THRESHOLDS]
# If an authority server receives that much queries as a total, it is being DDoSed
#DDOS_AUTHORITATIVE_THRESHOLDS = [x * DOMAIN_ATTACK_THRESHOLD for x in DDOS_DOMAIN_THRESHOLDS]

# Decrement every counter periodically
CLIENTDOMAIN_DECREMENTS = [float(x) * PURGE_DELAY / THRESHOLD_TIME for x in CLIENTDOMAIN_THRESHOLDS]
CLIENT_DECREMENTS = [float(x) * DOMAIN_ATTACK_THRESHOLD for x in CLIENTDOMAIN_DECREMENTS]
DDOS_CLIENTDOMAIN_DECREMENTS = [float(x) * PURGE_DELAY / THRESHOLD_TIME for x in DDOS_CLIENTDOMAIN_THRESHOLDS]
DDOS_DOMAIN_DECREMENTS = [float(x) * PURGE_DELAY / THRESHOLD_TIME for x in DDOS_DOMAIN_THRESHOLDS]
#DDOS_AUTHORITATIVE_DECREMENTS = [float(x) * PURGE_DELAY / THRESHOLD_TIME for x in DDOS_AUTHORITATIVE_THRESHOLDS]

# TODO: Eventually put this in a file of its own
# Basically only put here :
# - Antivirus or security related domains
# - Stuff that don't make "normal" use of DNS servers
# - Also add ASAHI Net related domains
WHITELIST_DOMAINS = set([
                        # Your own domains here (such as domains that might end up in search domains on customer premises)
#                        "my.company.tld", "other.domain.tld",
                        # Known security related services
                        "avts.mcafee.com.", "avqs.mcafee.com.", "geoipd.global.sonicwall.com.", "trendmicro.com.", "sbl.spamhaus.org.", "bl.spamcop.net.", "zen.spamhaus.org.",
                        ])
WHITELIST_MULTIPLIER = 100
WHITELIST_CLIENTDOMAIN_THRESHOLDS = [x * WHITELIST_MULTIPLIER for x in CLIENTDOMAIN_THRESHOLDS]
WHITELIST_DDOS_CLIENTDOMAIN_THRESHOLDS = [x * WHITELIST_MULTIPLIER for x in DDOS_CLIENTDOMAIN_THRESHOLDS]
WHITELIST_DDOS_DOMAIN_THRESHOLDS = [x * WHITELIST_MULTIPLIER for x in DDOS_DOMAIN_THRESHOLDS]
WHITELIST_CLIENTDOMAIN_DECREMENTS = [x * WHITELIST_MULTIPLIER for x in CLIENTDOMAIN_DECREMENTS]
WHITELIST_DDOS_DOMAIN_DECREMENTS = [x * WHITELIST_MULTIPLIER for x in DDOS_DOMAIN_DECREMENTS]

# If RRSET count is at least above QUERY_COUNT * MEANING_THRESHOLD, then it has some meaningful use
# [ 5000, 0, 0, 1500 ] -> 5000 * 0.01 -> 1500 > 50 -> meaningful
RELATIVE_MEANING_THRESHOLD = 0.001
ABSOLUTE_MEANING_THRESHOLD = 2
# Increment threshold AFTER calculating decrements to ensure meaning measure remains, without affecting decrements
CLIENTDOMAIN_THRESHOLDS[RRSET_COUNT_INDEX] *= 10
DDOS_CLIENTDOMAIN_THRESHOLDS[RRSET_COUNT_INDEX] *= 10

# Ensure one unit of meaning for a given domain is conserved as long as possible
DOMAIN_MINIMUMS = [ 0, 0, 0, ABSOLUTE_MEANING_THRESHOLD - 1, 0 ]

# If a domain has been the target of a rejection decision more than this number of times, block it
# This is to avoid registering the whole world in the whitelist
DOMAIN_BURST_THRESHOLD = 150
DOMAIN_BURST_DECREMENT = float(DOMAIN_BURST_THRESHOLD) * PURGE_DELAY / THRESHOLD_TIME
DOMAIN_BURST_MINIMUM = 0

# TODO: Eventually put this in a file of its own
# Register here IPv6 prefixes which you own, and what prefix length you give to your users
# This is especially intended for cases where networks larger than /64 are given out
IPV6_PREFIXES_MAP = dict([
#                            ("<IPV6_ADDRESS_SPACE>", 64),
                         ])
# Convert the contents of the map in actuall IPv6Network objects
IPV6_PREFIXES_MAP = { ipaddress.ip_network(key.decode("utf-8")): value for (key, value) in IPV6_PREFIXES_MAP.iteritems() }
IPV6_DEFAULT_PREFIXLEN = 64

def canonicalize_ipv6_client(client):
    client_addr = ipaddress.ip_address(client.decode("utf-8"))
    for network, usermask in IPV6_PREFIXES_MAP.iteritems():
        if client_addr in network:
            client_user_network = ipaddress.ip_network((client_addr, usermask), False)
            return str(client_user_network)
    client_user_network = ipaddress.ip_network((client_addr, IPV6_DEFAULT_PREFIXLEN), False)
    return str(client_user_network)

def decrement_elem(elem, threshold, decrement, minimum, purge=0):
        if elem > threshold:
                return threshold
        if purge > 0:
                return 0
        if elem < decrement:
                if elem >= (minimum + 1):
                        elem = minimum
                else:
                        elem = 0
        else:
                elem -= decrement
        return elem

def get_counter(dictionary, key):
        return dictionary.get(key, list(DEFAULT_MINIMUMS))

def increment_counter(dictionary, key, index, count):
        data = get_counter(dictionary, key)
        data[index] += count
        if key not in dictionary:
                dictionary[key] = data
        return data

def decrement_counter(dictionary, get_values, purge):
        purge = []
        for key, data in dictionary.iteritems():
                (thresholds, decrements, minimums) = get_values(key)
                data = [decrement_elem(elem, threshold, decrement, minimum, purge) for elem, threshold, decrement, minimum in zip(data, thresholds, decrements, minimums)]
                if all(x == 0 for x in data): # Ready for deletion
                        purge.append(key)
                else:
                        dictionary[key] = data
        for x in purge:
                del dictionary[x]


def check_thresholds_on_data(data, thresholds):
        return any(elem >= threshold for elem, threshold in zip(data, thresholds))

# This function serves to calculate the meaning coefficient for this data array.
# Returns: a boolean, which indicates whether the data array was meaningful enough
# 
# Quirks :
# - Consider data meaningful if we don't have enough queries
# - After that, consider data meaningless if we have ZERO records at all
def is_data_meaningful(data, decrements, rel_threshold, abs_threshold, ignore_negligible=False):
        if ignore_negligible and (data[QUERY_COUNT_INDEX] < decrements[QUERY_COUNT_INDEX]):
                return True
        if data[RRSET_COUNT_INDEX] == 0:
                return False
#        log_info(GEIGEKI_HEADER + "LOOKUP data meaning check: %s / %s (%s) > %s ?" % (data[RRSET_COUNT_INDEX],  data[QUERY_COUNT_INDEX], (float(data[RRSET_COUNT_INDEX]) / data[QUERY_COUNT_INDEX]), threshold))
        return ((float(data[RRSET_COUNT_INDEX]) / data[QUERY_COUNT_INDEX]) > rel_threshold) or (data[RRSET_COUNT_INDEX] > abs_threshold)

class GeigekiDictionary(object):
        def __init__(self, ignore_aaaa=False):
                self._lock = threading.Lock()
                self._created = int(time.time())
                self._aaaa_ignore = ignore_aaaa
                # Dictionaries
                self._client_dict = {}
                self._domain_dict = {}
                self._clientdomain_dict = {}
                self._domain_burst_dict = {}

        def set_ignore_aaaa_records(self, ignore_aaaa=True):
                self._aaaa_ignore = ignore_aaaa

        def get_counters(self, client, domain):
                clientdomain = "%s/%s" % (client, domain)
                with self._lock:
                        counters = [get_counter(d, k) for d, k in zip([self._client_dict, self._domain_dict, self._clientdomain_dict], [client, domain, clientdomain])]
                return counters

        def increment_counters(self, client, domain, index, count=1):
                clientdomain = "%s/%s" % (client, domain)
                with self._lock:
                        counters = [increment_counter(d, k, index, count) for d, k in zip([self._client_dict, self._domain_dict, self._clientdomain_dict], [client, domain, clientdomain])]
                return counters

        def decrement_counters(self, purge):
                with self._lock:
                        decrement_counter(self._client_dict, (lambda key: (CLIENT_THRESHOLDS, CLIENT_DECREMENTS, DEFAULT_MINIMUMS)), purge)
                        decrement_counter(self._domain_dict, (lambda key: (WHITELIST_DDOS_DOMAIN_THRESHOLDS, WHITELIST_DDOS_DOMAIN_DECREMENTS, DOMAIN_MINIMUMS) if key in WHITELIST_DOMAINS else (DDOS_DOMAIN_THRESHOLDS, DDOS_DOMAIN_DECREMENTS, DOMAIN_MINIMUMS)), purge)
                        decrement_counter(self._clientdomain_dict, (lambda key: (WHITELIST_CLIENTDOMAIN_THRESHOLDS, WHITELIST_CLIENTDOMAIN_DECREMENTS, WHITELIST_DDOS_CLIENTDOMAIN_THRESHOLDS) if key.split("/")[1] in WHITELIST_DOMAINS else (CLIENTDOMAIN_THRESHOLDS, CLIENTDOMAIN_DECREMENTS, DDOS_CLIENTDOMAIN_THRESHOLDS)), purge)
                        decrement_counter(self._domain_burst_dict, (lambda key: ([ DOMAIN_BURST_THRESHOLD ], [ DOMAIN_BURST_DECREMENT ], [ DOMAIN_BURST_MINIMUM ])), purge)

        def reinitialize_or_purge(self):
                now = int(time.time())
                if now > (self._created + THRESHOLD_TIME):
                        self._created = now
                        verbose(VERB_ALGO, GEIGEKI_HEADER + "REINIT: Executing total reinitialization of dictionaries")
                        self.decrement_counters(purge=1)
                elif now > (self._created + PURGE_DELAY):
                        self._created = now
                        verbose(VERB_ALGO, GEIGEKI_HEADER + "PURGE: Executing decrement of dictionaries")
                        self.decrement_counters(purge=0)

        def lookup(self, client, domain, qtype, authoritatives):
                # Check if we need to purge or reinitialize
                self.reinitialize_or_purge()

                # Ignore AAAA queries lookups (for increments) if we are using a AAAA filter, they would just mess up numbers
                if self._aaaa_ignore and qtype == "AAAA":
                        # Just get latest data arrays from dictionaries
                        (client_data, domain_data, clientdomain_data) = self.get_counters(client, domain)
                else:
                        # Update dictionaries, and get the latest data arrays
                        (client_data, domain_data, clientdomain_data) = self.increment_counters(client, domain, QUERY_COUNT_INDEX)

                # Tune thresholds for whitelist
                clientdomain_thresholds = CLIENTDOMAIN_THRESHOLDS
                ddos_domain_thresholds = DDOS_DOMAIN_THRESHOLDS
                ddos_clientdomain_thresholds = DDOS_CLIENTDOMAIN_THRESHOLDS
                if domain in WHITELIST_DOMAINS or qtype == "PTR":
                        clientdomain_thresholds = WHITELIST_CLIENTDOMAIN_THRESHOLDS
                        ddos_domain_thresholds = WHITELIST_DDOS_DOMAIN_THRESHOLDS
                        ddos_clientdomain_thresholds = WHITELIST_DDOS_CLIENTDOMAIN_THRESHOLDS

                # Check thresholds
                ####
                # 1. Is client's queries to the given domain breaching attack thresholds?
                domain_single_attack = check_thresholds_on_data(clientdomain_data, clientdomain_thresholds)

                # 1.1 Is client making queries to the given domain actually replying meaningful information?
                if (domain_single_attack):
                        domain_single_attack = not is_data_meaningful(clientdomain_data, CLIENTDOMAIN_DECREMENTS, RELATIVE_MEANING_THRESHOLD, ABSOLUTE_MEANING_THRESHOLD)

                ####
                # 2. Is client's total number of queries breaching attack thresholds?
                single_attack = check_thresholds_on_data(client_data, CLIENT_THRESHOLDS)

                # 2.1 Is client making, as a whole, queries actually replying meaningful information?
                if (single_attack):
                        single_attack = not is_data_meaningful(client_data, CLIENT_DECREMENTS, RELATIVE_MEANING_THRESHOLD, ABSOLUTE_MEANING_THRESHOLD)

                ####
                # 3. Is domain itself experiencing queries beyond DDos thresholds?
                domain_under_ddos = check_thresholds_on_data(domain_data, ddos_domain_thresholds)

                # 3.1 Is domain actually replying meaningful information? (Reconsider only if the domain's RRSET count and CNAME counts are below threshold)
                if (domain_under_ddos and (domain_data[RRSET_COUNT_INDEX] < ddos_domain_thresholds[RRSET_COUNT_INDEX]) and (domain_data[CNAME_COUNT_INDEX] < ddos_domain_thresholds[CNAME_COUNT_INDEX]) ):
                        domain_under_ddos = not is_data_meaningful(domain_data, DDOS_DOMAIN_DECREMENTS, RELATIVE_MEANING_THRESHOLD, ABSOLUTE_MEANING_THRESHOLD, ignore_negligible=True)

                ####
                # 4. Is client taking part in the DDoS on the given domain?
                member_of_ddos = check_thresholds_on_data(clientdomain_data, ddos_clientdomain_thresholds)

                # 4.2 Is client actually getting meaningful information from domain? (Reconsider only if the domain's RRSET and CNAME counts are below threshold)
                if (member_of_ddos and (domain_data[RRSET_COUNT_INDEX] < ddos_domain_thresholds[RRSET_COUNT_INDEX]) and (domain_data[CNAME_COUNT_INDEX] < ddos_domain_thresholds[CNAME_COUNT_INDEX]) ):
                        member_of_ddos = not is_data_meaningful(clientdomain_data, DDOS_CLIENTDOMAIN_DECREMENTS, RELATIVE_MEANING_THRESHOLD, ABSOLUTE_MEANING_THRESHOLD)

                allow_result = True

                # This client is just plain hammering our DNS server: if he sends that much, he HAS to be stopped, PERIOD.
                if single_attack:
                        verbose(VERB_ALGO, GEIGEKI_HEADER + "LOOKUP result: client '%s' hammering our server" % client)
                        allow_result = False

                # This client is just plain hammering this domain
                if domain_single_attack:
                        verbose(VERB_ALGO, GEIGEKI_HEADER + "LOOKUP result: client '%s' hammering domain '%s'" % (client, domain))
                        allow_result = False

                # The core check for simple water torture attacks on a single domain
                if domain_under_ddos and member_of_ddos:
                        verbose(VERB_ALGO, GEIGEKI_HEADER + "LOOKUP result: client '%s' was a participant in DDoS on domain '%s'" % (client, domain))
                        allow_result = False

                if (allow_result == False and any([data[QUERY_COUNT_INDEX] > 0 and data[QUERY_COUNT_INDEX] % 25 == 0  for data in (client_data, domain_data, clientdomain_data)])) or (allow_result == True and any([data[QUERY_COUNT_INDEX] > 0 and data[QUERY_COUNT_INDEX] % 100 == 0 for data in (client_data, domain_data, clientdomain_data)])):
                        log_info(GEIGEKI_HEADER + "LOOKUP stats on domain %s by %s (domain): client(%s / %s) domain(%s / %s) clientdomain(%s / %s / %s)" % (domain, client, client_data, CLIENT_THRESHOLDS, domain_data, ddos_domain_thresholds, clientdomain_data, clientdomain_thresholds, ddos_clientdomain_thresholds))
                        log_info(GEIGEKI_HEADER + "LOOKUP result on domain %s by %s: single_attack_on_domain_by_client=%s single_attack_by_client=%s is_domain_ddosed=%s is_client_member_of_ddos=%s" % (domain, client, domain_single_attack, single_attack, domain_under_ddos, member_of_ddos))


                # Last ditch attempt to avoid classifying a query as an attack.
                #
                # This does not apply to "single_attack", since this buffer rejections for a given domain,
                # and "single_attack" will just block a client hammering our server with cache-misses.
                #
                # Buffer the "rejection" results, and only act upon it once the burst threshold has been broken, to allow for leeway.
                # This logic is based on statistics taken from the logs :
                # Actually harmful attacks *WILL* breach three figures within five minutes,
                # anything else can be ignored safely.
                if not allow_result and not single_attack:
                        # Update the counter safely
                        with self._lock:
                                domain_burst = self._domain_burst_dict.get(domain, [ DOMAIN_BURST_MINIMUM ])
                                domain_burst[0] += 1
                                self._domain_burst_dict[domain] = domain_burst

                        if domain_burst[0] < DOMAIN_BURST_THRESHOLD:
                                # Log the first time a rejection decision was made, and every 25 times while under the threshold
                                if (domain_burst[0] == 1) or (domain_burst[0] % 25 == 0):
                                        log_info(GEIGEKI_HEADER + "LOOKUP result on domain %s by ALL: burst(%s / %s)" % (domain, domain_burst[0], DOMAIN_BURST_THRESHOLD))
                                return True

                return allow_result

        def count_fail_query(self, client, domain):
                # Check if we need to purge or reinitialize
                self.reinitialize_or_purge()

                # Update dictionaries
                self.increment_counters(client, domain, FAIL_COUNT_INDEX)
                return True

        def count_any_query(self, client, domain):
                # Check if we need to purge or reinitialize
                self.reinitialize_or_purge()

                # Update dictionaries
                self.increment_counters(client, domain, ANY_COUNT_INDEX)
                return True

        def count_query_size(self, client, domain, rrset):
                # Check if we need to purge or reinitialize
                self.reinitialize_or_purge()

                # Update dictionaries
                self.increment_counters(client, domain, RRSET_COUNT_INDEX, count=rrset)
                return True

        def count_cnames_replies(self, client, domain, cnames):
                # Check if we need to purge or reinitialize
                self.reinitialize_or_purge()

                # Update dictionaries
                self.increment_counters(client, domain, CNAME_COUNT_INDEX, count=cnames)
                return True

def init(id, cfg):
        global mod_env
        log_info(GEIGEKI_HEADER + "init called, module id is %d, port: %d, script: '%s'" % (id, cfg.port, cfg.python_script))
        aaaa_filter_check_result = None
        try:
                aaaa_filter_check_result = (cfg.aaaa_filter > 0)
        except AttributeError, err:
                pass
        log_info(GEIGEKI_HEADER + "Presence of AAAA filter patch : %s" % aaaa_filter_check_result)
        if aaaa_filter_check_result:
                verbose(VERB_ALGO, GEIGEKI_HEADER + "Will ignore lookups on AAAA records, since for most we will return empty records")

        log_info(GEIGEKI_HEADER + "Standard thresholds :")
        log_info(GEIGEKI_HEADER + "- CLIENTDOMAIN_THRESHOLDS : %s" % (CLIENTDOMAIN_THRESHOLDS))
        log_info(GEIGEKI_HEADER + "- CLIENT_THRESHOLDS : %s" % (CLIENT_THRESHOLDS))
        log_info(GEIGEKI_HEADER + "- DDOS_CLIENTDOMAIN_THRESHOLDS : %s" % (DDOS_CLIENTDOMAIN_THRESHOLDS))
        log_info(GEIGEKI_HEADER + "- DDOS_DOMAIN_THRESHOLDS : %s" % (DDOS_DOMAIN_THRESHOLDS))
        log_info(GEIGEKI_HEADER + "Standard decrements :")
        log_info(GEIGEKI_HEADER + "- CLIENTDOMAIN_DECREMENTS : %s" % (CLIENTDOMAIN_DECREMENTS))
        log_info(GEIGEKI_HEADER + "- CLIENT_DECREMENTS : %s" % (CLIENT_DECREMENTS))
        log_info(GEIGEKI_HEADER + "- DDOS_CLIENTDOMAIN_DECREMENTS : %s" % (DDOS_CLIENTDOMAIN_DECREMENTS))
        log_info(GEIGEKI_HEADER + "- DDOS_DOMAIN_DECREMENTS : %s" % (DDOS_DOMAIN_DECREMENTS))
        log_info(GEIGEKI_HEADER + "Whitelisted domains : %s" % len(WHITELIST_DOMAINS))
        log_info(GEIGEKI_HEADER + "Whitelist thresholds :")
        log_info(GEIGEKI_HEADER + "- WHITELIST_CLIENTDOMAIN_THRESHOLDS : %s" % (WHITELIST_CLIENTDOMAIN_THRESHOLDS))
        log_info(GEIGEKI_HEADER + "- WHITELIST_DDOS_CLIENTDOMAIN_THRESHOLDS : %s" % (WHITELIST_DDOS_CLIENTDOMAIN_THRESHOLDS))
        log_info(GEIGEKI_HEADER + "- WHITELIST_DDOS_DOMAIN_THRESHOLDS : %s" % (WHITELIST_DDOS_DOMAIN_THRESHOLDS))
        log_info(GEIGEKI_HEADER + "Whitelist decrements :")
        log_info(GEIGEKI_HEADER + "- WHITELIST_CLIENTDOMAIN_DECREMENTS : %s" % (WHITELIST_CLIENTDOMAIN_DECREMENTS))
        log_info(GEIGEKI_HEADER + "- WHITELIST_DDOS_DOMAIN_DECREMENTS : %s" % (WHITELIST_DDOS_DOMAIN_DECREMENTS))
        log_info(GEIGEKI_HEADER + "Rejection holding threshold/decrement :")
        log_info(GEIGEKI_HEADER + "- DOMAIN_BURST_THRESHOLD : %s" % DOMAIN_BURST_THRESHOLD)
        log_info(GEIGEKI_HEADER + "- DOMAIN_BURST_DECREMENT : %s" % DOMAIN_BURST_DECREMENT)

        mod_env = []
#        mod_env.append(ThreadSafeSocketPool(cfg.num_threads))
        mod_env.append(None) # This would be where we'd put the communication interface
        mod_env.append(GeigekiDictionary(ignore_aaaa=aaaa_filter_check_result))
        return True

def deinit(id):
        global mod_env
        log_info(GEIGEKI_HEADER + "deinit called, module id is %d" % id)
#        if mod_env[0] is not None:
#                verbose(VERB_ALGO, GEIGEKI_HEADER + "closing sockets")
#                mod_env[0].close_sockets()
        return True

def inform_super(id, qstate, superqstate, qdata):
        return True

def allow_query(qinfo, delegation, delegation_name, client):
        global mod_env
        query_components = qinfo.qname_str.rstrip(".").split(".")
        if len(query_components) == 1 and '?' in query_components[-1]: # Non-printable characters in TLD (up to com or jp or net). Block.
                verbose(VERB_ALGO, GEIGEKI_HEADER + "invalid characters in query '%s/%s/%s' (%s), rejecting" % (qinfo.qname_str, qinfo.qtype_str, qinfo.qclass_str, delegation_name))
                return False
        if len(query_components) > 1 and any(['?' in x for x in [ query_components[-1], query_components[-2] ]]): # Non-printable characters in domain/TLD (up to domain.com or co.jp). Block.
                verbose(VERB_ALGO, GEIGEKI_HEADER + "invalid characters in query '%s/%s/%s' (%s), rejecting" % (qinfo.qname_str, qinfo.qtype_str, qinfo.qclass_str, delegation_name))
                return False
        if (client is None): # Don't impede requests launched by Unbound itself
                verbose(VERB_ALGO, GEIGEKI_HEADER + "'%s/%s/%s' is not a client originated request, allowing" % (qinfo.qname_str, qinfo.qtype_str, qinfo.qclass_str))
                return True

        verbose(VERB_ALGO, GEIGEKI_HEADER + "client '%s' requested '%s/%s/%s' (%s)" % (client, qinfo.qname_str, qinfo.qtype_str, qinfo.qclass_str, delegation_name))
        if (delegation is None or delegation.dname_str == "."): # No data in cache for this delegation. Let through.
                verbose(VERB_ALGO, GEIGEKI_HEADER + "no delegation found for '%s/%s/%s', allowing" % (qinfo.qname_str, qinfo.qtype_str, qinfo.qclass_str))
                return True
        if (len(delegation.dname_str.rstrip(".").split(".")) <= 1): # Query that will go up to a TLD. Let through.
                verbose(VERB_ALGO, GEIGEKI_HEADER + "would go up to a TLD (%s) for '%s/%s/%s', allowing" % (delegation.dname_str, qinfo.qname_str, qinfo.qtype_str, qinfo.qclass_str))
                return True

        usable_server_names = []
        usable_servers = []
        if (delegation.nslist is not None):
                tmp = delegation.nslist
                while (tmp is not None):
                        usable_server_names.append(tmp.dname_str)
                        tmp = tmp.next
        if (delegation.usable_list is not None):
                tmp = delegation.usable_list
                while (tmp is not None):
                        usable_servers.append(tmp.addr)
                        tmp = tmp.next_usable

        # Use addresses in priority if we have them
        if len(usable_servers) == 0: # Maybe we got non resolvable authoritative NSes. Can be part of a DDoS countermeasure, whatever, throw it in to keep track of who is hammering a domain.
            usable_servers = usable_server_names

        if qinfo.qtype_str == "ANY": # ANY queries increment a counter of their own.
                mod_env[1].count_any_query(client, delegation_name)

        result = None
        try:
                result = mod_env[1].lookup(client, delegation_name, qinfo.qtype_str, usable_servers)
        except Exception, err:
                verbose(VERB_ALGO, GEIGEKI_HEADER + traceback.format_exc())
        return result

def operate(id, event, qstate, qdata):
        global mod_env
        policy_result = True
        client = None
        if (qstate.mesh_info.reply_list is not None):
            client = qstate.mesh_info.reply_list.query_reply.addr
            # If client came via IPv6, we will reduce his address to a prefix
            if qstate.mesh_info.reply_list.query_reply.family == "ip6":
                client = canonicalize_ipv6_client(client)

        delegation = find_delegation(qstate, qstate.qinfo.qname, len(qstate.qinfo.qname))
        delegation_name = "<NONE>"
        if (delegation is not None):
                delegation_name = delegation.dname_str.lower()

        if (event == MODULE_EVENT_NEW) or (event == MODULE_EVENT_PASS):
                policy_result = allow_query(qstate.qinfo, delegation, delegation_name, client)

                if (delegation is not None):
                        verb = "allowed"
                        if policy_result is None:
                                verb = "ignored"
                                policy_result = True
                        if not policy_result:
                                verb = "rejected"
                        if DEBUG:
                                verb += " (DEBUG)"
                        log_info(GEIGEKI_HEADER + "%s %s %s (%s) %s %s" % (verb, client, qstate.qinfo.qname_str, delegation_name, qstate.qinfo.qtype_str, qstate.qinfo.qclass_str))
                if DEBUG: # If we are in debug mode, don't block, but log as if it was going to be blocked
                        policy_result = True
                if (policy_result): # Pass query to next module
                        qstate.ext_state[id] = MODULE_WAIT_MODULE
                else:
                        qstate.ext_state[id] = MODULE_ERROR
                return True

        if (event == MODULE_EVENT_MODDONE) or (event == MODULE_EVENT_NOREPLY) or (event == MODULE_EVENT_REPLY):
                if (client is not None and delegation is not None and qstate.return_msg is not None):
                        rep = qstate.return_msg.rep
                        return_rcode = rep.flags & 0xf
                        # Log NXDOMAINs and SERVFAILs
                        if return_rcode == RCODE_SERVFAIL or return_rcode == RCODE_NXDOMAIN:
                                log_info(GEIGEKI_HEADER + "allowed query from %s failed (code: %s) %s (%s) %s %s" % (client, return_rcode, qstate.qinfo.qname_str, delegation_name, qstate.qinfo.qtype_str, qstate.qinfo.qclass_str))
                                mod_env[1].count_fail_query(client, delegation_name)
                        # Log number of RRsets in return message for successes and non-empty answers
                        if return_rcode == RCODE_NOERROR and rep.rrset_count == 0:
                                verbose(VERB_ALGO, GEIGEKI_HEADER + "Processing empty query return as if it had one RRSET")
                                mod_env[1].count_query_size(client, delegation_name, 1)
                        if return_rcode == RCODE_NOERROR and rep.rrset_count > 0:
                                cname_count = sum([int(rep.rrsets[i].rk.type_str == "CNAME") for i in range(0, rep.rrset_count)])
                                mod_env[1].count_cnames_replies(client, delegation_name, int(cname_count))
                                count = rep.an_numrrsets - cname_count
                                verbose(VERB_ALGO, GEIGEKI_HEADER + "Processing query return, containing %s answer RRSETs (%s meaningful)" % (rep.an_numrrsets, count))
                                mod_env[1].count_query_size(client, delegation_name, int(count))

                qstate.ext_state[id] = MODULE_FINISHED
                return True

        log_err(GEIGEKI_HEADER + "pythonmod: BAD event")
        qstate.ext_state[id] = MODULE_ERROR
        return True
