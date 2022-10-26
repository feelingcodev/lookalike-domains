#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

import simplejson
import time
import csv
import sys
import idna
from tn_dnstwist import *

SOLR_ENDPOINT = "http://solr-prod.trustnet.venafi.com:8983/solr/{}/select?q={}&wt=json"
COLLECTION_NAME = "certificates"
current_date = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
BASIC_HEADERS = ['Customer Domain', 'Number of Certs in TN (expired & valid)', 'Still Valid as of {}'.format(time.ctime()), 'Number of certs still rely on SHA1', 'Number of certs still rely on MD5', 'Number of Wildcard certs', 'Number of certs issued by Let\'s Encrypt']
DOMAINS_LIKE_YOURS_HEADERS = ['Customer Domain', 'Domains Alike', 'Number of certs issued to domains alike']

def build_basic_query_list(customer_domain):
    TOTAL_NUM_OF_CERTS= "subjectCN:*.{}%20OR%20subjectAlternativeNameDns:({})%20OR%20subjectAlternativeNameDns:(*.{})".format(customer_domain, customer_domain,customer_domain)
    STILL_VALID_AS_OF_CURRENT_DATE = "{}%20AND%20validityEnd:[{}%20TO%20*]".format(TOTAL_NUM_OF_CERTS, current_date)
    NUM_OF_CERTS_OF_SHA1 = "{}%20AND%20signatureHashAlgorithm:SHA1".format(STILL_VALID_AS_OF_CURRENT_DATE)
    NUM_OF_CERTS_OF_MD5 = "{}%20AND%20signatureHashAlgorithm:MD5".format(STILL_VALID_AS_OF_CURRENT_DATE)
    USE_WILDCARD = "subjectCN:\\*.{}%20OR%20subjectAlternativeNameDns:(\\*.{})%20AND%20validityEnd:[{}%20TO%20*]".format(customer_domain, customer_domain, current_date)
    ISSUED_BY_LETENCRYPT = "{}%20AND%20authorityKeyIdentifierHash:AFA1479A914E33BE6F261C0D4D920013ECC1F805%20AND%20selfSigned:false".format(STILL_VALID_AS_OF_CURRENT_DATE)
    return [TOTAL_NUM_OF_CERTS, STILL_VALID_AS_OF_CURRENT_DATE, NUM_OF_CERTS_OF_SHA1, NUM_OF_CERTS_OF_MD5, USE_WILDCARD, ISSUED_BY_LETENCRYPT]

def get_basic_results_from_solr(customer_domain, query_list):
    results = []
    for index, query in enumerate(query_list):
        print(SOLR_ENDPOINT.format(COLLECTION_NAME,query))
        connection = urllib2.urlopen(SOLR_ENDPOINT.format(COLLECTION_NAME,query))
        response = simplejson.load(connection)
        result = response['response']['numFound']
        results.append(str(result))

    return results

def get_domains_alike(customer_domain):
    _, variants = get_domain_variants(customer_domain, None)
    variant_domains = []
    total_count = 0
    for variant in variants:
        try:
            domain = idna.encode(variant['domain-name'])
            variant_valid_query = "subjectCN:*.{}%20OR%20subjectAlternativeNameDns:({})%20OR%20subjectAlternativeNameDns:(*.{})%20AND%20validityEnd:[{}%20TO%20*]".format(domain, domain, domain, current_date)
            print(SOLR_ENDPOINT.format(COLLECTION_NAME,variant_valid_query))
            connection = urllib2.urlopen(SOLR_ENDPOINT.format(COLLECTION_NAME,variant_valid_query))
            response = simplejson.load(connection)
            result = response['response']['numFound']
            total_count = total_count + result
        except (idna.core.InvalidCodepoint, idna.core.IDNABidiError, idna.core.IDNAError):
            # https://github.com/kjd/idna/issues/25
            print(domain)
        variant_domains.append(domain)
    return [';'.join(variant_domains), total_count]

def operate_on_csv(from_filename, advanced=False):
    if advanced:
        to_filename = from_filename[0: from_filename.find('.')] + '_alike_result.csv'
        with open(from_filename, 'r') as infile, open(to_filename, 'w') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(DOMAINS_LIKE_YOURS_HEADERS)
            reader = csv.reader(infile, delimiter=' ')
            for item in reader:
                if len(item) > 0:
                    customer_domain = idna.encode(item[0].strip())
                    print('\n=========Querying domain: {}'.format(customer_domain))
                    result = get_domains_alike(customer_domain)
                    result.insert(0, customer_domain)
                    writer.writerow(result)
    else:
        to_filename = from_filename[0: from_filename.find('.')] + '_basic_result.csv'
        with open(from_filename, 'r') as infile, open(to_filename, 'w') as outfile:
            writer = csv.writer(outfile)
            writer.writerow(BASIC_HEADERS)
            reader = csv.reader(infile, delimiter=' ')
            for item in reader:
                if len(item) > 0:
                    customer_domain = idna.encode(item[0].strip())
                    print('\n=========Querying domain: {}'.format(customer_domain))
                    query_list = build_basic_query_list(customer_domain)
                    results = get_basic_results_from_solr(customer_domain, query_list)
                    results.insert(0, customer_domain)
                    writer.writerow(results)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        from_filename = sys.argv[1]
        #operate_on_csv(from_filename)
        operate_on_csv(from_filename, True)
    else:
        print("Plz provide a file that contains domains")
