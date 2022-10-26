#!/usr/bin/env python

try:
    import urllib.request as urllib2
except ImportError:
    import urllib2

from urlparse import urlparse

import simplejson
import time
import csv
import sys

SOLR_ENDPOINT = "http://solr-prod.trustnet.venafi.com:8983/solr/{}/select?q={}&wt=json"
COLLECTION_NAME = "certificates"
current_date = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
HEADERS = ['Total Recorded Number of Certs in TN', 'Still Valid as of {}'.format(time.ctime()), 'Number of valid SHA1 certs ', 'Number of valid MD5 certs ', 'Number of valid wildcard certs', 'Number of valid certs issued by Let\'s Encrypt', 'Number of valid Let\'s Encrypt certs issued for domains alike', 'Number of valid certs issued for domains alike']

def build_query_list(retail_domain):
    TOTAL_NUM_OF_CERTS= "subjectCN:*.{}%20OR%20subjectAlternativeNameDns:({})%20OR%20subjectAlternativeNameDns:(*.{})".format(retail_domain, retail_domain,retail_domain)
    STILL_VALID_AS_OF_CURRENT_DATE = "{}%20AND%20validityEnd:[{}%20TO%20*]".format(TOTAL_NUM_OF_CERTS, current_date)
    NUM_OF_CERTS_OF_SHA1 = "{}%20AND%20signatureHashAlgorithm:SHA1".format(STILL_VALID_AS_OF_CURRENT_DATE)
    NUM_OF_CERTS_OF_MD5 = "{}%20AND%20signatureHashAlgorithm:MD5".format(STILL_VALID_AS_OF_CURRENT_DATE)
    USE_WILDCARD = "subjectCN:\\*.{}%20OR%20subjectAlternativeNameDns:(\\*.{})%20AND%20validityEnd:[{}%20TO%20*]".format(retail_domain, retail_domain, current_date)
    ISSUED_BY_LETENCRYPT = "{}%20AND%20authorityKeyIdentifierHash:AFA1479A914E33BE6F261C0D4D920013ECC1F805%20AND%20selfSigned:false".format(STILL_VALID_AS_OF_CURRENT_DATE)
    TOTAL_NUM_OF_LE_CERTS_FOR_DOMAINS_ALIKE = "subjectCN:/(www.)?[0-9a-z][0-9a-z]*{}/%20AND%20authorityKeyIdentifierHash:AFA1479A914E33BE6F261C0D4D920013ECC1F805%20AND%20selfSigned:false".format(retail_domain)
    TOTAL_NUM_OF_CERTS_FOR_DOMAINS_ALIKE = "subjectCN:/(www.)?[0-9a-z][0-9a-z]*{}*/".format(retail_domain)

    return [TOTAL_NUM_OF_CERTS, STILL_VALID_AS_OF_CURRENT_DATE, NUM_OF_CERTS_OF_SHA1, NUM_OF_CERTS_OF_MD5, USE_WILDCARD, ISSUED_BY_LETENCRYPT, TOTAL_NUM_OF_LE_CERTS_FOR_DOMAINS_ALIKE, TOTAL_NUM_OF_CERTS_FOR_DOMAINS_ALIKE]

def get_results_from_solr(retail_domain, query_list):
    results = []
    for index, query in enumerate(query_list):
        print(SOLR_ENDPOINT.format(COLLECTION_NAME,query))
        connection = urllib2.urlopen(SOLR_ENDPOINT.format(COLLECTION_NAME,query))
        response = simplejson.load(connection)
        result = response['response']['numFound']
        if result > 0 and index == len(query_list) - 1:
            docs = response['response']['docs']
            cnlist = []
            for item in docs:
                print(item['subjectCN'][0])
                cnlist.append(item['subjectCN'][0])
                try:
                    print(item['subjectAlternativeNameDns'])
                    cnlist.extend(item['subjectAlternativeNameDns'])
                except KeyError as e:
                    pass
            result = str(result) + ':' + ','.join(cnlist)
        results.append(str(result))
    return results

def get_domain(url):
    parsed = urlparse(url)
    domain = parsed.hostname.replace("www.","")
    return domain

def operate_on_csv(from_filename, to_filename):
    with open(from_filename, 'r') as infile, open(to_filename, 'w') as outfile:
        reader = csv.reader(infile, delimiter=',')
        headers = next(reader, None)
        writer = csv.writer(outfile)
        writer.writerow(headers + HEADERS)
        for item in reader:
            if len(item) > 0:
                retail_url = item[2].strip()
                retail_domain = get_domain(retail_url)
                print('\n=========Querying domain: {}'.format(retail_domain))
                query_list = build_query_list(retail_domain)
                results = get_results_from_solr(retail_domain, query_list)
                results.insert(0, item[0])
                results.insert(1, item[1])
                results.insert(2, item[2])
                results.insert(3, item[3])
                results.insert(4, item[4])
                results.insert(5, item[5])
                writer.writerow(results)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        from_filename = sys.argv[1]
        to_filename = from_filename[0: from_filename.find('.')] + '_result.csv'
        print(to_filename)
        operate_on_csv(from_filename, to_filename)
    else:
        print("Please provide the input filename")
