###################################################################################################
# 1 - Send type of ZAP Report.
# 2 - Send Path of JSON Report
# 3 - Remove Whitelisted Entries
# 4 - Generate JUnit XML File
###################################################################################################
from enum import Enum
from io import BytesIO
import xml.etree.ElementTree as ET
import collections, sys, json, re
Alert = collections.namedtuple('Alert', ['name', 'description', 'solution', 'riskdesc', 'riskcode', 'target', 'raw_results'])
InformationalAlert = collections.namedtuple('Alert', ['name', 'description', 'solution', 'riskdesc', 'riskcode', 'target', 'raw_results'])
LowAlert = collections.namedtuple('Alert', ['name', 'description', 'solution', 'riskdesc', 'riskcode', 'target', 'raw_results'])
MediumAlert = collections.namedtuple('Alert', ['name', 'description', 'solution', 'riskdesc', 'riskcode', 'target', 'raw_results'])
HighAlert = collections.namedtuple('Alert', ['name', 'description', 'solution', 'riskdesc', 'riskcode', 'target', 'raw_results'])
informational_alerts = {}
low_alerts = {}
medium_alerts = {}
high_alerts = {}

whitelist_json = {}

# Define ENUM values as Type of Report
class ZAPDefectRiskLevel(Enum):
    def __str__(self):
        return str(self.value)

    Informational  = 0
    Low  = 1
    Medium  = 2
    High = 3

# Define ENUM values as Type of Report
class ZAPReportType(Enum):
    def __str__(self):
        return str(self.value)

    ZAP_SCAN = 1
    NMAP_SCAN = 3
    SSL_SCAN = 4
    ZAP_ACTIVE_SCAN = 5
    ZAP_MERGED_SCAN = 6
    OTHER = 99

# Read JSON File.
def read_json_from_json_file(path):
    return json.load(open(path))

# Perform Whitelisting if Required. Make it Optional
# URL, ID and NAME is Mandatory in JSON file
def is_whitelisted(plugin_id, uri):
    if  whitelist_json != "":
        if plugin_id in whitelist_json:
            for whitelist_uri in whitelist_json[plugin_id]['regex_uris']:
                if re.match(whitelist_uri, uri):
                    return True
        
    return False

# Fetch All the Alerts from ZAP Scan.
def fetch_all_alerts_from_site(json_obj, fields_to_remove, generateWhitelistXml):
    alerts = {}

    for site in json_obj:
        for alertitem in site['alerts']:

            desc = alertitem.pop('desc')
            solution = alertitem.pop('solution')
            riskdesc = alertitem.pop('riskdesc')
            riskcode = alertitem.pop('riskcode')

            # Remove redundant information from alter
            for key in fields_to_remove:
                if key in alertitem:
                    del alertitem[key]

            # Remove project specific whitelisted alerts
            if generateWhitelistXml == "true":
                alertitem['instances'] = [i for i in alertitem['instances'] \
                    if not is_whitelisted(alertitem['pluginid'], i['uri'])]
            else :
                alertitem['instances'] = [i for i in alertitem['instances'] \
                    if is_whitelisted(alertitem['pluginid'], i['uri'])]

            if not alertitem['instances']:
                continue

            alert = Alert(
                alertitem['name'],
                desc,
                solution,
                riskdesc,
                riskcode,
                site['@name'],
                json.dumps(alertitem, sort_keys=True, indent=2, separators=(',', ': '))
            )
            alerts.setdefault(alertitem['pluginid'], []).append(alert)

            # Fill Alert Object
            if riskcode == str(ZAPDefectRiskLevel.Informational.value):
                informational_alerts.setdefault(alertitem['pluginid'], []).append(alert)
            elif riskcode == str(ZAPDefectRiskLevel.Low.value):
                low_alerts.setdefault(alertitem['pluginid'], []).append(alert)
            elif riskcode == str(ZAPDefectRiskLevel.Medium.value):
                medium_alerts.setdefault(alertitem['pluginid'], []).append(alert)
            elif riskcode == str(ZAPDefectRiskLevel.High.value):
                high_alerts.setdefault(alertitem['pluginid'], []).append(alert)

    return alerts


# Parse JSON based upon type of the report
def parse_json_report(type, json_obj, generateWhitelistXml):
    alerts = {}
    fields_to_remove = ('confidence', 'wascid', 'sourceid', 'riskcode', 'cweid', 'otherinfo')

    # if there is only one site, zap will not return a list, need to make it a list
    if type == ZAPReportType.ZAP_SCAN.value:
        if not isinstance(json_obj['site'], list):
            json_obj['site'] = [json_obj['site']]
    if type == ZAPReportType.ZAP_MERGED_SCAN.value:
        if not isinstance(json_obj['ZAP'][0]['site'], list):
            json_obj['ZAP'][0]['site'] = [json_obj['ZAP'][0]['site']]

    if type == ZAPReportType.ZAP_SCAN.value:
        alerts = fetch_all_alerts_from_site(json_obj['site'],fields_to_remove, generateWhitelistXml)
    if type == ZAPReportType.ZAP_MERGED_SCAN.value:
        alerts = fetch_all_alerts_from_site(json_obj['ZAP'][0]['site'],fields_to_remove, generateWhitelistXml)

    return alerts

def group_defect_alerts(junit_xml, alert_type, alerts, defect_type):
    if any(map(lambda x: any(x), alert_type)):
        parenttestsuite = ET.SubElement(junit_xml, 'testsuite')
        parenttestsuite.set('id', defect_type)
        parenttestsuite.set('name', defect_type)
        for plugin_id in alert_type:
            testsuite = ET.SubElement(parenttestsuite, 'testsuite')
            testsuite.set('id', plugin_id)
            testsuite.set('name', alerts[plugin_id][0].name)
            for alert in alerts[plugin_id]:
                testcase = ET.SubElement(testsuite, 'testcase')
                testcase.set('name', alert.target)
                failure = ET.SubElement(testcase, 'failure')
                failure.set('message', 'Problem:\n' + alert.description + \
                    '\n\nSolution:\n' + alert.solution)
                failure.text = alert.raw_results

    return junit_xml


def generate_junit_xml_group_by_defects_1(alerts):
    junit_xml = ET.Element('testsuites')
    junit_xml.set('id', 'zap.security.scan')

    junit_xml = group_defect_alerts(junit_xml, informational_alerts, alerts, "Info")
    junit_xml = group_defect_alerts(junit_xml, low_alerts, alerts, "Low")
    junit_xml = group_defect_alerts(junit_xml, medium_alerts, alerts, "Medium")
    junit_xml = group_defect_alerts(junit_xml, high_alerts, alerts, "High")

    return junit_xml

# Report portal compatible XML files contains testsuites, testcase tags. It must contain failure attribute
# However, it would be very difficult to convert ZAP to compatible JUnit XML files
# Therefore, convert JSON to recognised JUnit.
# Later on use 'reportportalcypressjunit' agent
def generate_junit_xml_group_by_defects(alerts):
    junit_xml = ET.Element('testsuites')
    junit_xml.set('id', 'zap.security.scan')

    parenttestsuite = ET.SubElement(junit_xml, 'testsuite')
    parenttestsuite.set('id', "Info")
    parenttestsuite.set('name', "Info")
    for plugin_id in informational_alerts:
        testsuite = ET.SubElement(parenttestsuite, 'testsuite')
        testsuite.set('id', plugin_id)
        testsuite.set('name', alerts[plugin_id][0].name)
        for alert in alerts[plugin_id]:
            testcase = ET.SubElement(testsuite, 'testcase')
            testcase.set('name', alert.target)
            failure = ET.SubElement(testcase, 'failure')
            failure.set('message', 'Problem:\n' + alert.description + \
                '\n\nSolution:\n' + alert.solution)
            failure.text = alert.raw_results

    parenttestsuite = ET.SubElement(junit_xml, 'testsuite')
    parenttestsuite.set('id', "Low")
    parenttestsuite.set('name', "Low")
    for plugin_id in low_alerts:
        testsuite = ET.SubElement(parenttestsuite, 'testsuite')
        testsuite.set('id', plugin_id)
        testsuite.set('name', alerts[plugin_id][0].name)
        for alert in alerts[plugin_id]:
            testcase = ET.SubElement(testsuite, 'testcase')
            testcase.set('name', alert.target)
            failure = ET.SubElement(testcase, 'failure')
            failure.set('message', 'Problem:\n' + alert.description + \
                '\n\nSolution:\n' + alert.solution)
            failure.text = alert.raw_results

    parenttestsuite = ET.SubElement(junit_xml, 'testsuite')
    parenttestsuite.set('id', "Medium")
    parenttestsuite.set('name', "Medium")
    for plugin_id in medium_alerts:
        testsuite = ET.SubElement(parenttestsuite, 'testsuite')
        testsuite.set('id', plugin_id)
        testsuite.set('name', alerts[plugin_id][0].name)
        for alert in alerts[plugin_id]:
            testcase = ET.SubElement(testsuite, 'testcase')
            testcase.set('name', alert.target)
            failure = ET.SubElement(testcase, 'failure')
            failure.set('message', 'Problem:\n' + alert.description + \
                '\n\nSolution:\n' + alert.solution)
            failure.text = alert.raw_results

    parenttestsuite = ET.SubElement(junit_xml, 'testsuite')
    parenttestsuite.set('id', "High")
    parenttestsuite.set('name', "High")
    for plugin_id in high_alerts:
        testsuite = ET.SubElement(parenttestsuite, 'testsuite')
        testsuite.set('id', plugin_id)
        testsuite.set('name', alerts[plugin_id][0].name)
        for alert in alerts[plugin_id]:
            testcase = ET.SubElement(testsuite, 'testcase')
            testcase.set('name', alert.target)
            failure = ET.SubElement(testcase, 'failure')
            failure.set('message', 'Problem:\n' + alert.description + \
                '\n\nSolution:\n' + alert.solution)
            failure.text = alert.raw_results

    return junit_xml

def generate_junit_xml(alerts):
    junit_xml = ET.Element('testsuites')
    junit_xml.set('id', 'zap.security.scan')
    for plugin_id in alerts:
        testsuite = ET.SubElement(junit_xml, 'testsuite')
        testsuite.set('id', plugin_id)
        testsuite.set('name', alerts[plugin_id][0].name)
        for alert in alerts[plugin_id]:
            testcase = ET.SubElement(testsuite, 'testcase')
            testcase.set('name', "["+alert.riskdesc+"] "+alert.target)
            failure = ET.SubElement(testcase, 'failure')
            failure.set('message', 'Problem:\n' + alert.description + \
                '\n\nSolution:\n' + alert.solution)
            failure.text = alert.raw_results

    return junit_xml

# Create XML file/ Overwrites XML file if Exists. XML declaration is Mandatory
def write_xml_data_to_file(xml, filename):
    f = BytesIO()
    et = ET.ElementTree(xml)
    et.write(f, encoding='utf-8', xml_declaration=True)
    outfile = open(filename, 'wb')
    outfile.write(f.getvalue())
    outfile.close

def convert(type , jsonFilePath, whitelistJsonFilePath, generateWhitelistXml, outputFilePath):
    json_report = read_json_from_json_file(jsonFilePath)
    global whitelist_json
    if  whitelistJsonFilePath != "":
        whitelist_json = read_json_from_json_file(whitelistJsonFilePath)

    alerts = parse_json_report(type, json_report, generateWhitelistXml)
    junit_xml = generate_junit_xml_group_by_defects_1(alerts)
    write_xml_data_to_file(junit_xml, filename=outputFilePath)