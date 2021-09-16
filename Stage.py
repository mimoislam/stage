import json

import requests
import xml.etree.cElementTree as e
import xmltodict, json
import argparse
import xml.etree.ElementTree as ET
import os.path


# parser = argparse.ArgumentParser()
# parser.add_argument('-x', action='store_true',metavar='N', type=int, nargs='+',)
# options = parser.parse_args()
# if options.x:
#     print(options.x)

def Apache(parser,path):
    if not os.path.exists(path):

        parser.error("The file %s does not exist!" % path)
        return
    else:
        if not path.endswith('.xml'):
            parser.error("The file %s is not .xml file" % path)
            return
        tree = ET.parse(path)


        root = tree.getroot()
        country= ET.tostring(root)
        result =xmltodict.parse(country)
        obj=result["ns0:project"]["ns0:dependencies"]['ns0:dependency']
        idx=-1
        for package in obj:
            idx=idx+1

            groupId = package['ns0:groupId'].split('.')
            vendor = groupId[0]
            vendor2=''
            if groupId[0] == 'org':
                vendor = groupId[1]
            elif groupId[0] == 'com':
                vendor = groupId[1]
            elif groupId[0] == 'net':
                vendor = groupId[2]
            elif groupId[0] == 'nl':
                vendor = 'apache'
            elif groupId[0] == 'io':
                vendor = groupId[1]
            elif groupId[0] == 'javax':
                pass
            else:
                vendor2 = 'apache'
                vendor = groupId[0]
            if vendor2=='':
                AddToParseList(vendor2+'/'+package['ns0:artifactId'],        package['ns0:version'])
                AddToParseList(vendor2+'/'+package['ns0:artifactId'].replace('-','_'),  package['ns0:version'])
                AddToParseList(vendor2.replace('-', '_')+'/'+package['ns0:artifactId'],        package['ns0:version'])
                AddToParseList(vendor2.replace('-', '_')+'/'+package['ns0:artifactId'].replace('-','_'),  package['ns0:version'])
                idx=idx+4
            AddToParseList(vendor + '/' + package['ns0:artifactId'],  package['ns0:version'])
            AddToParseList(vendor + '/' + package['ns0:artifactId'].replace('-', '_'),  package['ns0:version'])
            AddToParseList(vendor.replace('-', '_') + '/' + package['ns0:artifactId'], package['ns0:version'])
            AddToParseList(vendor.replace('-', '_') + '/' + package['ns0:artifactId'].replace('-', '_'), package['ns0:version'])
            idx = idx + 4


def Laravel(parser,path):
    if not os.path.exists(path):
        parser.error("The file %s does not exist!" % path)
    else:
        if not path.endswith('.lock'):
            parser.error("The file %s is not .lock file" % path)
            return
        with open(path) as jsonFile:
            jsonObject = json.load(jsonFile)
            jsonFile.close()
        for idx, package in enumerate(jsonObject['packages']):
            AddToParseList(package['name'], package['version'])



def addtoList(v, p, r,ve):
    global reportList
    reportList[v + "/" + p] = {
        'cve_id': r['cve']['CVE_data_meta']['ID'],
        'description_data': r['cve']['description']['description_data'],
        'cwe': r['cve']['problemtype']['problemtype_data'],
        'publishedDate': r['publishedDate'],
        'lastModifiedDate': r['lastModifiedDate'],
        'baseMetricV3': r['impact']['baseMetricV3'],
        'baseMetricV2': r['impact']['baseMetricV2'],
        'version': ve
    }
def CheckCpe(string,vendor,result,cpeMatch):
    global  nameVendors
    if ((string[3]).find(vendor)) == 0:

        for package in nameVendors[vendor]:

            if (string[4] == package):
                if string[5] == nameVendors[vendor][package]:
                    addtoList(vendor, package, result, nameVendors[vendor][package])
                    print(vendor + "/" + package + " Version : " + string[5])
                    print('this is the package we are looking for')

                elif (string[5] == '*'):
                    if "versionStartIncluding" in cpeMatch:
                        versionStart = cpeMatch['versionStartIncluding'].split('.')
                        for x in range(len(versionStart) - 1, 2):
                            versionStart.append('0')
                        excluding = False
                        if 'versionEndExcluding' in cpeMatch:
                            excluding = True
                            versionEnd = cpeMatch['versionEndExcluding'].split('.')
                            for x in range(len(versionEnd) - 1, 2):
                                versionEnd.append('0')
                        else:
                            versionEnd = cpeMatch['versionEndIncluding'].split('.')
                            for x in range(len(versionEnd) - 1, 2):
                                versionEnd.append('0')

                        vers = nameVendors[vendor][package].split('.')
                        vers = [int(i) for i in vers]
                        versionEnd = [int(i) for i in versionEnd]
                        versionStart = [int(i) for i in versionStart]
                        first = (versionStart[0] <= vers[0]) & (
                            ((versionEnd[0] >= vers[0]) & excluding))

                        second = (versionStart[1] <= vers[1]) & (
                                (versionEnd[1] >= vers[1]) & excluding)

                        third = (versionStart[2] <= vers[2]) & (
                                ((versionEnd[2] > vers[2]) & excluding) |
                                ((versionEnd[2] >= vers[2]) & (
                                    not excluding)))
                        if (first) :
                                if (second) :
                                        if third:
                                            addtoList(vendor, package, result, nameVendors[vendor][package])
                                            print(
                                                vendor + "/" + package + " Version : " + nameVendors[vendor][package])
                                            print('this is the package we are looking for '
                                                  'Hello1')

                    else:
                        if 'versionEndIncluding' in cpeMatch:
                            if cpeMatch['versionEndIncluding'] == nameVendors[vendor][package]:
                                addtoList(vendor, package, result, nameVendors[vendor][package])
                                print(vendor + "/" + package + " Version : " + nameVendors[vendor][package])
                                print('this is the package we are looking for versionEndIncluding')


def CheckWithKeyWord():
    global nameVendors
    for vendor in nameVendors:

        print('https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=' + vendor)
        contents = requests.get('https://services.nvd.nist.gov/rest/json/cves/1.0?keyword=' + vendor)
        if contents.status_code == 200:
            test = json.loads(contents.content)
            if 'result' in test:
                for result in test['result']['CVE_Items']:
                    for cpe in result['configurations']['nodes']:
                        for cpeMatch in cpe['cpe_match']:
                            string = (cpeMatch['cpe23Uri']).split(':')
                            CheckCpe(string, vendor, result,cpeMatch)

        else:
            print(str(contents.status_code) + ' error ')
def CheckWithCpe():
    global nameVendors
    for vendor in nameVendors:
        for package in nameVendors[vendor]:
            print('https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=cpe:2.3:a:*' + vendor+'*:'+package+':'+nameVendors[vendor][package])
            contents = requests.get('https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=cpe:2.3:a:*'  + vendor+'*:'+package+':'+nameVendors[vendor][package])
            if contents.status_code == 200:
                test = json.loads(contents.content)
                if 'result' in test:
                    for result in test['result']['CVE_Items']:
                        addtoList(vendor, package, result, nameVendors[vendor][package])
            else:
                print(str(contents.status_code) + ' error ')
def AddToParseList (name,version):
    global nameVendors

    exp = name.split("/", 1)
    version = version.replace('v', '')
    if exp[0] in nameVendors:
        nameVendors[exp[0]][exp[1]] = version
    else:
        nameVendors[exp[0]] = {exp[1]: version}
def ReportJson():
    global reportList
    with open('packages.json') as jsonFile:
        jsonObject = json.load(jsonFile)
        jsonFile.close()
    if 'json' in jsonObject :
        jsonreport={}
        for cve in reportList :
            for report in jsonObject['json']['placement']:
                jsonreport[jsonObject['json']['placement'][report]]=reportList[cve][report]

        jsonfile = open(jsonObject['json']['output']+"/"+jsonObject['json']['template'], "w")
        json.dump(jsonreport, jsonfile, indent=4, sort_keys=False)

def indent(elem, level=0):
    i = "\n" + level*"  "
    if len(elem):
        if not elem.text or not elem.text.strip():
            elem.text = i + "  "
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
        for elem in elem:
            indent(elem, level+1)
        if not elem.tail or not elem.tail.strip():
            elem.tail = i
    else:
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = i

def ReportXml():
    global reportList
    first = ET.Element('Report')
    with open('packages.json') as jsonFile:
        jsonObject = json.load(jsonFile)
        jsonFile.close()
    if 'xml' in jsonObject:
        placement=jsonObject['xml']['placement']
        for name in reportList:
            r = e.SubElement(first, 'CVE')
            e.SubElement(r, 'package').text = str(name)
            if 'cve_id' in placement:
                e.SubElement(r,placement['cve_id']).text = str(reportList[name]['cve_id'])
            if 'publishedDate'in placement:
                e.SubElement(r,placement['publishedDate']).text = str(reportList[name]['publishedDate'])
            if 'lastModifiedDate' in placement:
                e.SubElement(r,placement['lastModifiedDate']).text = str(reportList[name]['lastModifiedDate'])
            if 'version'in placement:
                e.SubElement(r,placement['version']).text = str(reportList[name]['version'])


            if 'description_data'in placement:

                description_data=e.SubElement(r,placement['description_data'])


                for z in reportList[name]['description_data']:
                    e.SubElement(description_data, "lang").text = str(z["lang"])
                    e.SubElement(description_data, "value").text = str(z["value"])
            if 'cwe'in placement:
                cwe=e.SubElement(r,placement['cwe'])

                for z in reportList[name]['cwe']:
                    description = e.SubElement(cwe, 'description')
                    for res in z['description']:
                        e.SubElement(description, "lang").text = str(res["lang"])
                        e.SubElement(description, "value").text = str(res["value"])
            if 'baseMetricV3' in placement:
                baseMetricV3 = e.SubElement(r, placement['baseMetricV3'])
                e.SubElement(baseMetricV3, 'exploitabilityScore').text = str(reportList[name]['baseMetricV3']['exploitabilityScore'])
                e.SubElement(baseMetricV3, 'impactScore').text = str(reportList[name]['baseMetricV3']['impactScore'])
                cvssV3 = e.SubElement(baseMetricV3, 'cvssV3')
                for n in reportList[name]['baseMetricV3']['cvssV3']:
                    e.SubElement(cvssV3, n).text = str(reportList[name]['baseMetricV3']['cvssV3'][n])
            if 'baseMetricV2' in placement:
                baseMetricV2 = e.SubElement(r,placement ['baseMetricV2'])

                e.SubElement(baseMetricV3, 'severity').text = str(reportList[name]['baseMetricV2']['severity'])
                e.SubElement(baseMetricV3, 'exploitabilityScore').text = str(reportList[name]['baseMetricV2']['exploitabilityScore'])
                e.SubElement(baseMetricV3, 'impactScore').text = str(reportList[name]['baseMetricV2']['impactScore'])
                e.SubElement(baseMetricV3, 'obtainAllPrivilege').text = str(reportList[name]['baseMetricV2']['obtainAllPrivilege'])
                e.SubElement(baseMetricV3, 'obtainUserPrivilege').text = str(reportList[name]['baseMetricV2']['obtainUserPrivilege'])
                e.SubElement(baseMetricV3, 'obtainOtherPrivilege').text = str(reportList[name]['baseMetricV2']['obtainOtherPrivilege'])
                e.SubElement(baseMetricV3, 'userInteractionRequired').text = str(reportList[name]['baseMetricV2']['userInteractionRequired'])
                cvssV2 = e.SubElement(baseMetricV2, 'cvssV2')
                for n in reportList[name]['baseMetricV2']['cvssV2']:
                    e.SubElement(cvssV2, n).text = str(reportList[name]['baseMetricV2']['cvssV2'][n])
            indent(r)

        a = e.ElementTree(first)

        a.write("json_to_xml.xml",encoding="utf-8", xml_declaration=True)

if __name__=='__main__':
    nameVendors = {}

    parser = argparse.ArgumentParser(description="ikjMatrix multiplication")
    # parser.add_argument("-i", dest="filename", required=True,
    #                     help="input file with two matrices", metavar="FILE",
    #                     type=lambda x: is_valid_file(parser, x))
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-a", dest="filename",
                        help="input file with two matrices", metavar="FILE",
                        type=lambda x: Apache(parser, x))
    group.add_argument("-l", dest="filename",
                        help="input file with two matrices", metavar="FILE",
                        type=lambda x: Laravel(parser, x))
    args = parser.parse_args()




    ######## Save File of packages as json





    # add to AddToParseList changement


    reportList = {}
    CheckWithCpe()
    ReportXml()
    ReportJson()