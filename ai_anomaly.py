# ai_model_trainer_enterprise.py

import joblib, json, os
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import CountVectorizer

# === 1. Static Normal & Anomalous Samples ===
normal_samples = [
    # === Secure Core Services ===
    "22/tcp ssh OpenSSH_9.3p1",                     # Hardened latest SSH
    "80/tcp http Apache_2.4.58",                    # Patched Apache
    "443/tcp https nginx_1.24.0",                   # TLS-enforced web server
    "3306/tcp mysql MySQL_8.0.36",                  # Latest MySQL with auth
    "5432/tcp postgresql PostgreSQL_15.3",          # Patched PostgreSQL
    "3389/tcp rdp Microsoft-RDP_10.0_secure",       # RDP with NLA
    
    # === Internal Monitoring / Mgmt ===
    "161/udp snmp SNMPv3_encrypted",                # Secure SNMP
    "162/udp snmptrap SNMPv3",                      # Secure SNMP trap
    "514/udp syslog rsyslog_8.2302",                # Hardened syslog
    "22/tcp ssh bastion_host_only",                # Jump server SSH only
    
    # === DNS/NTP/Email (Properly configured) ===
    "53/udp dns BIND_9.18.20",                      # DNS server patched
    "123/udp ntp NTP_4.2.8p15",                     # Authenticated NTP
    "25/tcp smtp Postfix_3.7.4_tls",                # Mail relay
    "110/tcp pop3 Dovecot_2.3.21",                  # POP3 over TLS
    "143/tcp imap Dovecot_2.3.21",                  # IMAP with STARTTLS
    
    # === Directory/Domain Controllers ===
    "389/tcp ldap OpenLDAP_2.6.4_tls",              # LDAP with TLS
    "636/tcp ldaps OpenLDAP_2.6.4",                 # LDAP secure
    "88/tcp kerberos MIT_Kerberos_1.20.1",          # Kerberos authentication

    # === Web & App Stacks (secured) ===
    "8080/tcp http Apache_Tomcat_10.1.10",          # Modern Tomcat
    "9443/tcp https SpringBoot_3.2_secure",         # Hardened Spring API
    "3000/tcp grafana Grafana_10.2_dashboard",      # Grafana with Auth
    "9090/tcp prometheus Prometheus_2.48.1",        # Metrics, no remote write
    
    # === Cloud & DevSecOps Tools (Auth-enabled) ===
    "9000/tcp sonarqube SonarQube_10.4",            # Code scanner
    "8081/tcp nexus Nexus_3.63.0_auth",             # Artifact manager
    "15672/tcp rabbitmq RabbitMQ_3.12_dashboard_tls",# Secure dashboard
    "8888/tcp jupyter Secure_JupyterHub",           # Not public

    # === Database & Message Brokers ===
    "27017/tcp mongodb MongoDB_6.0.12_auth",        # Mongo with x509
    "6379/tcp redis Redis_7.2_tls",                 # Redis TLS+Auth
    "1521/tcp oracle Oracle_19c_DB",                # Hardened Oracle DB
    "9200/tcp elasticsearch Elastic_8.12.2_tls",    # Secured cluster

    # === Virtualization / Infrastructure Ports ===
    "8443/tcp vcenter VMware_7.0_u3",               # Patched vCenter
    "5985/tcp winrm WinRM_3.0_kerberos_only",       # Auth-restricted
    "5900/tcp vnc RealVNC_7.5_TLS",                 # Encrypted VNC
    "7000/tcp backup_server Veeam_12",              # Backup agent
    "9997/tcp splunk_forwarder Splunk_9.2.1"        # Secure telemetry

    # === IoT / SCADA secured (used in research centers) ===
    "102/tcp siemens_s7comm_encrypted",             # Siemens PLC (TLS)
    "2404/tcp iec104 Authenticated_IEC104",         # Smart grid protocol
]


anomalous_samples = [
    # === Known RCEs / CVEs ===
    "21/tcp ftp vsftpd_2.3.4_backdoor CVE-2011-2523",
    "22/tcp ssh Dropbear_2012", "445/tcp smb EternalBlue CVE-2017-0144",
    "3389/tcp rdp BlueKeep CVE-2019-0708", "80/tcp http phpmyadmin_exposed",
    "443/tcp https kibana CVE-2021-43798", "7001/tcp weblogic Ghostcat CVE-2020-2551",
    "4505/tcp saltstack CVE-2020-11651", "8009/tcp ajp CVE-2020-1938",
    "3000/tcp grafana CVE-2021-43798", "5601/tcp kibana default_creds",
    "5000/tcp docker_api no_auth CVE-2019-5736", "10250/tcp kubelet no_auth CVE-2018-1002105",
    "2375/tcp docker_daemon exposed", "1433/tcp mssql SA_login CVE-2022-35829",
    "3306/tcp mysql root_login", "8081/tcp nexus_repo exposed",
    "8086/tcp influxdb metrics_leak", "8888/tcp jupyter exposed",
    "15672/tcp rabbitmq dashboard_open", "9200/tcp elasticsearch no_auth",
    "8443/tcp vcenter CVE-2021-21972", "16992/tcp amt exposed",
    "5985/tcp winrm exposed", "12345/tcp netbus_backdoor",
    "31337/tcp elite_port", "7000/tcp dev_console open",

    # === Cloud/IoT/Backdoor Attack Surfaces ===
    "7547/tcp tr-069 Mirai_CVE-2017-17215", "5555/tcp adb android_open",
    "554/tcp rtsp ip_camera", "2379/tcp etcd open_cluster",
    "81/tcp webcam admin_port", "4000/tcp p2p_backdoor",
    "10000/tcp webmin exposed", "5986/tcp winrm_ssl auth_bypass",
    "22/tcp ssh hardcoded_credential_backdoor", "25/tcp smtp open_relay",
    
    # === Web & Cloud Exploits ===
    "80/tcp http exposed_admin_panel", "80/tcp http laravel_env_leak",
    "443/tcp https exposed_gitlab_runner", "5001/tcp minio open_api",
    "8080/tcp springboot actuator_exposed", "8000/tcp uvicorn debug_open",
    "8889/tcp jupyter_auth_disabled", "9000/tcp sonarqube unauth_dashboard",

    # === Lateral Movement / Escalation / Abuse ===
    "135/tcp dcom lateral_vector", "5985/tcp winrm script_abuse",
    "22/tcp ssh passwordless_rsa_login", "389/tcp ldap anon_bind",
    "111/tcp rpcbind exposed", "137/tcp netbios info_leak",

    # === Simulated Behavioral Anomalies ===
    "behavior:portscan_100_ports",
    "behavior:arp_poisoning",
    "behavior:syn_flood_1000_syns",
    "behavior:bruteforce_login",
    "behavior:mac_spoofing",
    "behavior:smb_relay_attack",
    "behavior:icmp_tunnel_detected",
    "behavior:unauthorized_proxy_usage",
    "behavior:sudo_log_clear",
    "behavior:nmap_aggressive_scan",
    "behavior:kerberos_ticket_spray"
]


# 2. Optional Log Retraining
json_path = "results.json"
if os.path.exists(json_path):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            log_samples = json.load(f)
            for r in log_samples:
                s = r.get("Services", "")
                if any(tag in r.get("Alert", "").lower() for tag in ["critical", "high"]):
                    anomalous_samples.append(s.lower())
                else:
                    normal_samples.append(s.lower())
    except Exception as e:
        print(f"[!] Could not parse logs for retraining: {e}")

# 3. Train Model
X = normal_samples + anomalous_samples
y = [1] * len(normal_samples) + [-1] * len(anomalous_samples)

vectorizer = CountVectorizer()
X_vec = vectorizer.fit_transform(X)

model = IsolationForest(contamination=0.25, random_state=42)
model.fit(X_vec)

# 4. Save
joblib.dump(model, "ai_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")
print("AI model & vectorizer trained and saved.")
print(f"→ Normal: {len(normal_samples)} | Anomalous: {len(anomalous_samples)}")
