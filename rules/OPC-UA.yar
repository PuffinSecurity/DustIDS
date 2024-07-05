rule browse_request_forward : OPC_UA
{
  meta:
    protocol = "OPC_UA"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Detects an OPC UA browse request broadcast with subtypes."
    impact = "Identifies browsing operations in OPC UA servers, which may indicate network scanning or enumeration."
    uuid = "8d57814a742e428cb4c4a52a093cde72"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Detects browsing operations to identify potential network scanning or enumeration."
  strings:
    $opc_ua_header = { 4d 53 47 }
    $browse_request_header = { 02 00 00 }
    $browse_direction_forward = { 00 00 00 00 }
    $browse_subtypes = { 01 }
    $node_class_mask = { 00 00 00 00 }
  condition:
    $opc_ua_header at 0 and $browse_request_header at 28 and $browse_direction_forward at 91 and $browse_subtypes at 97 and $node_class_mask at 98
}

rule request_session_python_client : OPC_UA
{
  meta:
    protocol = "OPC_UA"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Detects a Python client requesting a session."
    impact = "Identifies sessions initiated by Python clients, which may indicate automation or scripting access."
    uuid = "5acd84d20d144a3cba75165a02035a88"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Detects Python client session requests to monitor remote access attempts."
  strings:
    $opc_ua_header = { 4d 53 47 }
    $python_client = "Pure Python Client"
    $application_uri = "urn:freeopcua:client"
    $product_uri = "urn:freeopcua.github.no:client"
  condition:
    $opc_ua_header at 0 and $python_client and $product_uri and $application_uri
}

rule request_session_dotnet_client : OPC_UA
{
  meta:
    protocol = "OPC_UA"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Detects a .NET client requesting a session."
    impact = "Identifies sessions initiated by .NET clients, which may indicate automation or scripting access."
    uuid = "5acd84d20d144a3cba75165a02035a88"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Detects .NET client session requests to monitor remote access attempts."
  strings:
    $opc_ua_header = { 4d 53 47 }
    $urn = "urn:"
    $product_uri = "opcfoundation.org/UASDK"
  condition:
    $opc_ua_header at 0 and $product_uri and $urn
}

rule request_session_eclipse_milo_client : OPC_UA
{
  meta:
    protocol = "OPC_UA"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Detects an Eclipse Milo client requesting a session."
    impact = "Identifies sessions initiated by Eclipse Milo clients, which may indicate automation or scripting access."
    uuid = "5acd84d20d144a3cba75165a02035a88"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Detects Eclipse Milo client session requests to monitor remote access attempts."
  strings:
    $opc_ua_header = { 4d 53 47 }
    $python_client = "Milo Client"
    $application_uri = "urn:eclipse:milo"
    $product_uri = "projects.eclipse.org/projects/iot.milo"
  condition:
    $opc_ua_header at 0 and $python_client and $product_uri and $application_uri
}

rule request_session_nodejs_client : OPC_UA
{
  meta:
    protocol = "OPC_UA"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Detects a Node.js client requesting a session."
    impact = "Identifies sessions initiated by Node.js clients, which may indicate automation or scripting access."
    uuid = "5acd84d20d144a3cba75165a02035a88"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Detects Node.js client session requests to monitor remote access attempts."
  strings:
    $opc_ua_header = { 4d 53 47 }
    $urn = "urn:"
    $node_opcua_uri = ":NodeOPCUA-Client"
  condition:
    $opc_ua_header at 0 and $urn and $node_opcua_uri
}

rule request_session_without_cert : OPC_UA
{
  meta:
    protocol = "OPC_UA"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Detects a client requesting a session without a certificate."
    impact = "Identifies clients attempting to establish sessions without providing a certificate, which may indicate a potential security risk."
    uuid = "2cdef1e9e478438f9b8e9882f0e60e6b"
    standard = "NIST SP 800-82"
    category = "IA"
    category_name = "Identification and Authentication"
    control = "IA-5"
    control_description = "Authenticator Management: Detects session requests without certificates to identify potential security risks."
  strings:
    $opc_ua_header = { 4d 53 47 }
    $certificate = { FF FF FF FF }
  condition:
    $opc_ua_header at 0 and $certificate at 259
}

rule localhost_client : OPC_UA
{
  meta:
    protocol = "OPC_UA"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Detects a client requesting access from localhost."
    impact = "Identifies local access attempts, which may indicate local testing or internal scanning."
    uuid = "3ae9f1b5f8b7420a9d8f935e9ed3c9b0"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-20"
    control_description = "Use of External Information Systems: Detects local access attempts to monitor testing or internal scanning activities."
  strings:
    $opc_ua_header = { 4d 53 47 }
    $opc_uri = "opc.tcp://127.0.0.1"
  condition:
    $opc_ua_header at 0 and $opc_uri at 162
}

rule client_from_internet : OPC_UA
{
  meta:
    protocol = "OPC_UA"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Detects a client requesting access from the internet."
    impact = "Identifies remote access attempts, which may indicate external scanning or unauthorized access."
    uuid = "1f8e37b8e4a24e41b7a2b4f01f31e3f0"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-20"
    control_description = "Use of External Information Systems: Detects remote access attempts to monitor external scanning or unauthorized access."
  strings:
    $opc_ua_header = { 4d 53 47 }
    $protocol = "opc.tcp://"
    $ip = /[0-9]{1,3}\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})/
    $private_ip = /(10\.)|(172\.1[6-9])|(172\.2[0-9])|(172\.3[0-1])|(192\.168)/
  condition:
    $opc_ua_header at 0 and $protocol at 162 and $ip at 172 and not $private_ip at 172
}
