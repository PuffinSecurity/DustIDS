rule unsolicited_response : DNP3 
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.0"
    description = "Server reports an unsolicited response from client."
    impact = "The server receives an unexpected response from the client, which might indicate abnormal behavior."
    uuid = "4d2d28ec58684736914e7c779f0d528c"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Monitor the information system to detect and respond to inappropriate or unusual activity."
  strings: 
    $dnp3_header = { 05 64 }
    $unsolicited_response = { 82 }
  condition: 
    $dnp3_header at 0 and $unsolicited_response at 12 and #dnp3_header < 2
}

rule cold_restart : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.0"
    description = "Client sends a cold restart command."
    impact = "Client instructs the device to perform a cold restart, which might cause disruptions."
    uuid = "12010549da5148508a53294062755d5a" 
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings:
    $dnp3_header = { 05 64 }
    $cold_restart = { 0d }
  condition:
    $dnp3_header at 0 and $cold_restart at 12 and #dnp3_header < 2
}

rule warm_restart : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.0"
    description = "Client sends a warm restart command."
    impact = "Client instructs the device to perform a warm restart, which might cause temporary disruptions."
    uuid = "8d6a7c77057c48daa3c72001e9f3d689" 
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings:
    $dnp3_header = { 05 64 }
    $warm_restart = { 0e }
  condition:
    $dnp3_header at 0 and $warm_restart at 12 and #dnp3_header < 2
}

rule broadcast_request : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.4.0"
    description = "Client sends a broadcast request."
    impact = "Broadcast requests might affect multiple devices simultaneously, potentially causing network congestion."
    uuid = "0d7be1ab27244756ae5f11b00fd37ac1" 
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Monitor the information system to detect and respond to inappropriate or unusual activity."
  strings:
    $dnp3_header = { 05 64 }
    $broadcast = { FF FF }
  condition:
    $dnp3_header at 0 and $broadcast at 4 and #dnp3_header < 2
}

rule unauthorized_write_req_to_plc : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "Client sends an unauthorized write request."
    impact = "Unauthorized write requests can modify PLC behavior or data, potentially leading to malfunction."
    uuid = "03e323f2ffc94d4593b5487f882b1b79"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Enforce approved authorizations for logical access to the system in accordance with applicable policy."
  strings:
    $dnp3_header = { 05 64 }
    $payload = /(\x02|\x04|\x05|\x06|\x09|\x0A|\x0F|\x12)/
  condition:
    $dnp3_header at 0 and $payload at 12 and #dnp3_header < 2
}

rule unauthorized_miscellaneous_req_to_plc : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.1"
    description = "Client sends an unauthorized miscellaneous request."
    impact = "Unauthorized miscellaneous requests can lead to various disruptions or changes in PLC operation."
    uuid = "275a728dcd0b419dbf480a618fc13853"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Enforce approved authorizations for logical access to the system in accordance with applicable policy."
  strings:
    $dnp3_header = { 05 64 }
    $payload = /(\x03|\x07|\x08|\x0B|\x0C|\x10|\x11|\x13|\x14|\x15|\x16|\x17|\x18|\x19|\x1A|\x1B|\x1C|\x1D|\x1E)/
  condition:
    $dnp3_header at 0 and $payload at 20 and #dnp3_header < 2
}

rule points_list : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.1"
    description = "Points list is transmitted."
    impact = "Transmission of points list may indicate regular or unauthorized access to system points data."
    uuid = "275a728dcd0b419dbf480a618fc13853"
    standard = "NIST SP 800-82"
    category = "AU"
    category_name = "Audit and Accountability"
    control = "AU-12"
    control_description = "Audit Record Generation: Create audit records containing sufficient information to establish what events occurred, the sources of the events, and the outcomes of the events."
  strings:
    $dnp3_header = { 05 64 }
    $list = { 81 }
    $payload = /(\x02|\x04|\x06|\x0a|\x0c|\x0e)/
  condition:
    $dnp3_header at 0 and $list at 12 and $payload at 14 and #dnp3_header < 2
}

rule function_code_request : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.2"
    description = "Function code request is sent."
    impact = "Function code requests might indicate querying or commanding device operations."
    uuid = "0a49ad1330134004a09469fe9f6fc0ae"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Monitor the information system to detect and respond to inappropriate or unusual activity."
  strings:
    $dnp3_header = { 05 64 }
    $code_req = { 81 ?? 01 }
  condition:
    $dnp3_header at 0 and $code_req at 12 and #dnp3_header < 2
}

rule stop_application : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.1"
    description = "Client sends a stop application command."
    impact = "Client instructs the device to stop an application, potentially halting critical processes."
    uuid = "12010549da5148508a53294062755d5a" 
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings:
    $dnp3_header = { 05 64 }
    $stop_app = { 12 }
  condition:
    $dnp3_header at 0 and $stop_app at 12 and #dnp3_header < 2
}

rule link_status_scan : DNP3
{
  meta:
    protocol = "DNP3"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.4.1"
    description = "Link status scan is performed."
    impact = "Link status scans are used to check the status of network links, potentially for monitoring or diagnostics."
    uuid = "0ce7610402b84de29f5c1bbf8b47529b" 
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Monitor the information system to detect and respond to inappropriate or unusual activity."
  strings:
    $dnp3_header = { 05 64 }
    $link_layer_control = { 05 c9 ?? 00 }    
  condition:
    $dnp3_header at 0 and $link_layer_control at 2 and #dnp3_header < 2
}
