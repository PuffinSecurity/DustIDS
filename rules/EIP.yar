rule eip_change_date_binary_v180414 : EIP
{
  meta:
    protocol = "ETHERNET/IP"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.0"
    description = "EIP command to change date."
    impact = "Changes the system date on the device, which could affect time-sensitive operations."
    uuid = "55d9d9f409084e88849e13b17c7e1964"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Monitor the information system to detect and respond to inappropriate or unusual activity."
  strings: 
    $eip_header = { 70 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 }
    $eip_command = { 04 02 20 8b 24 01 }
  condition: 
    $eip_header at 0 and $eip_command
}

rule eip_change_port_binary_v180414 : EIP
{
  meta:
    protocol = "ETHERNET/IP"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.1"
    description = "EIP command to change port."
    impact = "Changes the network port configuration, potentially affecting communication."
    uuid = "65a5cc55984f4f4a87e4d7240df42b9c"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $eip_header = { 6f 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 }
    $eip_command = { 10 03 20 f6 24 01 30 06 }
  condition: 
    $eip_header at 0 and $eip_command
}

rule eip_firmware_update_binary_v180414 : EIP
{
  meta:
    protocol = "ETHERNET/IP"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.2"
    description = "EIP command to update firmware."
    impact = "Updates the device firmware, which could introduce new functionalities or vulnerabilities."
    uuid = "2a362f18b65345e5a383f3d8f969c1cf"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-2"
    control_description = "Flaw Remediation: Identify, report, and correct information system flaws and provide protection from the flaws until they are corrected."
  strings: 
    $eip_header = { 6f 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 }
    $eip_command = { 4d 02 20 a1 }
  condition: 
    $eip_header at 0 and $eip_command
}

rule eip_software_upload_v180414 : EIP
{
  meta:
    protocol = "ETHERNET/IP"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.3"
    description = "EIP command to upload software."
    impact = "Uploads new software to the device, which might alter its behavior or introduce vulnerabilities."
    uuid = "ebd854843822473e96a91ffcb8a5621f"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-2"
    control_description = "Flaw Remediation: Identify, report, and correct information system flaws and provide protection from the flaws until they are corrected."
  strings: 
    $eip_header = { 70 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 }
    $eip_command = { 4f 03 20 6a }
  condition: 
    $eip_header at 0 and $eip_command
}

rule eip_reset_binary_v180414 : EIP
{
  meta:
    protocol = "ETHERNET/IP"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.4"
    description = "EIP command to reset the device."
    impact = "Resets the device, which might interrupt its operations temporarily."
    uuid = "c4aeb36570ef40b29ccac97a1583fdd0"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings: 
    $eip_header = { 70 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 }
    $eip_command = { 05 02 20 ?? 24 ?? }
  condition: 
    $eip_header at 0 and $eip_command
}

rule eip_start_binary_v180414 : EIP
{
  meta:
    protocol = "ETHERNET/IP"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.5"
    description = "EIP command to start the device."
    impact = "Starts the device operations, potentially resuming any interrupted processes."
    uuid = "94c7d2fce8f748fe9549ed70fa7e3454"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings: 
    $eip_header = { 70 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 }
    $eip_command = { 06 02 20 ?? 24 ?? }
  condition: 
    $eip_header at 0 and $eip_command
}

rule eip_stop_binary_v180414 : EIP
{
  meta:
    protocol = "ETHERNET/IP"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.6"
    description = "EIP command to stop the device."
    impact = "Stops the device operations, potentially halting critical processes."
    uuid = "6c484f4ae87d4512a02a6952ee9add2a"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings: 
    $eip_header = { 70 00 ?? ?? ?? ?? ?? ?? 00 00 00 00 }
    $eip_command = { 07 02 20 ?? 24 ?? }
  condition: 
    $eip_header at 0 and $eip_command
}
