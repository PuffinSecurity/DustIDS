rule Siemens_S7_Set_Clock : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Set clock request"
    impact = "Allows time synchronization or manipulation of the PLC clock."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "0d35a1d41247421aae837dfa57cd0638"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.0"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects clock synchronization or manipulation requests."
  strings:
    $header = { 03 00 }
    $payload1 = { 32 07 00 }
    $payload2 = { 00 01 12 04 11 47 02 00 }
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17
}

rule Siemens_S7_Set_Password : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Set PLC session password request"
    impact = "Enables setting or changing the session password, enhancing security control."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "3350a6d871c74db39fc7cb765db9324e"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.2"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "IA"
    category_name = "Identification and Authentication"
    control = "IA-5"
    control_description = "Authenticator Management: Detects requests to set or change PLC session passwords."
  strings:
    $header = { 03 00 }
    $payload = { 00 01 12 04 11 45 01 00 }
  condition:
    $header at 0 and $payload at 17
}

rule Siemens_S7_Set_CPU_Stop : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Set PLC CPU stop request"
    impact = "Commands the PLC CPU to stop, halting operations."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "c2a7529d561e463383f4ee579aafd913"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.1.0"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "System Recovery and Reconstitution: Detects CPU stop commands to halt operations."
  strings:
    $payload = { 29 00 00 00 00 00 09 50 5f 50 52 4f 47 52 41 4d }
  condition:
    $payload
}

rule Siemens_S7_Set_CPU_Hot_Restart : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Set PLC CPU hot restart request"
    impact = "Triggers a hot restart of the CPU, restarting without losing memory."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "98fcadd492454e008f36e2b72cf24b9a"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.1.0"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "System Recovery and Reconstitution: Detects hot restart commands to restart CPU without losing memory."
  strings:
    $payload = { 28 00 00 00 00 00 00 fd 00 00 09 50 5f 50 52 4f }
  condition:
    $payload
}

rule Siemens_S7_Set_CPU_Cold_Restart : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Set PLC CPU cold restart request"
    impact = "Initiates a cold restart, resetting the CPU and clearing memory."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "708fe78b4c1646569024c422336673ac"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.1.0"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "System Recovery and Reconstitution: Detects cold restart commands to reset CPU and clear memory."
  strings:
    $payload = { 28 00 00 00 00 00 00 fd 00 02 43 20 09 50 5f 50 52 4f 47 52 41 4d }
  condition:
    $payload
}

rule Siemens_S7_Write_Var : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Write variable"
    impact = "Allows writing data to a variable in the PLC."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "893dfef82ca14a34a2bfffdcf7e5a425"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-5"
    control_description = "Access Restrictions for Change: Detects write variable operations to ensure proper data handling."
  strings:
    $header = { 03 00 }
    $payload = { 05 }
  condition:
    $header at 0 and $payload at 17
}

rule Siemens_S7_Request_Download : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Request download"
    impact = "Initiates the process of downloading data or a program to the PLC."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "fde3a73ca62e42bfaa69bf4b3614f5da"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects requests to download data or programs to PLC."
  strings:
    $header = { 03 00 }
    $payload = { 1a }
  condition:
    $header at 0 and $payload at 17
}

rule Siemens_S7_Download_Block : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Download block"
    impact = "Facilitates block-wise download of data or programs to the PLC."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "139a29d3f3ce48289bdc29a0178d6db5"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects block-wise download operations to PLC."
  strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1b }
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17
}

rule Siemens_S7_Download_Ended : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Download ended"
    impact = "Marks the completion of a block-wise data or program download to the PLC."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "69902ca843d842fe9492105fefe0e4ad"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects the end of block-wise download operations to PLC."
  strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1c }
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17
}

rule Siemens_S7_Start_Upload : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Start upload"
    impact = "Begins the process of uploading data or programs from the PLC."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "b8c3da7545394af4a22d41c792444a80"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects requests to start uploading data or programs from PLC."
  strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1d }
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17
}

rule Siemens_S7_Upload : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Upload"
    impact = "Allows block-wise upload of data or programs from the PLC."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "26aa3e919bb24d3eb8c71d9964acb897"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects block-wise upload operations from PLC."
  strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1e }
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17
}

rule Siemens_S7_End_Upload : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "End upload"
    impact = "Marks the completion of a block-wise upload of data or programs from the PLC."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "4bb4a2c740ed4cefa871bf64a89c31eb"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects the end of block-wise upload operations from PLC."
  strings:
    $header = { 03 00 }
    $payload1 = { 32 01 }
    $payload2 = { 1f }
  condition:
    $header at 0 and $payload1 at 7 and $payload2 at 17
}

rule Siemens_S7_Delete_Block : Siemens_S7
{
  meta:
    protocol = "SiemensS7"
    description = "Delete block"
    impact = "Allows the deletion of a data block or program from the PLC, potentially disrupting operations."
    author = "Jose Ramon Palanco <jpalanco@barbaraiot.com>"
    uid = "2dcef8a3655a44eb97424a41ece101c1"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    dst_port = "102"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects delete block operations to ensure proper data handling."
  strings:
    $header = { 03 00 }
    $payload = { 05 5f }
  condition:
    $header at 0 and $payload
}
