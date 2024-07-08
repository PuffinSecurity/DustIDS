rule memory_area_write : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "FINS command to write to a memory area."
    impact = "Writes data to the specified memory area, potentially altering device operation."
    uuid = "8c059aa02b3c4941a06e8b620609cd99"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 01 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule stop_command : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "FINS stop command."
    impact = "Stops the device operation, potentially halting critical processes."
    uuid = "a3ed5327ecfe43d780637caaa9ac1415"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 04 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule invalid_command_area_clear : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.1"
    description = "FINS invalid command: clear program area."
    impact = "Clears the program area, potentially removing important configurations or programs."
    uuid = "da35140cc2534fe38106dd7549715548"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 08 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule force_right_acquire : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.2"
    description = "FINS command to acquire access rights forcefully."
    impact = "Forcefully acquires access rights, potentially disrupting normal access control mechanisms."
    uuid = "08131f969740423fb12906ddd6a0cb22"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Enforce approved authorizations for logical access to the system in accordance with applicable policy."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 0C 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule error_clear : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "FINS error clear command."
    impact = "Clears error logs or statuses, potentially hiding issues."
    uuid = "779adefb398245588973dc2afc04f36a"
    standard = "NIST SP 800-82"
    category = "AU"
    category_name = "Audit and Accountability"
    control = "AU-12"
    control_description = "Audit Record Generation: Create audit records containing sufficient information to establish what events occurred, the sources of the events, and the outcomes of the events."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 21 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule force_reset : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.1"
    description = "FINS forced set/reset command."
    impact = "Forces the device to reset, potentially causing temporary disruption."
    uuid = "66c35fc338bf4ab3a73aebe5b0bd705a"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 23 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule memory_area_fill : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.2"
    description = "FINS command to fill memory area."
    impact = "Fills a specified memory area with data, potentially overwriting existing data."
    uuid = "9a968a6364ee439ab535b3cd84f87ad4"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 01 03 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule memory_area_transfer : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.3"
    description = "FINS command to transfer memory area."
    impact = "Transfers data between memory areas, potentially moving critical data."
    uuid = "a4ed2d6ed7d947579bf63acc4c493583"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 01 05 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule parameter_area_write : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.4"
    description = "FINS command to write to parameter area."
    impact = "Writes data to the parameter area, potentially changing device settings."
    uuid = "0b99c903454e43308d10a6036766a82c"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 02 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule parameter_area_clear : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.5"
    description = "FINS command to clear parameter area."
    impact = "Clears the parameter area, potentially resetting device settings."
    uuid = "fd23dc96678847a1ae4beb82460cf06d"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 02 03 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule program_area_protect : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.6"
    description = "FINS command to protect program area."
    impact = "Protects the program area, potentially preventing unauthorized changes."
    uuid = "98ed78a06c1d4420a471acd90b58c421"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 04 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule program_area_protect_clear : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.7"
    description = "FINS command to clear program area protection."
    impact = "Clears the protection of the program area, potentially allowing unauthorized changes."
    uuid = "5badd0c4b89e4c0492dd04cc5a6adf36"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 05 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule program_area_write : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.8"
    description = "FINS command to write to program area."
    impact = "Writes data to the program area, potentially modifying the program logic."
    uuid = "4c70bfcdb3ce4669bbf90a771c97d140"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 07 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule program_area_clear : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.9"
    description = "FINS command to clear program area."
    impact = "Clears the program area, potentially deleting critical program logic."
    uuid = "b782253da1ef4239b7cf62a45c2a81dc"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 03 08 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule error_log_clear : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.0"
    description = "FINS command to clear error log."
    impact = "Clears the error log, potentially hiding previous errors."
    uuid = "62bacca4ad8548d8bc89259f95e2b13d"
    standard = "NIST SP 800-82"
    category = "AU"
    category_name = "Audit and Accountability"
    control = "AU-12"
    control_description = "Audit Record Generation: Create audit records containing sufficient information to establish what events occurred, the sources of the events, and the outcomes of the events."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 21 03 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule clock_write : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.1"
    description = "FINS command to write to the clock."
    impact = "Writes the system clock, potentially affecting time-sensitive operations."
    uuid = "9cdd7b10989645479170fcdab35bc21c"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 07 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule run : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.2"
    description = "FINS run command."
    impact = "Starts the device operation, potentially resuming critical processes."
    uuid = "35b53b3722784b7288e38156f11094ce"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 04 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule forced_set_reset_cancel : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.3"
    description = "FINS command to cancel forced set/reset."
    impact = "Cancels a forced set or reset, potentially restoring normal operations."
    uuid = "ab8ed6c3926048d6901127cc71af12ed"
    standard = "NIST SP 800-82"
    category = "CP"
    category_name = "Contingency Planning"
    control = "CP-10"
    control_description = "Information System Recovery and Reconstitution: Employ mechanisms to ensure information system recovery and reconstitution to a known secure state after a disruption or failure."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 23 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule data_link_table_write : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.4"
    description = "FINS command to write to data link table."
    impact = "Writes data to the link table, potentially altering network communication paths."
    uuid = "10725d7ff6a646aab9be933a0ca6e641"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 02 21 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule name_delete : FINS 
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.5"
    description = "FINS command to delete a name."
    impact = "Deletes a name or label, potentially removing identifiers."
    uuid = "f2d69d2b455f4870b7284352a6ad610b"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 26 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_single_file_write_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.6"
    description = "FINS command to write a single file."
    impact = "Writes a file to the device, potentially altering its data."
    uuid = "6950d45a9f8548e1852e8aac5e929b27"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 03 ?? ?? 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_single_file_write_with_overwrite_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.7"
    description = "FINS command to write a single file with overwrite."
    impact = "Writes a file to the device with overwrite option, potentially replacing existing data."
    uuid = "70959b1b15c74b87bd3ef2f9256b40c7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 03 ?? ?? 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_single_file_append_data_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.8"
    description = "FINS command to append data to a file."
    impact = "Appends data to an existing file on the device, potentially expanding its size."
    uuid = "50c51b97bf6a49a18ed385091a5b2bf7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 03 ?? ?? 00 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_single_file_overwrite_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.1.9"
    description = "FINS command to overwrite a file."
    impact = "Overwrites an existing file on the device, potentially replacing its contents."
    uuid = "d62a8075ed73465aa2459f726dac7642"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 03 ?? ?? 00 03 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_memory_card_format_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.0"
    description = "FINS command to format memory card."
    impact = "Formats the memory card, potentially erasing all its contents."
    uuid = "e801f112f1324772a299fe56ff10ebdf"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 04 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_file_delete_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.1"
    description = "FINS command to delete a file."
    impact = "Deletes a file from the device, potentially removing critical data."
    uuid = "7135c39bf7b64180ab187afc231d37cc"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Protect the integrity of software, firmware, and information."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 05 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_volume_label_create_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.2"
    description = "FINS command to create a volume label."
    impact = "Creates a volume label on the device, potentially aiding in identification."
    uuid = "c2e491386ccc42af97d1e801413c7a85"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 06 ?? ?? 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_volume_label_create_or_overwrite_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.3"
    description = "FINS command to create or overwrite a volume label."
    impact = "Creates or overwrites a volume label on the device, potentially replacing existing labels."
    uuid = "87ce011245444c5bb41fdf1084ad19fa"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 06 ?? ?? 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_volume_label_delete_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.4"
    description = "FINS command to delete a volume label."
    impact = "Deletes a volume label from the device, potentially removing identifiers."
    uuid = "0d2340a62d33417193ccb6a35a7c5349"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 06 ?? ?? 00 02 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_file_copy_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.5"
    description = "FINS command to copy a file."
    impact = "Copies a file within the device, potentially duplicating data."
    uuid = "ce73a402ac224f1b8979a71804ba387a"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 07 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_file_name_change_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.2.6"
    description = "FINS command to change a file name."
    impact = "Changes the name of a file on the device, potentially altering its identification."
    uuid = "e2ee250284a844ab85b269f9e17daa2e"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 08 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_memory_area_file_transfer_pc_to_device_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.0"
    description = "FINS command to transfer memory area file from PC to device."
    impact = "Transfers a file from the PC to the device's memory area, potentially altering its data."
    uuid = "ba35eaab08bf435ba9595afe9a2dc7f5"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0A 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_memory_area_file_transfer_device_to_pc_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.1"
    description = "FINS command to transfer memory area file from device to PC."
    impact = "Transfers a file from the device's memory area to the PC, potentially exposing its data."
    uuid = "844de1d3359940f595daf59d9e56ec13"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0A 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_parameter_area_file_transfer_pc_to_device_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.2"
    description = "FINS command to transfer parameter area file from PC to device."
    impact = "Transfers a file from the PC to the device's parameter area, potentially altering its settings."
    uuid = "041badf6b7604e7689255d8e065a8222"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0B 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_parameter_area_file_transfer_device_to_pc_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.3"
    description = "FINS command to transfer parameter area file from device to PC."
    impact = "Transfers a file from the device's parameter area to the PC, potentially exposing its settings."
    uuid = "85dcd601dc654068852630d0805d5dc0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0B 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_program_area_file_transfer_pc_to_device_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.4"
    description = "FINS command to transfer program area file from PC to device."
    impact = "Transfers a file from the PC to the device's program area, potentially altering its program logic."
    uuid = "7bf594c5147b4aa7890696139775751d"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings: 
    $fins_header = { 00 02 }
    $fins_command = { 22 0C 00 00 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}

rule fins_program_area_file_transfer_device_to_pc_binary_v180316 : FINS
{
  meta:
    protocol = "FINS"
    manufacturer = "Omron"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "1.3.5"
    description = "FINS command to transfer program area file from device to PC."
    impact = "Transfers a file from the device's program area to the PC, potentially exposing its program logic."
    uuid = "674e355f549d44de94779a6e11521b7b"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-6"
    control_description = "Configuration Settings: Establish and maintain baseline configurations and ensure changes to the configuration are monitored and controlled."
  strings:
    $fins_header = { 00 02 }
    $fins_command = { 22 0C 00 01 }
  condition: 
    $fins_header at 1 and $fins_command at 10
}
