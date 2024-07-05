rule force_listen_only_mode : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Enables forced listen only mode"
    impact = "Places the device in listen only mode, preventing it from acting on commands"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.2"
    uuid = "1e0af54bf2fd4e75aa985608f3a0c361"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Prevents unauthorized remote access."
  strings: 
    $modbus_header = { 00 00 }
    $force_listen = { 08 00 04 }
  condition: 
    $modbus_header at 2 and $force_listen at 7
}

rule restart_communications_option : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Restarts communication options"
    impact = "Resets communication settings, potentially disrupting normal operations"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.2"
    uuid = "dadb0f5fb6144db981a06bd706646c80"
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-5"
    control_description = "Denial of Service Protection: Ensures system can manage and recover from communication disruptions."
  strings: 
    $modbus_header = { 00 00 }
    $restart = { 08 00 01 }
  condition: 
    $modbus_header at 2 and $restart at 7
}

rule clear_counters_and_diagnostic_registers : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Clears counters and diagnostic registers"
    impact = "Erases diagnostic data and counters, affecting system monitoring and diagnostics"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    uuid = "5bc4878a009942dd8fdefe9e91e24a70"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Ensures ongoing system monitoring for unauthorized changes."
  strings: 
    $modbus_header = { 00 00 }
    $clear_diag = { 08 00 0a }
  condition: 
    $modbus_header at 2 and $clear_diag at 7
}

rule slave_device_busy_exception_code_delay : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Induces busy exception code on slave devices"
    impact = "Signals that the slave device is busy, potentially delaying response to legitimate commands"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.4.0"
    uuid = "9adde64659e24456badb74be64d315ce"
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-15"
    control_description = "Collaborative Computing Devices: Ensures devices can manage and recover from busy states."
  strings: 
    $modbus_header = { 00 00 }
    $busy = { 06 }
    $payload = { 80 }
  condition: 
    $modbus_header at 2 and $busy at 8 and $payload at 7
}

rule ack_exception_code_delay : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Acknowledges exception code with a delay"
    impact = "Delays the acknowledgment of exception codes, affecting error handling procedures"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.4.0"
    uuid = "52cf133f7ec543388d6a90bdc2a219fe"
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-24"
    control_description = "Timeouts: Ensures appropriate handling of delayed responses and timeouts."
  strings: 
    $modbus_header = { 00 00 }
    $ack = { 05 }
    $payload = { 80 }
  condition: 
    $modbus_header at 2 and $ack at 8 and $payload at 7
}

rule points_list_scan : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Scans points list"
    impact = "Retrieves a list of points from the device, which may disclose operational details"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.1.0"
    uuid = "51325c4b7a35415dbfa77360b031a451"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Ensures monitoring for unauthorized data retrieval attempts."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 80 }
    $points_list = { 02 }
  condition: 
    $modbus_header at 2 and $payload at 7 and $points_list at 8
}

rule function_code : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Handles specific function codes"
    impact = "Executes commands based on the function code received, impacting device operations"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.1.0"
    uuid = "1a09d6f501004b168e3b85ff46fac53b"
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-24"
    control_description = "Timeouts: Ensures proper handling and execution of function codes."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 80 }
    $points_list = { 01 }
  condition: 
    $modbus_header at 2 and $payload at 7 and $points_list at 8
}

rule Modbus_TCP_Write_single_coil : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Writes to a single coil via Modbus TCP"
    impact = "Modifies the state of a single coil, potentially affecting device behavior"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.3"
    uuid = "a6be02ca588341fa9318ca8330c0f9f8"
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-7"
    control_description = "Boundary Protection: Ensures changes to single components do not impact overall system integrity."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 05 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Write_single_register : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Writes to a single register via Modbus TCP"
    impact = "Alters the value of a single register, which could change device operations or settings"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "experimental"
    ruleVersion = "v1.2.3"
    uuid = "04904d0e255e436d8519fa2b1dcbf7bb"
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-7"
    control_description = "Boundary Protection: Ensures changes to single components do not impact overall system integrity."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 06 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Read_Exception_Status : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Reads the exception status via Modbus TCP"
    impact = "Checks the exception status of the device, used for diagnostics and error analysis"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "experimental"
    ruleVersion = "v1.2.1"
    uuid = "4a81b3de62d74600b557cf17e28345d5"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Ensures ongoing monitoring of exception statuses."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 07 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Diagnostics_Device : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Performs device diagnostics via Modbus TCP"
    impact = "Executes diagnostic commands that could interrupt normal device operation or reveal sensitive information"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.1"
    uuid = "cdba7682c5404eb7b4f2077252752ab9"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Ensures ongoing system diagnostics and monitoring."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 08 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Write_Multiple_Coils : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Writes to multiple coils via Modbus TCP"
    impact = "Modifies multiple coil states, affecting multiple aspects of device operation"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.1"
    uuid = "be6d7d1694e44deeae195bee99011ce5"
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-7"
    control_description = "Boundary Protection: Ensures coordinated changes to multiple components maintain system integrity."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 0f }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Write_Multiple_registers : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Writes to multiple registers via Modbus TCP"
    impact = "Changes settings across multiple registers, potentially leading to significant changes in device behavior"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.1"
    uuid = "7ffea98b5f0e45448c4e8e3f5e7d371d"
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-7"
    control_description = "Boundary Protection: Ensures coordinated changes to multiple components maintain system integrity."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 10 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Write_File_Record : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Writes a file record via Modbus TCP"
    impact = "Stores data to the device's file system, potentially overwriting existing files or data"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.4.1"
    uuid = "3a32a1948c8b49398b36f4b0b549ec3b"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Ensures integrity of file records."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 15 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Write_Register : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Masks and writes to a register via Modbus TCP"
    impact = "Manipulates register values with a mask before writing, allowing for precise control over register contents"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.5"
    uuid = "0e87e4a32de44013ba73df5f8ed268fa"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Ensures integrity of register data."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 16 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Read_Write_Multiple_Registers : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Reads and writes multiple registers via Modbus TCP"
    impact = "Performs both reading and writing operations on multiple registers, influencing device processes and settings"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.4.5"
    uuid = "129082bb1a3f48fab882df6e30cd519f"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Ensures integrity of read/write operations."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 17 }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule Modbus_TCP_Read_Device_Identification : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Reads device identification via Modbus TCP"
    impact = "Obtains device identification information, useful for asset management and network mapping"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.0"
    uuid = "e68410aee14244a985f372b88769bd2e"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-8"
    control_description = "Information System Component Inventory: Ensures inventory of device identifications."
  strings: 
    $modbus_header = { 00 00 }
    $payload = { 2B }
  condition: 
    $modbus_header at 2 and $payload at 7 
}

rule unauthorized_read_request_plc : modbus 
{
  meta:
    protocol = "MODBUS"
    author = "Jose Ramon Palanco <jose.palanco@puffinsecurity.com>"
    description = "Unauthorized read request to a PLC"
    impact = "Attempts to read from a PLC without authorization, potentially exposing sensitive operational data"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "experimental"
    ruleVersion = "v1.2.4"
    uuid = "032d4d272ced432b804beb6dfeca98d1"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Ensures unauthorized access attempts are detected and controlled."
  strings: 
    $modbus_header = { 00 00 }
    $unauth_read_plc = /[\S\s]{3}(\x01|\x02|\x03|\x04|\x07|\x0B|\x0C|\x11|\x14|\x17|\x18|\x2B)/
  condition: 
    $modbus_header at 2 and $unauth_read_plc at 3
}
