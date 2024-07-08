rule unavailability : MTCONNECT
{
  meta:
    protocol = "MTConnect"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    uuid = "a0a0a53ea3b540f6ba17751c007c52fb"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.0"
    description = "Adapter unavailable."
    impact = "Detects when an adapter becomes unavailable in SCADA systems, affecting device communication."
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-7"
    control_description = "Boundary Protection: Detects unavailability of components to maintain system integrity."
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "UNAVAILABLE</Availability>"
  condition:
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule armed_emergency_stop : MTCONNECT
{
  meta:
    protocol = "MTConnect"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    uuid = "86e6519170924b118c78b75a34bb4aa6"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.0"
    description = "Emergency stop activated."
    impact = "Detects activation of emergency stops, indicating a potential safety or security issue in SCADA environments."
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Detects activation of emergency stops to ensure safety and integrity."
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "ARMED</EmergencyStop>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule triggered_emergency_stop : MTCONNECT
{
  meta:
    protocol = "MTConnect"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    uuid = "86e6519170924b118c78b75a34bb4aa6"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.3.0"
    description = "Emergency stop ended."
    impact = "Monitors the cessation of emergency stops, potentially indicating the resolution of earlier detected safety or security issues."
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Detects cessation of emergency stops to ensure continued safety and integrity."
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "TRIGGERED</EmergencyStop>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule interface_state : MTCONNECT
{
  meta:
    protocol = "MTConnect"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    uuid = "9d51215f72444b8db9c698e3b9202453"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    description = "Interface state disabled."
    impact = "Identifies when a device interface is disabled, potentially impacting operational control and monitoring."
    standard = "NIST SP 800-82"
    category = "SC"
    category_name = "System and Communications Protection"
    control = "SC-7"
    control_description = "Boundary Protection: Detects disabled interfaces to ensure continued protection and integrity."
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "DISABLED</InterfaceState>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule power_state_off : MTCONNECT
{
  meta:
    protocol = "MTConnect"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    uuid = "f7ecc7d8660e4ebba7630be19cffab0f"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    description = "Adapter power is off."
    impact = "Detects when an adapter is powered off, potentially indicating a shutdown or power failure in SCADA systems."
    standard = "NIST SP 800-82"
    category = "PE"
    category_name = "Physical and Environmental Protection"
    control = "PE-11"
    control_description = "Emergency Power Off: Ensures detection of power-off states to maintain system availability."
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "OFF</PowerState>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule program_edit_active : MTCONNECT
{
  meta:
    protocol = "MTConnect"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    uuid = "b7950c6128784cd9a37d93ab00c91a2b"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    description = "Controller in program edit mode."
    impact = "Detects when a controller is in program edit mode, allowing modifications to operational programming which might affect SCADA operations."
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-5"
    control_description = "Access Restrictions for Change: Ensures that program edits are monitored to prevent unauthorized changes."
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "ACTIVE</ProgramEdit>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule development_functional_mode : MTCONNECT
{
  meta:
    protocol = "MTConnect"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    uuid = "c9e8a7c6a018423ca29cdac13afbf36b"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.0"
    description = "Functional mode set to development."
    impact = "Identifies when a device is set to development mode, potentially indicating changes in operational settings or testing phases."
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Security Impact Analysis: Detects development mode to assess security impacts of configuration changes."
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "PROCESS_DEVELOPMENT</FunctionalMode>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}

rule maintenance_functional_mode : MTCONNECT
{
  meta:
    protocol = "MTConnect"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    uuid = "26159ec625064a1681a30cd6c8130ef0"
    lastUpdate = "2023-02-06T12:11:00+0100"
    status = "stable"
    ruleVersion = "v1.2.0"
    description = "Functional mode set to maintenance."
    impact = "Detects when a device is set to maintenance mode, possibly indicating ongoing or scheduled maintenance activities."
    standard = "NIST SP 800-82"
    category = "MA"
    category_name = "Maintenance"
    control = "MA-3"
    control_description = "Maintenance Tools: Detects maintenance mode to ensure proper use of maintenance tools and protocols."
  strings:
    $http_header = "HTTP"
    $xml_schema_loc = "urn:mtconnect.org:MTConnectStreams"
    $xml_devicestream_tag = "<DeviceStream"
    $xml_componentstreams_tag = "<ComponentStreams"
    $xml_events_tag = "<Events>"
    $xml_state_tag = "MAINTENANCE</FunctionalMode>"
  condition: 
    $http_header at 0 and $xml_schema_loc and $xml_devicestream_tag and $xml_componentstreams_tag and $xml_events_tag and $xml_state_tag 
}
