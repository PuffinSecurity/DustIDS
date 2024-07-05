rule unavaliability : MTCONNECT
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

