rule ascii_device_write_in_bits : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing bits to a device using ASCII format."
    impact = "Allows direct bit manipulation of device memory, potentially altering device operation."
    uuid = "cd9da45486274f7980fe63ad6213e3a2"
    lastUpdate = "2023-02-06T11:15:00+0100"
    status = "stable"
    ruleVersion = "v1.2.0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects ASCII format bit writing operations."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 31 30 30 ?? 31}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_in_bits : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing bits to a device using binary format."
    impact = "Allows direct bit manipulation of device memory, potentially altering device operation."
    uuid = "fcee1e46161e4730b69ab24599cb0dd7"
    lastUpdate = "2023-02-06T11:15:00+0100"
    status = "stable"
    ruleVersion = "v1.2.0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects binary format bit writing operations."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 14 ?1 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_device_write_in_word : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing words to a device using ASCII format."
    impact = "Enables modification of device memory at the word level, influencing device operations."
    uuid = "38bd9a1d253647dc94b8ca7d768ed07b"
    lastUpdate = "2023-02-06T11:17:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects ASCII format word writing operations."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 31 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_in_word : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing words to a device using binary format."
    impact = "Enables modification of device memory at the word level, influencing device operations."
    uuid = "224acbcdd76d43c796cb0371979edfd6"
    lastUpdate = "2023-02-06T11:17:00+0100"
    status = "stable"
    ruleVersion = "v1.2.5"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects binary format word writing operations."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_device_write_random_in_bits : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Randomly writing bits to a device using ASCII format."
    impact = "Allows random bit manipulation in device memory, potentially causing unpredictable device behavior."
    uuid = "afc345357ce145c3974f32b12d99d2e1"
    lastUpdate = "2023-02-06T11:20:00+0100"
    status = "stable"
    ruleVersion = "v1.3.0"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detects random bit writing operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 32 30 30 ?? 31}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_random_in_bits : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Randomly writing bits to a device using binary format."
    impact = "Allows random bit manipulation in device memory, potentially causing unpredictable device behavior."
    uuid = "984a0abfdc334ac9a01acb0cdc440fc7"
    lastUpdate = "2023-02-06T11:20:00+0100"
    status = "stable"
    ruleVersion = "v1.3.0"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detects random bit writing operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 14 ?1 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_device_write_random_in_word : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Randomly writing words to a device using ASCII format."
    impact = "Enables random word-level modifications in device memory, affecting device functionality unpredictably."
    uuid = "331c1bb9857446f1bc17aa697cd3f73a"
    lastUpdate = "2023-02-06T11:22:00+0100"
    status = "stable"
    ruleVersion = "v1.3.3"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detects random word writing operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 32 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_random_in_word : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Randomly writing words to a device using binary format."
    impact = "Enables random word-level modifications in device memory, affecting device functionality unpredictably."
    uuid = "99c055c3b3074614ba9379c8dca0448e"
    lastUpdate = "2023-02-06T11:22:00+0100"
    status = "stable"
    ruleVersion = "v1.3.3"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detects random word writing operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_device_write_block : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing blocks to a device using ASCII format."
    impact = "Facilitates block-level data writing, impacting device storage and program execution."
    uuid = "9c1b08d80d4b4253a656920afb575603"
    lastUpdate = "2023-02-06T11:25:00+0100"
    status = "stable"
    ruleVersion = "v1.4.0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects block writing operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 36 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_device_write_block : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing blocks to a device using binary format."
    impact = "Facilitates block-level data writing, impacting device storage and program execution."
    uuid = "bcf0f846f690461483c89a92ab533f3d"
    lastUpdate = "2023-02-06T11:25:00+0100"
    status = "stable"
    ruleVersion = "v1.4.0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects block writing operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_extend_unit_write : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing to an extended unit using ASCII format."
    impact = "Enables writing to additional storage or processing units, potentially expanding system capabilities."
    uuid = "d186845e7bcf455ca818fc736d122e90"
    lastUpdate = "2023-02-06T11:30:00+0100"
    status = "stable"
    ruleVersion = "v1.4.3"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects writing operations to extended units in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 30 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_extend_unit_write : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing to an extended unit using binary format."
    impact = "Enables writing to additional storage or processing units, potentially expanding system capabilities."
    uuid = "f018e893d65b4544b65b59bf106ad8f4"
    lastUpdate = "2023-02-06T11:30:00+0100"
    status = "stable"
    ruleVersion = "v1.4.3"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects writing operations to extended units in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_memory_write : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing to memory using ASCII format."
    impact = "Directly modifies system memory, potentially altering program execution or data integrity."
    uuid = "a0c5e30fbd7d4fcda42f35b60b7fc353"
    lastUpdate = "2023-02-06T11:35:00+0100"
    status = "stable"
    ruleVersion = "v1.4.5"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detects memory writing operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 31 33 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_memory_write : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing to memory using binary format."
    impact = "Directly modifies system memory, potentially altering program execution or data integrity."
    uuid = "9049bbaa447643e88ebb9207599ec85e"
    lastUpdate = "2023-02-06T11:35:00+0100"
    status = "stable"
    ruleVersion = "v1.4.5"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detects memory writing operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {13 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_run : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote run commands using ASCII format."
    impact = "Triggers execution of remote operations, potentially starting processes or tasks on a device."
    uuid = "0d0ee30b6b1f444f80d7d4012e418c24"
    lastUpdate = "2023-02-06T11:40:00+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote run command initiation in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_run : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote run commands using binary format."
    impact = "Triggers execution of remote operations, potentially starting processes or tasks on a device."
    uuid = "afe7e83e5619465b9b713106979e6682"
    lastUpdate = "2023-02-06T11:40:00+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote run command initiation in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_stop : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote stop commands using ASCII format."
    impact = "Allows remote halting of device operations, potentially stopping processes or tasks."
    uuid = "905fb096a8ef40788c03d7bf86561fde"
    lastUpdate = "2023-02-06T11:45:00+0100"
    status = "stable"
    ruleVersion = "v1.4.9"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote stop command initiation in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 32 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_stop : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote stop commands using binary format."
    impact = "Allows remote halting of device operations, potentially stopping processes or tasks."
    uuid = "b0cec95dd2ff4cb98daf7bc5082dd85d"
    lastUpdate = "2023-02-06T11:45:00+0100"
    status = "stable"
    ruleVersion = "v1.4.9"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote stop command initiation in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_pause : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote pause commands using ASCII format."
    impact = "Enables temporary suspension of device activities, potentially pausing ongoing processes."
    uuid = "50c656b4d4c74978b4da0663c147a7e8"
    lastUpdate = "2023-02-06T11:50:00+0100"
    status = "stable"
    ruleVersion = "v1.4.9"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote pause command initiation in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 33 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_pause : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote pause commands using binary format."
    impact = "Enables temporary suspension of device activities, potentially pausing ongoing processes."
    uuid = "02910ee7c6af43758cd5187c0f8ee826"
    lastUpdate = "2023-02-06T11:50:00+0100"
    status = "stable"
    ruleVersion = "v1.4.9"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote pause command initiation in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {03 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_latch : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote latch commands using ASCII format."
    impact = "Triggers the latching mechanism in devices, potentially locking their current state or configuration."
    uuid = "191aa7393e29480fbc746b7b45892d48"
    lastUpdate = "2023-02-06T11:55:00+0100"
    status = "stable"
    ruleVersion = "v1.4.9"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote latch command initiation in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_latch : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote latch commands using binary format."
    impact = "Triggers the latching mechanism in devices, potentially locking their current state or configuration."
    uuid = "8ed3c75f75164094b3085462fb96b645"
    lastUpdate = "2023-02-06T11:55:00+0100"
    status = "stable"
    ruleVersion = "v1.4.9"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote latch command initiation in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {05 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_reset : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote reset commands using ASCII format."
    impact = "Allows resetting of device to initial or default settings, potentially clearing current configurations."
    uuid = "574136bc4117411d9e700b03e3f8ae08"
    lastUpdate = "2023-02-06T12:00:00+0100"
    status = "stable"
    ruleVersion = "v1.5.0"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote reset command initiation in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_reset : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Initiating remote reset commands using binary format."
    impact = "Allows resetting of device to initial or default settings, potentially clearing current configurations."
    uuid = "c3563353fe5646da9e4e7330634e3ff8"
    lastUpdate = "2023-02-06T12:00:00+0100"
    status = "stable"
    ruleVersion = "v1.5.0"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-3"
    control_description = "Access Enforcement: Detects remote reset command initiation in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_change_file_date : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Changing file date using ASCII format."
    impact = "Modifies file metadata, specifically the date, which can affect file system organization and data retrieval."
    uuid = "fcb0b9dd25044e0ebb5adf26f471dd46"
    lastUpdate = "2023-02-06T12:05:00+0100"
    status = "stable"
    ruleVersion = "v1.1.0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file date change operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_change_file_date : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Changing file date using binary format."
    impact = "Modifies file metadata, specifically the date, which can affect file system organization and data retrieval."
    uuid = "0a179d6b85344cd5b96825c8dd8d12f9"
    lastUpdate = "2023-02-06T12:05:00+0100"
    status = "stable"
    ruleVersion = "v1.1.0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file date change operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {26 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_write_file : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing to a file using ASCII format."
    impact = "Writes data to files, potentially modifying content and affecting data integrity and system behavior."
    uuid = "0671fd1e64614043b74575c548cfd753"
    lastUpdate = "2023-02-06T12:10:00+0100"
    status = "stable"
    ruleVersion = "v1.1.5"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file writing operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 39 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_write_file : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Writing to a file using binary format."
    impact = "Writes data to files, potentially modifying content and affecting data integrity and system behavior."
    uuid = "59db5373411c4d5d99f7a4cadcfaa252"
    lastUpdate = "2023-02-06T12:10:00+0100"
    status = "stable"
    ruleVersion = "v1.1.5"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file writing operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {29 18 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_copy_file : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Copying a file using ASCII format."
    impact = "Duplicates file data, affecting disk usage and data management."
    uuid = "f502029b7706466c84c52649d59b19b4"
    lastUpdate = "2023-02-06T12:15:00+0100"
    status = "stable"
    ruleVersion = "v1.2.3"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file copy operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 34 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_copy_file : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Copying a file using binary format."
    impact = "Duplicates file data, affecting disk usage and data management."
    uuid = "c683adab1cf84f209c778a147cdc5b25"
    lastUpdate = "2023-02-06T12:15:00+0100"
    status = "stable"
    ruleVersion = "v1.2.3"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file copy operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {24 18 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_delete_file : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Deleting a file using ASCII format."
    impact = "Removes files, potentially affecting data availability."
    uuid = "f5980e41e9d349c3a1640e9a7f685646"
    lastUpdate = "2023-02-06T12:20:00+0100"
    status = "stable"
    ruleVersion = "v1.3.0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file deletion operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 32 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_delete_file : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Deleting a file using binary format."
    impact = "Removes files, potentially affecting data availability."
    uuid = "fa70af0ce26543318481a51b3697326c"
    lastUpdate = "2023-02-06T12:20:00+0100"
    status = "stable"
    ruleVersion = "v1.3.0"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file deletion operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {22 18 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_change_file_state : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Changing file state using ASCII format."
    impact = "Alters file properties, which can influence how the file is accessed or managed."
    uuid = "4fae6b15fb5648df9ec9ad427f91572f"
    lastUpdate = "2023-02-06T12:25:00+0100"
    status = "stable"
    ruleVersion = "v1.3.5"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file state change operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_change_file_state : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Changing file state using binary format."
    impact = "Alters file properties, which can influence how the file is accessed or managed."
    uuid = "05ebe1d21b5a4551aea3cce060f38917"
    lastUpdate = "2023-02-06T12:25:00+0100"
    status = "stable"
    ruleVersion = "v1.3.5"
    standard = "NIST SP 800-82"
    category = "CM"
    category_name = "Configuration Management"
    control = "CM-4"
    control_description = "Monitoring Configuration Changes: Detects file state change operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {25 18 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule ascii_remote_password_unlock : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Remote password unlock using ASCII format."
    impact = "Enables access to secured areas of the system, potentially compromising security settings."
    uuid = "af0a7be363a1416b830cfa1d91c5a865"
    lastUpdate = "2023-02-06T12:30:00+0100"
    status = "stable"
    ruleVersion = "v1.3.7"
    standard = "NIST SP 800-82"
    category = "IA"
    category_name = "Identification and Authentication"
    control = "IA-2"
    control_description = "Identification and Authentication (Organizational Users): Detects remote password unlock operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 33 30 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_password_unlock : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Remote password unlock using binary format."
    impact = "Enables access to secured areas of the system, potentially compromising security settings."
    uuid = "d442a4433c7543fe88d9127c1cd4c229"
    lastUpdate = "2023-02-06T12:30:00+0100"
    status = "stable"
    ruleVersion = "v1.3.7"
    standard = "NIST SP 800-82"
    category = "IA"
    category_name = "Identification and Authentication"
    control = "IA-2"
    control_description = "Identification and Authentication (Organizational Users): Detects remote password unlock operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {30 16 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}


rule ascii_remote_password_lock : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Remote password lock using ASCII format."
    impact = "If an adversary locked the system, it might prevent legitimate users from accessing it."
    uuid = "36be35b2630147e890a5e234c3e90527"
    lastUpdate = "2023-02-06T12:35:00+0100"
    status = "stable"
    ruleVersion = "v1.3.9"
    standard = "NIST SP 800-82"
    category = "IA"
    category_name = "Identification and Authentication"
    control = "IA-2"
    control_description = "Identification and Authentication (Organizational Users): Detects remote password lock operations in ASCII format."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 33 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule binary_remote_password_lock : SLMP 
{
  meta:
    protocol = "SLMP"
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Remote password lock using binary format."
    impact = "If an adversary locked the system, it might prevent legitimate users from accessing it."
    uuid = "ba91f4030e904001bb179c9a6eb717ba"
    lastUpdate = "2023-02-06T12:35:00+0100"
    status = "stable"
    ruleVersion = "v1.3.9"
    standard = "NIST SP 800-82"
    category = "IA"
    category_name = "Identification and Authentication"
    control = "IA-2"
    control_description = "Identification and Authentication (Organizational Users): Detects remote password lock operations in binary format."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {31 16 00 00}
  condition:
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}
