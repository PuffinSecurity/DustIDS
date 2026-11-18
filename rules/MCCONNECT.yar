rule mcconnect_ascii_batch_write_in_bits : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII message batch writing in bits."
    impact = "Alters SCADA device operation by modifying bit values."
    uuid = "d29ccbd54606453da742a7a45dafe926"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 31 30 30 ?? 31}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_batch_write_in_bits : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary message batch writing in bits."
    impact = "Alters SCADA device operation by modifying bit values."
    uuid = "2d4dd0b945094ae1aae812f031fe03fc"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 14 ?1 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_batch_write_in_word : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII message batch writing in word."
    impact = "Alters SCADA device operation by modifying word values."
    uuid = "2d4dd0b945094ae1aae812f031fe03fc"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 31 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_batch_write_in_word : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary message batch writing in word."
    impact = "Alters SCADA device operation by modifying word values."
    uuid = "c895edc996264e4985fb6d7d8d26d18b"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_write_random_in_bits_test : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII message for random bit writing in devices."
    impact = "Alters SCADA device operation by randomly modifying bit values."
    uuid = "abb8992acb62432ca57867d595664c45"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 32 30 30 ?? 31}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_write_random_in_bits_test : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary message for random bit writing in devices."
    impact = "Alters SCADA device operation by randomly modifying bit values."
    uuid = "f041f868fdd8488ab49023dd1290ee79"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 14 ?1 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_write_random_in_word_test : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII message for random word writing in devices."
    impact = "Alters SCADA device operation by randomly modifying word values."
    uuid = "fac13362065d4b8bb62b01f0315eaeae"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 32 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_write_random_in_word_test : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary message for random word writing in devices."
    impact = "Alters SCADA device operation by randomly modifying word values."
    uuid = "66acb91f9bd64bc6ba8cf0432ae1aa0c"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_multiple_block_batch_write : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII message for multiple block batch writing."
    impact = "Impacts SCADA systems by writing across multiple blocks."
    uuid = "b6a5561b0c894ca19f2d0845138beea9"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 34 30 36 30 30 ?? 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_multiple_block_batch_write : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary message for multiple block batch writing."
    impact = "Impacts SCADA systems by writing across multiple blocks."
    uuid = "0bf495d38aff44c1972e2a80c56c572c"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 14 ?0 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_inteligent_function_buffer_memory_write : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII message for intelligent buffer memory writing."
    impact = "Enables advanced data handling and storage functions in SCADA systems."
    uuid = "cafb59470b19421d992df63d113f796a"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 30 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_inteligent_function_buffer_memory_write : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary message for intelligent buffer memory writing."
    impact = "Enables advanced data handling and storage functions in SCADA systems."
    uuid = "96797179a2a646d1a8ad41c682d07f87"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_buffer_memory_write : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII message for buffer memory writing."
    impact = "Influences memory operations, impacting device processing and storage."
    uuid = "88574ecb5ccf4bcc92f55e58e6b57c47"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 31 33 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_buffer_memory_write : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary message for buffer memory writing."
    impact = "Influences memory operations, impacting device processing and storage."
    uuid = "4cfd5f4319f2450ead1051ee7be96731"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {13 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_remote_run : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to remotely run processes."
    impact = "Initiates operations remotely, potentially starting production cycles or tests."
    uuid = "676538f35d6844cd8f595c4dc0161c2a"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Enforces security controls on remote access to ensure proper authorization and protection against unauthorized actions."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_remote_run : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to remotely run processes."
    impact = "Initiates operations remotely, potentially starting production cycles or tests."
    uuid = "ef24d68289194afabcd1b8915fb40b37"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Enforces security controls on remote access to ensure proper authorization and protection against unauthorized actions."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {01 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_remote_stop : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to remotely stop processes."
    impact = "Allows for the emergency or scheduled stopping of operations remotely."
    uuid = "75ade8c997014006989a2178efd9249e"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Enforces security controls on remote access to ensure proper authorization and protection against unauthorized actions."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 32 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_remote_stop : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to remotely stop processes."
    impact = "Allows for the emergency or scheduled stopping of operations remotely."
    uuid = "2bf24b0fdef746e4ae7b724b981c8b9f"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Enforces security controls on remote access to ensure proper authorization and protection against unauthorized actions."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {02 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_ascii_remote_pause : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to remotely pause processes."
    impact = "Enables pausing of operational processes, affecting continuity and timing."
    uuid = "e84dfe27773946778f3701a4a0825e56"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Enforces security controls on remote access to ensure proper authorization and protection against unauthorized actions."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 33 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_binary_remote_pause : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to remotely pause processes."
    impact = "Enables pausing of operational processes, affecting continuity and timing."
    uuid = "73bcaddd0b5b486caf46bc71c51d7f93"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-17"
    control_description = "Remote Access: Enforces security controls on remote access to ensure proper authorization and protection against unauthorized actions."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {03 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_remote_latch_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command for remote latching."
    impact = "Enables setting of device states to a latched position, which could be misused to maintain unauthorized states."
    uuid = "91b37121f2224206b3b8fb1a7b3cc9fa"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Ensuring the system's state and activity are consistently monitored to detect and respond to unauthorized changes or actions."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_remote_latch_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command for remote latching."
    impact = "Enables setting of device states to a latched position, which could be misused to maintain unauthorized states."
    uuid = "0cd769b8c51d4c1da3ab4ff6b894a979"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-4"
    control_description = "Information System Monitoring: Ensuring the system's state and activity are consistently monitored to detect and respond to unauthorized changes or actions."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {05 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_remote_reset_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command for remote reset."
    impact = "Can be exploited to reset device states, potentially disrupting operations and causing system reinitialization."
    uuid = "f5e1ccdb62e04170aeda70f33fa1628c"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 30 30 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_remote_reset_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command for remote reset."
    impact = "Can be exploited to reset device states, potentially disrupting operations and causing system reinitialization."
    uuid = "1989c4304d024be89990d8ba40b07280"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 10 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_information_modification_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to modify file information."
    impact = "Could be used to alter metadata, potentially hiding unauthorized changes or misleading system audits."
    uuid = "4cec2e37bdef46d28671b57dbe702157"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 32 30 34 30 30 30 ??}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_information_modification_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to modify file information."
    impact = "Could be used to alter metadata, potentially hiding unauthorized changes or misleading system audits."
    uuid = "db72a720507e47c5b5adc2332423a7bb"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {04 12 0? 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_write_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command for file writing."
    impact = "Allows writing to files, which could be misused for injecting malicious data or scripts."
    uuid = "af6747539a204d4caf6f11a34d2c31cd"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 32 30 33 30 30 30 ??}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_write_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command for file writing."
    impact = "Allows writing to files, which could be misused for injecting malicious data or scripts."
    uuid = "013e78a00d99472fbee4aef54bc717d6"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {03 12 0? 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_copy_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to copy files."
    impact = "Could facilitate unauthorized duplication of sensitive data or propagation of malware."
    uuid = "e4db333f8a024f3ca483d1727bf311b1"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 32 30 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_copy_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to copy files."
    impact = "Could facilitate unauthorized duplication of sensitive data or propagation of malware."
    uuid = "a7328e53828842a789930fa794dfa8f3"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {06 12 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_delete_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to delete files."
    impact = "Enables deletion of files, which could be used to erase evidence or disrupt system operations."
    uuid = "35febdb6db9f4040ac2aab7c445f97d0"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 32 30 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_delete_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to delete files."
    impact = "Enables deletion of files, which could be used to erase evidence or disrupt system operations."
    uuid = "c05a8cc8f067476d984087c42cdfba23"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {05 12 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_write_slmp_compatible_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command for SLMP-compatible file writing."
    impact = "Permits writing to files in a manner compatible with SLMP, potentially enabling data manipulation."
    uuid = "4981284793b2481f9dc13deeaecd8e66"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 39 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_write_slmp_compatible_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command for SLMP-compatible file writing."
    impact = "Permits writing to files in a manner compatible with SLMP, potentially enabling data manipulation."
    uuid = "2a28f6b270e245e998030ad95ccbe72b"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {29 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_copy_slmp_compatible_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to copy SLMP-compatible files."
    impact = "Enables copying of files in SLMP format, which could be exploited for duplicating sensitive configurations."
    uuid = "6f971df0582c444185ade91a3829533c"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 34 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_copy_slmp_compatible_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to copy SLMP-compatible files."
    impact = "Enables copying of files in SLMP format, which could be exploited for duplicating sensitive configurations."
    uuid = "e4c09ef43d55412bb9f01834067c530f"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {24 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_delete_slmp_compatible_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to delete SLMP-compatible files."
    impact = "Allows deletion of SLMP-compatible files, potentially leading to loss of critical configuration data."
    uuid = "8a1410d2eb4845da97ff0a44a1d48a28"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 32 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_delete_slmp_compatible_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to delete SLMP-compatible files."
    impact = "Allows deletion of SLMP-compatible files, potentially leading to loss of critical configuration data."
    uuid = "2079768275b54b849a41fc8cdac03fc6"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {22 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_creation_date_modification_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to modify file creation dates."
    impact = "Could be used to obscure the true date of file creation, potentially for purposes of deception or fraud."
    uuid = "e1cf97b09eea4e0fa4cf72f9de6943eb"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 36 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_creation_date_modification_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to modify file creation dates."
    impact = "Could be used to obscure the true date of file creation, potentially for purposes of deception or fraud."
    uuid = "67e159d1f3a14431b00f0e19e0c2957c"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {26 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_file_attribute_modification_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to modify file attributes."
    impact = "Allows changes to file attributes, which could be exploited to alter file visibility or access permissions."
    uuid = "d0bc33e27f3d426599bdcea4e93090c8"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 38 32 35 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_file_attribute_modification_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to modify file attributes."
    impact = "Allows changes to file attributes, which could be exploited to alter file visibility or access permissions."
    uuid = "59a04c02753d40cbb872c5f3b2f3bd1c"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "SI"
    category_name = "System and Information Integrity"
    control = "SI-7"
    control_description = "Software, Firmware, and Information Integrity: Detecting and protecting against unauthorized changes to software, firmware, and information."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {25 18 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_remote_password_unlock_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to unlock a password."
    impact = "Could be misused to bypass password security, granting unauthorized access to secure areas of a system."
    uuid = "9d18094d14e74373b0bc7132289ef0a4"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-2"
    control_description = "Account Management: Ensuring only authorized users have access to systems and resources."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 33 30 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_remote_password_unlock_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to unlock a password."
    impact = "Could be misused to bypass password security, granting unauthorized access to secure areas of a system."
    uuid = "7142905d32f446948f96045fd0cfdb7e"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-2"
    control_description = "Account Management: Ensuring only authorized users have access to systems and resources."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {30 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}

rule mcconnect_remote_password_lock_ascii_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "ASCII command to lock a password."
    impact = "Enables password protection, which can be activated to secure system access against unauthorized use."
    uuid = "14ee839ca8b74534a3c3ba8fe35a54f6"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-2"
    control_description = "Account Management: Ensuring only authorized users have access to systems and resources."
  strings:
    $slmp_header_4e_frame = { 35 34 30 30 ?? ?? ?? ?? 30 30 30 30 }
    $slmp_header_3e_frame = { 35 30 30 30 }
    $slmp_command = {31 36 33 31 30 30 30 30}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 30) or ($slmp_header_3e_frame at 0 and $slmp_command at 22)
}

rule mcconnect_remote_password_lock_binary_v180302 : MCCONNECT 
{
  meta:
    author = "Ricardo Stefanescu <ricardo.stefanescu@puffinsecurity.com>"
    description = "Binary command to lock a password."
    impact = "Enables password protection, which can be activated to secure system access against unauthorized use."
    uuid = "536493a016f548f28585754979152281"
    lastUpdate = "2022-07-05T14:13:15+0100"
    status = "stable"
    ruleVersion = "v1.4.7"
    standard = "NIST SP 800-82"
    category = "AC"
    category_name = "Access Control"
    control = "AC-2"
    control_description = "Account Management: Ensuring only authorized users have access to systems and resources."
  strings: 
    $slmp_header_4e_frame = { 54 00 ?? ?? 00 00 }
    $slmp_header_3e_frame = { 50 00 }
    $slmp_command = {31 16 00 00}
  condition: 
    ($slmp_header_4e_frame at 0 and $slmp_command at 15) or ($slmp_header_3e_frame at 0 and $slmp_command at 11)
}
