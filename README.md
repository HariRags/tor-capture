# Tor SNI Detector Plugin

This plugin is a Wireshark Lua post-dissector that detects Tor traffic by examining TLS Server Name Indication (SNI) fields as well as known Tor IP addresses. When the plugin identifies Tor traffic, it marks the packet

The plugin works for both live captures and saved PCAP files.

## Installation

1. **Copy the Plugin:**  
   Place the `wireshark_plugin.lua` file into your Wireshark plugins directory.
   - **Windows:** `C:\Users\<Name>\AppData\Roaming\Wireshark\plugins`
   if this does not work, you can find the folder to put the plugin by opening Wireshark > Help > Aboout Wireshark > Folders > Personal Lua Plugins

2. **Reload Wireshark**

3. **Colour Rule**
    Open View > Colouring Rules
    Press the + button to add a new rule 
    Name it `Tor_Traffic`
    Filter `tor_sni_detector.is_tor == 1`
    Background colour white 
    Foreground colour Red 
    Make sure the rule is at the top of the list
    Click OK 

## Use
- Now after reloading wireshark start capture
- Now open the Tor browser and connect
- Tor packets will be visibile with a white background and red text with protocl name Tor! 
- You can also open a pcap with tor traffic and it will show the Tor packets, you can use `torcapture.pcapng` as an example  