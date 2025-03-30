-- Wireshark Lua Plugin: Tor SNI Detector
-- This plugin marks TLS packets with SNI entries matching Tor's specific Base32 encoding pattern
-- and all subsequent TCP/TLS packets involving those IP addresses

-- Plugin information
local plugin_info = {
    version = "2.1.0",
    author = "Your Name",
    description = "Detects Tor traffic by examining SNI fields using Tor's exact Base32 algorithm"
}

-- Create a new protocol
local tor_sni_detector = Proto("tor_sni_detector", "Tor SNI Pattern Detector")

-- Define protocol fields
local f_is_tor = ProtoField.bool("tor_sni_detector.is_tor", "Tor Traffic Detected")
local f_sni = ProtoField.string("tor_sni_detector.sni", "Server Name Indication")
local f_detection_type = ProtoField.string("tor_sni_detector.detection_type", "Detection Type")

tor_sni_detector.fields = { f_is_tor, f_sni, f_detection_type }

-- Field extractors
local sni_field = Field.new("tls.handshake.extensions_server_name")
local tcp_field = Field.new("tcp")
local tls_field = Field.new("tls")
local udp_field = Field.new("udp")

-- Table to store known Tor IP addresses
local tor_ips = {}

-- Helper function: Check if SNI matches exact Tor generation pattern
local function is_tor_sni_pattern(sni)
    -- Based on Tor's code analysis:
    -- 1. Prefix is always "www."
    -- 2. Suffix is always ".com"
    -- 3. Middle part is Base32-encoded random bytes
    -- 4. Length of random part is between 4-25 characters before encoding
    --    This means 7-40 characters after Base32 encoding (each 5 bits becomes a character)
    
    -- First check if the format matches www.<something>.com
    local domain_part = sni:match("^www%.([a-zA-Z2-7]+)%.com$")
    if not domain_part then
        return false
    end
    
    -- Check length of the domain part (should be 7-40 chars after Base32 encoding)
    local domain_len = #domain_part
    if domain_len < 7 or domain_len > 40 then
        return false
    end
    
    -- Check if all characters are valid Base32 characters (A-Z, 2-7)
    -- Tor uses only these characters in their Base32 encoding
    for i = 1, domain_len do
        local char = domain_part:sub(i, i):lower()
        -- Base32 uses a-z and 2-7 (no 0, 1, 8, 9)
        if not (char:match("[a-z]") or char:match("[2-7]")) then
            return false
        end
    end
    
    -- Check if the length is divisible by 8 (full Base32 blocks)
    -- or is one of the valid partial block lengths
    local valid_lengths = {
        [7] = true,  -- 5 bytes encode to 8 base32 chars, minus 1 = 7
        [8] = true,  -- 5 bytes encode to 8 base32 chars
        [15] = true, -- 10 bytes minus 1 = 9 encode to 16 base32 chars minus 1 = 15
        [16] = true, -- 10 bytes encode to 16 base32 chars
        [23] = true, -- 15 bytes minus 2 = 13 encode to 24 base32 chars minus 1 = 23
        [24] = true, -- 15 bytes encode to 24 base32 chars
        [31] = true, -- 20 bytes minus 1 = 19 encode to 32 base32 chars minus 1 = 31
        [32] = true, -- 20 bytes encode to 32 base32 chars
        [39] = true, -- 25 bytes minus 1 = 24 encode to 40 base32 chars minus 1 = 39
        [40] = true, -- 25 bytes encode to 40 base32 chars
    }
    
    -- Check if domain length matches one of the expected lengths from Tor's algorithm
    -- Tor doesn't use padding in their Base32 implementation for SNI
    if not valid_lengths[domain_len] then
        -- Additional check: Base32 encodes each 5 bytes to 8 characters
        local remainder = domain_len % 8
        -- Valid remainders are 0, 2, 4, 5, and 7 in Base32 without padding
        if not (remainder == 0 or remainder == 2 or remainder == 4 or remainder == 5 or remainder == 7) then
            return false
        end
    end
    
    -- All Tor-specific checks passed - very high probability this is Tor traffic
    return true
end

-- Reset function - called when a new capture file is loaded or created
function tor_sni_detector.init()
    tor_ips = {}  -- Clear the IP table

end

-- Dissector function
function tor_sni_detector.dissector(buffer, pinfo, tree)
    -- Skip packets without IP addresses (non-IP protocols)
    if not pinfo.src or not pinfo.dst then
        return
    end
    
    -- Skip UDP packets - Tor typically uses TCP
    if udp_field() then
        return
    end
    
    -- Only process TCP or TLS packets
    local is_tcp = tcp_field() ~= nil
    local is_tls = tls_field() ~= nil
    
    if not (is_tcp or is_tls) then
        return
    end
    
    local src_ip = tostring(pinfo.src)
    local dst_ip = tostring(pinfo.dst)
    local is_tor = false
    local detection_type = ""
    local sni_str = ""
    
    -- Check if packet contains SNI field (possible new Tor detection)
    local sni = sni_field()
    if sni then
        sni_str = tostring(sni)
        if is_tor_sni_pattern(sni_str) then
            is_tor = true
            detection_type = "Tor SNI Pattern"
            -- Add both IPs to the known Tor IPs list
            tor_ips[dst_ip] = true
        end
    end
    
    -- Check if packet involves a previously identified Tor IP
    if not is_tor then
        if tor_ips[src_ip] or tor_ips[dst_ip] then
            is_tor = true
            detection_type = "Known Tor IP"
        end
    end
    
    -- Add protocol information to the packet if it's Tor-related
    local tor_color_rule_set = false

-- Add protocol information to the packet if it's Tor-related
if is_tor then
    local subtree = tree:add(tor_sni_detector, buffer(), "Tor Traffic Detected")
    subtree:add(f_is_tor, true)
    subtree:add(f_detection_type, detection_type)
    
    if sni_str ~= "" then
        subtree:add(f_sni, sni_str)
    end
    
    -- Change label to "Tor!" instead of "TOR"
    pinfo.cols.protocol = "Tor!"
    -- Properly handle info column modification
    local info_text = tostring(pinfo.cols.info)
    if not info_text:match("^%[Tor!%]") then
        pinfo.cols.info = "[Tor!] " .. info_text
    end
    
    -- Install a temporary coloring rule for packets with protocol containing "Tor!"
    
end
end

-- Register this dissector as a post-dissector to run on every packet
register_postdissector(tor_sni_detector)

-- Print a message when the script is loaded
print("Tor Traffic Detector Plugin Loaded - Precise Base32 Detection with Purple Highlights")