--  variables
PATH_SEPARATOR = package.config:sub(1,1)
iocs = {}
assets = {}
blocklist = {}
cidr_tags = {}
ip_to_dns_map = {}

-- create a new protocol so we can register a post-dissector
wft = Proto("wft", "Wireshark Forensics Toolkit")

-- source fields
wft_src_domain_field = ProtoField.string("wft.src.domain", "Source Domain")
wft_src_detection_field = ProtoField.string("wft.src.detection", "Source Detection")
wft_src_severity_field = ProtoField.string("wft.src.severity", "Source Detection Severity")
wft_src_threat_type_field = ProtoField.string("wft.src.threat_type", "Source Detection Threat Type")
wft_src_asset_tags = ProtoField.string("wft.src.tags", "Source Asset Tags")
wft_src_asset_os = ProtoField.string("wft.src.os", "Source Asset OS")
wft_src_asset_cve_ids = ProtoField.string("wft.src.cve_ids", "Source Asset Vulnerability CVEs")
wft_src_asset_top_cvss_score = ProtoField.float("wft.src.top_cvss_score", "Source Asset Vulnerability Top CVSS Score")

-- destination fields
wft_dst_domain_field = ProtoField.string("wft.dst.domain", "Destination Domain")
wft_dst_detection_field = ProtoField.string("wft.dst.detection", "Destination Detection")
wft_dst_severity_field = ProtoField.string("wft.dst.severity", "Destination Detection Severity")
wft_dst_threat_type_field = ProtoField.string("wft.dst.threat_type", "Destination Detection Threat Type")
wft_dst_asset_tags = ProtoField.string("wft.dst.tags", "Destination Asset Tags")
wft_dst_asset_os = ProtoField.string("wft.dst.os", "Destination Asset OS")
wft_dst_asset_cve_ids = ProtoField.string("wft.dst.cve_ids", "Destination Asset Vulnerability CVEs")
wft_dst_asset_top_cvss_score = ProtoField.float("wft.dst.top_cvss_score", "Destination Asset Vulnerability Top CVSS Score")

wft.fields = {
    wft_src_domain_field,
    wft_src_detection_field,
    wft_src_severity_field,
    wft_src_threat_type_field,
    wft_src_asset_tags,
    wft_src_asset_os,
    wft_src_asset_cve_ids,
    wft_src_asset_top_cvss_score,
    wft_dst_domain_field,
    wft_dst_detection_field,
    wft_dst_severity_field,
    wft_dst_threat_type_field,
    wft_dst_asset_tags,
    wft_dst_asset_os,
    wft_dst_asset_cve_ids,
    wft_dst_asset_top_cvss_score
  }

-- functions

function is_ip_in_cidr(ip, cidr)
    if not ip:match('%d.%d.%d.%d') then
        return false
    end
    n4, n3, n2, n1, c = cidr:match("%s*(%w*).%s*(%w*).%s*(%w*).%s*(%w*)/%s*(.*)")
    n1 = math.floor(tonumber(n1))
    n2 = math.floor(tonumber(n2))
    n3 = math.floor(tonumber(n3))
    n4 = math.floor(tonumber(n4))
    --print(n4 .. ":" .. n3 .. ":" .. n2 .. ":" .. n1)
    c = 32-tonumber(c)

    -- find mask m1 is rightmost , m4 is leftmost
    m1 = 255
    m2 = 255
    m3 = 255
    m4 = 255

    if c <= 0 then
        m1 = 255
    elseif c>=8 then
        m1 = 0
    else
        m1 = math.floor(m4 - (2^(c)-1))
    end

    c = c - 8
    if c <= 0 then
        m2 = 255
    elseif c>8 then
        m2 = 0
    else
        m2 = math.floor(m2 - (2^(c)-1))
    end

    c = c - 8
    if c <= 0 then
        m3 = 255
    elseif c>8 then
        m3 = 0
    else
        m3 = math.floor(m3 - (2^(c)-1))
    end

    c = c - 8
    if c <= 0 then
        m4 = 255
    elseif c == 0 or c>8 then
        m4 = 0
    else
        m4 = math.floor(m4 - (2^(c)-1))
    end
    --print(m4 .. ":" .. m3 .. ":" .. m2 .. ":" .. m1)

    i4, i3, i2, i1 = ip:match("%s*(%w*).%s*(%w*).%s*(%w*).%s*(%w*)")
    i1 = math.floor(tonumber(i1))
    i2 = math.floor(tonumber(i2))
    i3 = math.floor(tonumber(i3))
    i4 = math.floor(tonumber(i4))
    --print(i4 .. ":" .. i3 .. ":" .. i2 .. ":" .. i1)

    c1 = bit32.band(m1, i1)
    c2 = bit32.band(m2, i2)
    c3 = bit32.band(m3, i3)
    c4 = bit32.band(m4, i4)
    --print(c4 .. ":" .. c3 .. ":" .. c2 .. ":" .. c1)

    if (n1 == c1 or (c1 == 0 and i1 ~= 0) ) and (n2 == c2 or (c2 == 0 and i2 ~= 0)) and (n3 == c3 or (c3 == 0 and i3 ~= 0)) and (n4 == c4 or (c4 == 0 and i4 ~= 0)) then
        return true
    else
        return false
    end
end

function dump(o)
   if type(o) == 'table' then
      local s = '{ '
      for k,v in pairs(o) do
         if type(k) ~= 'number' then k = '"'..k..'"' end
         s = s .. '['..k..'] = ' .. dump(v) .. ','
      end
      return s .. '} '
   else
      return tostring(o)
   end
end

-- fill default values for ioc
function fill_default_values(ioc_value, ioc_type)
    if assets[ioc_value]==nil then
        assets[ioc_value] = {tags="", os="", cve_ids="", top_cvss_score=0}
    end

    if iocs[ioc_value]==nil then
        iocs[ioc_value] = {detection="", value_type=ioc_type,  severity="", threat_type=""}
    end

    if ioc_type == "ip" then
        if ip_to_dns_map[ioc_value]==nil then
            ip_to_dns_map[ioc_value] = ""
        end
    end
end

-- load IOC file
function load_iocs()
  ioc_def_path = persconffile_path('plugins')..PATH_SEPARATOR..'wireshark_forensics_toolkit'..PATH_SEPARATOR..'indicators.csv'
  local i = 0
  for line in io.lines(ioc_def_path) do
      if i ~= 1 and line ~= '' then
          local value_type, value, severity, threat_type = line:match("%s*(.*),%s*(.*),%s*(.*),%s*(.*)")
          threat_type = string.gsub(threat_type,"\r", "")
          iocs[value] = {value_type=value_type, severity=severity, threat_type=threat_type, detection="malicious"}
      end
  end
end

-- load assets vulnearbility and OS information
function load_asset_vulnerabilities()
  assets_def_path = persconffile_path('plugins')..PATH_SEPARATOR..'wireshark_forensics_toolkit'..PATH_SEPARATOR..'asset_vulnerabilities.csv'
  local i = 0
  for line in io.lines(assets_def_path) do
      if i ~= 1 and line ~= '' then
          local asset_address, os, top_cvss_score, cve_ids = line:match("%s*(.*),%s*(.*),%s*(.*),%s*(.*)")
          cve_ids = string.gsub(cve_ids,"\r", "")
          if top_cvss_score ~= nil or top_cvss_score ~= "" then
              top_cvss_score = tonumber(top_cvss_score)
          end
          if assets[asset_address] == nil then
              assets[asset_address] = {asset_address_type="ip", tags="", os=os, top_cvss_score=top_cvss_score, cve_ids=cve_ids}
          else
              assets[asset_address]["os"] = os
              assets[asset_address]["top_cvss_score"] = top_cvss_score
              assets[asset_address]["cve_ids"] = cve_ids
          end
      end
  end
end

-- load assets tags
function load_asset_tags()
  assets_def_path = persconffile_path('plugins')..PATH_SEPARATOR..'wireshark_forensics_toolkit'..PATH_SEPARATOR..'asset_tags.csv'
  local i = 0
  for line in io.lines(assets_def_path) do
      if i ~= 1 and line ~= '' then
          local address_type, address_value, tags = line:match("%s*(.*),%s*(.*),%s*(.*)")
          tags = string.gsub(tags,"\r", "")
          if address_type == "cidr" then
              cidr_tags[address_value] = tags
          else
              assets[address_value] = {asset_address_type=address_type, tags=tags, os="", top_cvss_score=0, cve_ids=""}
          end
      end
  end
end


-- parse DNS response packets to create in memory IP -> DNS Map
dns_tap = Listener.new(nil, "dns.count.answers >= 1")
count = Field.new("dns.count.answers")
dns_name = Field.new("dns.qry.name")
ip_address = Field.new("dns.a")

function dns_tap.packet(pinfo)
    local dns = dns_name()
    local ips = {ip_address()}
    for i in pairs(ips) do
        ip_str = tostring(ips[i])
        if ip_to_dns_map[ip_str] == nil or ip_to_dns_map[ip_str] == "" then
            ip_to_dns_map[ip_str] = tostring(dns)
        end
    end
end


-- the dissector function callback
function wft.dissector(tvb,pinfo,tree)
    subtree = tree:add(wft)

    src_ip = tostring(pinfo.src)
    dst_ip = tostring(pinfo.dst)

    fill_default_values(src_ip, "ip")
    fill_default_values(ip_to_dns_map[src_ip], "domain")
    fill_default_values(dst_ip, "ip")
    fill_default_values(ip_to_dns_map[dst_ip], "domain")


    src_domain = ip_to_dns_map[src_ip]
    dst_domain = ip_to_dns_map[dst_ip]
    if src_domain == nil then src_domain = "" end
    if dst_domain == nil then dst_domain = "" end

    ioc_src_key = iocs[src_ip]
    ioc_dst_key = iocs[dst_ip]
    if src_domain ~= "" then ioc_src_key = iocs[src_domain] end
    if dst_domain ~= "" then ioc_dst_key = iocs[dst_domain] end

    asset_src_key = assets[src_ip]
    asset_dst_key = assets[dst_ip]
    if asset_src_key["tags"] == "" and src_domain ~= "" then asset_src_key = assets[src_domain] end
    if asset_dst_key["tags"] == "" and dst_domain ~= "" then asset_dst_key = assets[dst_domain] end


    -- update CIDR tags for asset if available. If not create new asset entry
    for cidr,tags in pairs(cidr_tags) do
        if is_ip_in_cidr(src_ip, cidr) then
            if assets[src_ip] ~= nil then
                assets[src_ip]['tags'] = tags
            else
                assets[src_ip] = {asset_address_type="ip", tags=tags, os="", top_cvss_score=0, cve_ids=""}
            end
        end
        if is_ip_in_cidr(dst_ip, cidr) then
            if assets[dst_ip] ~= nil then
                assets[dst_ip]['tags'] = tags
            else
                assets[dst_ip] = {asset_address_type="ip", tags=tags, os="", top_cvss_score=0, cve_ids=""}
            end
        end
    end


    -- source fields
    subtree:add(wft_src_domain_field, tostring(src_domain))
    subtree:add(wft_src_detection_field, ioc_src_key["detection"])
    subtree:add(wft_src_severity_field, ioc_src_key["severity"])
    subtree:add(wft_src_threat_type_field, ioc_src_key["threat_type"])
    subtree:add(wft_src_asset_tags, asset_src_key["tags"])
    subtree:add(wft_src_asset_os, asset_src_key["os"])
    subtree:add(wft_src_asset_cve_ids, asset_src_key["cve_ids"])
    subtree:add(wft_src_asset_top_cvss_score, asset_src_key["top_cvss_score"])

    -- destination fields
    subtree:add(wft_dst_domain_field, tostring(dst_domain))
    subtree:add(wft_dst_detection_field, ioc_dst_key["detection"])
    subtree:add(wft_dst_severity_field, ioc_dst_key["severity"])
    subtree:add(wft_dst_threat_type_field, ioc_dst_key["threat_type"])
    subtree:add(wft_dst_asset_tags, asset_dst_key["tags"])
    subtree:add(wft_dst_asset_os, asset_dst_key["os"])
    subtree:add(wft_dst_asset_cve_ids, asset_dst_key["cve_ids"])
    subtree:add(wft_dst_asset_top_cvss_score, asset_dst_key["top_cvss_score"])

end


-- Data loading functions
load_iocs()
load_asset_tags()
load_asset_vulnerabilities()

register_postdissector(wft, true)


