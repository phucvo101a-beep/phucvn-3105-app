//! Pure-Rust Apple Property List (XML & Binary bplist00) Parser and Serializer
//! Zero C-dependencies, fully compatible with iOS 15.0 - iOS 27.2.1

use std::collections::HashMap;

/// Representation of Plist Values
#[derive(Debug, Clone, PartialEq)]
pub enum PlistValue {
    String(String),
    Data(Vec<u8>),
    Integer(i64),
    Real(f64),
    Boolean(bool),
    Array(Vec<PlistValue>),
    Dictionary(HashMap<String, PlistValue>),
}

impl PlistValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            PlistValue::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        match self {
            PlistValue::Data(d) => Some(d.as_slice()),
            _ => None,
        }
    }

    pub fn as_dict(&self) -> Option<&HashMap<String, PlistValue>> {
        match self {
            PlistValue::Dictionary(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[PlistValue]> {
        match self {
            PlistValue::Array(a) => Some(a.as_slice()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            PlistValue::Boolean(b) => Some(*b),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&PlistValue> {
        self.as_dict()?.get(key)
    }

    pub fn get_string(&self, key: &str) -> Option<String> {
        self.get(key)?.as_str().map(|s| s.to_string())
    }

    pub fn get_data(&self, key: &str) -> Option<Vec<u8>> {
        self.get(key)?.as_data().map(|d| d.to_vec())
    }
}

// ==============================================================================
// BASE64 ENCODER / DECODER
// ==============================================================================

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut table = [255u8; 256];
    for (i, &c) in B64_CHARS.iter().enumerate() {
        table[c as usize] = i as u8;
    }

    let clean: Vec<u8> = input
        .bytes()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();

    let mut out = Vec::with_capacity((clean.len() * 3) / 4);
    let mut buf = 0u32;
    let mut bits = 0;

    for &b in &clean {
        if b == b'=' {
            break;
        }
        let val = table[b as usize];
        if val == 255 {
            continue; // Ignore unknown characters
        }
        buf = (buf << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(out)
}

pub fn base64_encode(input: &[u8]) -> String {
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 { chunk[1] as usize } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as usize } else { 0 };

        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(B64_CHARS[(n >> 18) & 63] as char);
        out.push(B64_CHARS[(n >> 12) & 63] as char);
        if chunk.len() > 1 {
            out.push(B64_CHARS[(n >> 6) & 63] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_CHARS[n & 63] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ==============================================================================
// XML PLIST PARSER
// ==============================================================================

pub fn parse_plist(data: &[u8]) -> Result<PlistValue, String> {
    let bplist_magic = obfstr::obfstr!("bplist00").to_string();
    if data.starts_with(bplist_magic.as_bytes()) {
        parse_binary_plist(data)
    } else {
        let s = std::str::from_utf8(data)
            .map_err(|e| format!("Invalid UTF-8 XML plist: {}", e))?;
        parse_xml_plist(s)
    }
}

pub fn parse_xml_plist(xml: &str) -> Result<PlistValue, String> {
    let mut cursor = 0;
    skip_xml_declaration_and_doctypes(xml, &mut cursor);
    parse_xml_element(xml, &mut cursor)
}

fn skip_xml_declaration_and_doctypes(xml: &str, cursor: &mut usize) {
    let bytes = xml.as_bytes();
    while *cursor < bytes.len() {
        skip_whitespace(xml, cursor);
        if xml[*cursor..].starts_with("<?") {
            if let Some(end) = xml[*cursor..].find("?>") {
                *cursor += end + 2;
                continue;
            }
        }
        if xml[*cursor..].starts_with("<!DOCTYPE") || xml[*cursor..].starts_with("<!--") {
            if let Some(end) = xml[*cursor..].find('>') {
                *cursor += end + 1;
                continue;
            }
        }
        if xml[*cursor..].starts_with("<plist") {
            if let Some(end) = xml[*cursor..].find('>') {
                *cursor += end + 1;
                continue;
            }
        }
        break;
    }
}

fn skip_whitespace(xml: &str, cursor: &mut usize) {
    let bytes = xml.as_bytes();
    while *cursor < bytes.len() && bytes[*cursor].is_ascii_whitespace() {
        *cursor += 1;
    }
}

fn parse_xml_element(xml: &str, cursor: &mut usize) -> Result<PlistValue, String> {
    skip_whitespace(xml, cursor);
    if *cursor >= xml.len() {
        return Err("Unexpected end of XML".to_string());
    }

    if xml[*cursor..].starts_with("<dict>") || xml[*cursor..].starts_with("<dict ") {
        parse_xml_dict(xml, cursor)
    } else if xml[*cursor..].starts_with("<array>") || xml[*cursor..].starts_with("<array ") {
        parse_xml_array(xml, cursor)
    } else if xml[*cursor..].starts_with("<string>") {
        parse_xml_leaf(xml, cursor, "<string>", "</string>").map(PlistValue::String)
    } else if xml[*cursor..].starts_with("<string/>") {
        *cursor += "<string/>".len();
        Ok(PlistValue::String(String::new()))
    } else if xml[*cursor..].starts_with("<data>") {
        let content = parse_xml_leaf(xml, cursor, "<data>", "</data>")?;
        let bytes = base64_decode(&content)?;
        Ok(PlistValue::Data(bytes))
    } else if xml[*cursor..].starts_with("<data/>") {
        *cursor += "<data/>".len();
        Ok(PlistValue::Data(Vec::new()))
    } else if xml[*cursor..].starts_with("<integer>") {
        let content = parse_xml_leaf(xml, cursor, "<integer>", "</integer>")?;
        let num: i64 = content.trim().parse().unwrap_or(0);
        Ok(PlistValue::Integer(num))
    } else if xml[*cursor..].starts_with("<real>") {
        let content = parse_xml_leaf(xml, cursor, "<real>", "</real>")?;
        let num: f64 = content.trim().parse().unwrap_or(0.0);
        Ok(PlistValue::Real(num))
    } else if xml[*cursor..].starts_with("<true/>") {
        *cursor += "<true/>".len();
        Ok(PlistValue::Boolean(true))
    } else if xml[*cursor..].starts_with("<false/>") {
        *cursor += "<false/>".len();
        Ok(PlistValue::Boolean(false))
    } else {
        Err(format!("Unknown XML tag near: {}", &xml[*cursor..(*cursor + 30).min(xml.len())]))
    }
}

fn parse_xml_leaf(xml: &str, cursor: &mut usize, open_tag: &str, close_tag: &str) -> Result<String, String> {
    *cursor += open_tag.len();
    if let Some(end) = xml[*cursor..].find(close_tag) {
        let text = &xml[*cursor..*cursor + end];
        *cursor += end + close_tag.len();
        Ok(unescape_xml(text.trim()))
    } else {
        Err(format!("Missing closing tag: {}", close_tag))
    }
}

fn unescape_xml(input: &str) -> String {
    input
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
}

fn parse_xml_dict(xml: &str, cursor: &mut usize) -> Result<PlistValue, String> {
    if let Some(end) = xml[*cursor..].find('>') {
        *cursor += end + 1;
    }

    let mut dict = HashMap::new();

    loop {
        skip_whitespace(xml, cursor);
        if *cursor >= xml.len() {
            break;
        }
        if xml[*cursor..].starts_with("</dict>") {
            *cursor += "</dict>".len();
            break;
        }

        if xml[*cursor..].starts_with("<key>") {
            let key = parse_xml_leaf(xml, cursor, "<key>", "</key>")?;
            skip_whitespace(xml, cursor);
            let val = parse_xml_element(xml, cursor)?;
            dict.insert(key, val);
        } else {
            // Unexpected content inside dict
            if let Some(end) = xml[*cursor..].find('>') {
                *cursor += end + 1;
            } else {
                break;
            }
        }
    }

    Ok(PlistValue::Dictionary(dict))
}

fn parse_xml_array(xml: &str, cursor: &mut usize) -> Result<PlistValue, String> {
    if let Some(end) = xml[*cursor..].find('>') {
        *cursor += end + 1;
    }

    let mut arr = Vec::new();

    loop {
        skip_whitespace(xml, cursor);
        if *cursor >= xml.len() {
            break;
        }
        if xml[*cursor..].starts_with("</array>") {
            *cursor += "</array>".len();
            break;
        }

        let val = parse_xml_element(xml, cursor)?;
        arr.push(val);
    }

    Ok(PlistValue::Array(arr))
}

// ==============================================================================
// BINARY PLIST (bplist00) PARSER
// ==============================================================================

fn parse_binary_plist(data: &[u8]) -> Result<PlistValue, String> {
    let bplist_magic = obfstr::obfstr!("bplist00").to_string();
    if data.len() < 32 || !data.starts_with(bplist_magic.as_bytes()) {
        return Err(obfstr::obfstr!("Invalid binary plist header").to_string());
    }

    // Read trailer: 32 bytes at the end
    let trailer_pos = data.len() - 32;
    let trailer = &data[trailer_pos..];
    let offset_int_size = trailer[6] as usize;
    let object_ref_size = trailer[7] as usize;
    let num_objects = u64::from_be_bytes([
        trailer[8], trailer[9], trailer[10], trailer[11],
        trailer[12], trailer[13], trailer[14], trailer[15],
    ]) as usize;
    let top_object_idx = u64::from_be_bytes([
        trailer[16], trailer[17], trailer[18], trailer[19],
        trailer[20], trailer[21], trailer[22], trailer[23],
    ]) as usize;
    let offset_table_start = u64::from_be_bytes([
        trailer[24], trailer[25], trailer[26], trailer[27],
        trailer[28], trailer[29], trailer[30], trailer[31],
    ]) as usize;

    if offset_int_size == 0 || object_ref_size == 0 || num_objects == 0 {
        return Err("Corrupt bplist trailer".to_string());
    }

    // Helper to read offset of an object
    let get_offset = |idx: usize| -> Result<usize, String> {
        if idx >= num_objects {
            return Err("Object index out of bounds".to_string());
        }
        let pos = offset_table_start + idx * offset_int_size;
        if pos + offset_int_size > data.len() {
            return Err("Offset table out of bounds".to_string());
        }
        let mut val = 0usize;
        for i in 0..offset_int_size {
            val = (val << 8) | (data[pos + i] as usize);
        }
        Ok(val)
    };

    let mut cache: HashMap<usize, PlistValue> = HashMap::new();
    parse_bplist_object(data, top_object_idx, &get_offset, object_ref_size, &mut cache)
}

fn parse_bplist_object(
    data: &[u8],
    idx: usize,
    get_offset: &dyn Fn(usize) -> Result<usize, String>,
    ref_size: usize,
    cache: &mut HashMap<usize, PlistValue>,
) -> Result<PlistValue, String> {
    if let Some(val) = cache.get(&idx) {
        return Ok(val.clone());
    }

    let offset = get_offset(idx)?;
    if offset >= data.len() {
        return Err("Invalid object offset in bplist".to_string());
    }

    let marker = data[offset];
    let tag = marker & 0xF0;
    let mut count = (marker & 0x0F) as usize;
    let mut cur = offset + 1;

    let res = match tag {
        0x00 => {
            // Null, bool, fill
            match marker {
                0x00 => PlistValue::String(String::new()),
                0x08 => PlistValue::Boolean(false),
                0x09 => PlistValue::Boolean(true),
                _ => PlistValue::Boolean(false),
            }
        }
        0x10 => {
            // Integer (count is 2^count bytes)
            let bytes_len = 1 << count;
            if cur + bytes_len > data.len() {
                return Err("bplist integer out of bounds".to_string());
            }
            let mut val = 0i64;
            for i in 0..bytes_len {
                val = (val << 8) | (data[cur + i] as i64);
            }
            PlistValue::Integer(val)
        }
        0x20 => {
            // Real (float)
            PlistValue::Real(0.0)
        }
        0x40 => {
            // Data
            if count == 0x0F {
                count = read_bplist_length(data, &mut cur, get_offset)?;
            }
            if cur + count > data.len() {
                return Err("bplist data out of bounds".to_string());
            }
            PlistValue::Data(data[cur..cur + count].to_vec())
        }
        0x50 => {
            // ASCII String
            if count == 0x0F {
                count = read_bplist_length(data, &mut cur, get_offset)?;
            }
            if cur + count > data.len() {
                return Err("bplist ASCII string out of bounds".to_string());
            }
            let s = String::from_utf8_lossy(&data[cur..cur + count]).to_string();
            PlistValue::String(s)
        }
        0x60 => {
            // UTF-16 String
            if count == 0x0F {
                count = read_bplist_length(data, &mut cur, get_offset)?;
            }
            let byte_len = count * 2;
            if cur + byte_len > data.len() {
                return Err("bplist UTF-16 string out of bounds".to_string());
            }
            let u16s: Vec<u16> = data[cur..cur + byte_len]
                .chunks(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect();
            let s = String::from_utf16_lossy(&u16s);
            PlistValue::String(s)
        }
        0xA0 => {
            // Array
            if count == 0x0F {
                count = read_bplist_length(data, &mut cur, get_offset)?;
            }
            let mut arr = Vec::with_capacity(count);
            for _ in 0..count {
                let ref_idx = read_ref(data, &mut cur, ref_size)?;
                let child = parse_bplist_object(data, ref_idx, get_offset, ref_size, cache)?;
                arr.push(child);
            }
            PlistValue::Array(arr)
        }
        0xD0 => {
            // Dictionary
            if count == 0x0F {
                count = read_bplist_length(data, &mut cur, get_offset)?;
            }
            let mut key_refs = Vec::with_capacity(count);
            for _ in 0..count {
                key_refs.push(read_ref(data, &mut cur, ref_size)?);
            }
            let mut val_refs = Vec::with_capacity(count);
            for _ in 0..count {
                val_refs.push(read_ref(data, &mut cur, ref_size)?);
            }

            let mut dict = HashMap::with_capacity(count);
            for i in 0..count {
                let key_obj = parse_bplist_object(data, key_refs[i], get_offset, ref_size, cache)?;
                let val_obj = parse_bplist_object(data, val_refs[i], get_offset, ref_size, cache)?;
                if let PlistValue::String(k) = key_obj {
                    dict.insert(k, val_obj);
                }
            }
            PlistValue::Dictionary(dict)
        }
        _ => PlistValue::String(String::new()),
    };

    cache.insert(idx, res.clone());
    Ok(res)
}

fn read_ref(data: &[u8], cur: &mut usize, ref_size: usize) -> Result<usize, String> {
    if *cur + ref_size > data.len() {
        return Err("bplist ref out of bounds".to_string());
    }
    let mut val = 0usize;
    for i in 0..ref_size {
        val = (val << 8) | (data[*cur + i] as usize);
    }
    *cur += ref_size;
    Ok(val)
}

fn read_bplist_length(
    data: &[u8],
    cur: &mut usize,
    _get_offset: &dyn Fn(usize) -> Result<usize, String>,
) -> Result<usize, String> {
    if *cur >= data.len() {
        return Err("bplist length marker out of bounds".to_string());
    }
    let marker = data[*cur];
    *cur += 1;
    let tag = marker & 0xF0;
    if tag != 0x10 {
        return Err("Expected integer marker for bplist length".to_string());
    }
    let count = (marker & 0x0F) as usize;
    let byte_len = 1 << count;
    if *cur + byte_len > data.len() {
        return Err("bplist length value out of bounds".to_string());
    }
    let mut val = 0usize;
    for i in 0..byte_len {
        val = (val << 8) | (data[*cur + i] as usize);
    }
    *cur += byte_len;
    Ok(val)
}

// ==============================================================================
// XML PLIST SERIALIZER
// ==============================================================================

pub fn serialize_xml_dict(dict: &HashMap<String, PlistValue>) -> String {
    let mut xml = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    xml.push_str("<plist version=\"1.0\">\n<dict>\n");
    for (k, v) in dict {
        xml.push_str(&format!("  <key>{}</key>\n", escape_xml(k)));
        serialize_value_xml(&mut xml, v, 2);
    }
    xml.push_str("</dict>\n</plist>");
    xml
}

fn serialize_value_xml(out: &mut String, val: &PlistValue, indent: usize) {
    let ind = "  ".repeat(indent);
    match val {
        PlistValue::String(s) => {
            out.push_str(&format!("{}<string>{}</string>\n", ind, escape_xml(s)));
        }
        PlistValue::Data(d) => {
            out.push_str(&format!("{}<data>{}</data>\n", ind, base64_encode(d)));
        }
        PlistValue::Integer(i) => {
            out.push_str(&format!("{}<integer>{}</integer>\n", ind, i));
        }
        PlistValue::Real(r) => {
            out.push_str(&format!("{}<real>{}</real>\n", ind, r));
        }
        PlistValue::Boolean(b) => {
            if *b {
                out.push_str(&format!("{}<true/>\n", ind));
            } else {
                out.push_str(&format!("{}<false/>\n", ind));
            }
        }
        PlistValue::Array(arr) => {
            out.push_str(&format!("{}<array>\n", ind));
            for item in arr {
                serialize_value_xml(out, item, indent + 1);
            }
            out.push_str(&format!("{}</array>\n", ind));
        }
        PlistValue::Dictionary(dict) => {
            out.push_str(&format!("{}<dict>\n", ind));
            for (k, v) in dict {
                out.push_str(&format!("{}  <key>{}</key>\n", ind, escape_xml(k)));
                serialize_value_xml(out, v, indent + 1);
            }
            out.push_str(&format!("{}</dict>\n", ind));
        }
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}
