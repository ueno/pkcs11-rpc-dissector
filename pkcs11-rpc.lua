-- PKCS #11 RPC Protocol Dissector for Wireshark
-- Based on p11-kit implementation and draft-ueno-pkcs11-rpc specification
-- Copyright (C) 2025
--
-- This dissector supports:
-- - Protocol version 0 (PKCS #11 2.40)
-- - Protocol version 1 (PKCS #11 3.0)
-- - Protocol version 2 (mechanism parameter updates)

-- Declare protocol
local pkcs11_rpc_proto = Proto("pkcs11-rpc", "PKCS #11 RPC Protocol")

-- Protocol fields
local f = pkcs11_rpc_proto.fields
f.version = ProtoField.uint8("pkcs11_rpc.version", "Protocol Version", base.DEC)
f.call_code = ProtoField.uint32("pkcs11_rpc.call_code", "Call Code", base.DEC)
f.options_length = ProtoField.uint32("pkcs11_rpc.options_length", "Options Length", base.DEC)
f.buffer_length = ProtoField.uint32("pkcs11_rpc.buffer_length", "Buffer Length", base.DEC)
f.options_data = ProtoField.bytes("pkcs11_rpc.options_data", "Options Data")
f.call_id = ProtoField.uint32("pkcs11_rpc.call_id", "Call ID", base.DEC)
f.call_name = ProtoField.string("pkcs11_rpc.call_name", "Call Name")
f.signature = ProtoField.string("pkcs11_rpc.signature", "Signature")
f.message_type = ProtoField.string("pkcs11_rpc.message_type", "Message Type")

-- Serialization type fields
f.ulong = ProtoField.uint64("pkcs11_rpc.ulong", "CK_ULONG", base.HEX)
f.byte = ProtoField.uint8("pkcs11_rpc.byte", "CK_BYTE", base.HEX)
f.version_major = ProtoField.uint8("pkcs11_rpc.version_major", "Version Major", base.DEC)
f.version_minor = ProtoField.uint8("pkcs11_rpc.version_minor", "Version Minor", base.DEC)
f.string_len = ProtoField.uint32("pkcs11_rpc.string_len", "String Length", base.DEC)
f.string_value = ProtoField.string("pkcs11_rpc.string_value", "String Value")
f.array_count = ProtoField.uint32("pkcs11_rpc.array_count", "Array Count", base.DEC)
f.array_length = ProtoField.uint32("pkcs11_rpc.array_length", "Array Length", base.DEC)
f.byte_array = ProtoField.bytes("pkcs11_rpc.byte_array", "Byte Array")
f.attr_type = ProtoField.uint32("pkcs11_rpc.attr_type", "Attribute Type", base.HEX)
f.attr_value_len = ProtoField.uint32("pkcs11_rpc.attr_value_len", "Attribute Value Length", base.DEC)
f.attr_value = ProtoField.bytes("pkcs11_rpc.attr_value", "Attribute Value")
f.mech_type = ProtoField.uint32("pkcs11_rpc.mech_type", "Mechanism Type", base.HEX)
f.mech_param_type = ProtoField.uint8("pkcs11_rpc.mech_param_type", "Mechanism Parameter Type", base.HEX)
f.mech_param_len = ProtoField.uint32("pkcs11_rpc.mech_param_len", "Mechanism Parameter Length", base.DEC)
f.mech_param = ProtoField.bytes("pkcs11_rpc.mech_param", "Mechanism Parameter")
f.return_value = ProtoField.uint32("pkcs11_rpc.return_value", "Return Value (CK_RV)", base.HEX)

-- PKCS #11 function call mappings
local call_names = {
    [0] = { name = "ERROR", request = "", response = "u" },
    [1] = { name = "C_Initialize", request = "ayyay", response = "" },
    [2] = { name = "C_Finalize", request = "", response = "" },
    [3] = { name = "C_GetInfo", request = "", response = "vsusv" },
    [4] = { name = "C_GetSlotList", request = "yfu", response = "au" },
    [5] = { name = "C_GetSlotInfo", request = "u", response = "ssuvv" },
    [6] = { name = "C_GetTokenInfo", request = "u", response = "ssssuuuuuuuuuuuvvs" },
    [7] = { name = "C_GetMechanismList", request = "ufu", response = "au" },
    [8] = { name = "C_GetMechanismInfo", request = "uu", response = "uuu" },
    [9] = { name = "C_InitToken", request = "uayz", response = "" },
    [10] = { name = "C_OpenSession", request = "uu", response = "u" },
    [11] = { name = "C_CloseSession", request = "u", response = "" },
    [12] = { name = "C_CloseAllSessions", request = "u", response = "" },
    [13] = { name = "C_GetSessionInfo", request = "u", response = "uuuu" },
    [14] = { name = "C_InitPIN", request = "uay", response = "" },
    [15] = { name = "C_SetPIN", request = "uayay", response = "" },
    [16] = { name = "C_GetOperationState", request = "ufy", response = "ay" },
    [17] = { name = "C_SetOperationState", request = "uayuu", response = "" },
    [18] = { name = "C_Login", request = "uuay", response = "" },
    [19] = { name = "C_Logout", request = "u", response = "" },
    [20] = { name = "C_CreateObject", request = "uaA", response = "u" },
    [21] = { name = "C_CopyObject", request = "uuaA", response = "u" },
    [22] = { name = "C_DestroyObject", request = "uu", response = "" },
    [23] = { name = "C_GetObjectSize", request = "uu", response = "u" },
    [24] = { name = "C_GetAttributeValue", request = "uufA", response = "aAu" },
    [25] = { name = "C_SetAttributeValue", request = "uuaA", response = "" },
    [26] = { name = "C_FindObjectsInit", request = "uaA", response = "" },
    [27] = { name = "C_FindObjects", request = "ufu", response = "au" },
    [28] = { name = "C_FindObjectsFinal", request = "u", response = "" },
    [29] = { name = "C_EncryptInit", request = "uMu", response = "" },
    [30] = { name = "C_Encrypt", request = "uayfy", response = "ay" },
    [31] = { name = "C_EncryptUpdate", request = "uayfy", response = "ay" },
    [32] = { name = "C_EncryptFinal", request = "ufy", response = "ay" },
    [33] = { name = "C_DecryptInit", request = "uMu", response = "" },
    [34] = { name = "C_Decrypt", request = "uayfy", response = "ay" },
    [35] = { name = "C_DecryptUpdate", request = "uayfy", response = "ay" },
    [36] = { name = "C_DecryptFinal", request = "ufy", response = "ay" },
    [37] = { name = "C_DigestInit", request = "uM", response = "" },
    [38] = { name = "C_Digest", request = "uayfy", response = "ay" },
    [39] = { name = "C_DigestUpdate", request = "uay", response = "" },
    [40] = { name = "C_DigestKey", request = "uu", response = "" },
    [41] = { name = "C_DigestFinal", request = "ufy", response = "ay" },
    [42] = { name = "C_SignInit", request = "uMu", response = "" },
    [43] = { name = "C_Sign", request = "uayfy", response = "ay" },
    [44] = { name = "C_SignUpdate", request = "uay", response = "" },
    [45] = { name = "C_SignFinal", request = "ufy", response = "ay" },
    [46] = { name = "C_SignRecoverInit", request = "uMu", response = "" },
    [47] = { name = "C_SignRecover", request = "uayfy", response = "ay" },
    [48] = { name = "C_VerifyInit", request = "uMu", response = "" },
    [49] = { name = "C_Verify", request = "uayay", response = "" },
    [50] = { name = "C_VerifyUpdate", request = "uay", response = "" },
    [51] = { name = "C_VerifyFinal", request = "uay", response = "" },
    [52] = { name = "C_VerifyRecoverInit", request = "uMu", response = "" },
    [53] = { name = "C_VerifyRecover", request = "uayfy", response = "ay" },
    [54] = { name = "C_DigestEncryptUpdate", request = "uayfy", response = "ay" },
    [55] = { name = "C_DecryptDigestUpdate", request = "uayfy", response = "ay" },
    [56] = { name = "C_SignEncryptUpdate", request = "uayfy", response = "ay" },
    [57] = { name = "C_DecryptVerifyUpdate", request = "uayfy", response = "ay" },
    [58] = { name = "C_GenerateKey", request = "uMaA", response = "u" },
    [59] = { name = "C_GenerateKeyPair", request = "uMaAaA", response = "uu" },
    [60] = { name = "C_WrapKey", request = "uMuufy", response = "ay" },
    [61] = { name = "C_UnwrapKey", request = "uMuayaA", response = "u" },
    [62] = { name = "C_DeriveKey", request = "uMuaA", response = "u" },
    [63] = { name = "C_SeedRandom", request = "uay", response = "" },
    [64] = { name = "C_GenerateRandom", request = "ufy", response = "ay" },
    [65] = { name = "C_WaitForSlotEvent", request = "u", response = "u" },
    -- PKCS #11 3.0 (Version 1+)
    [66] = { name = "C_LoginUser", request = "uuayay", response = "" },
    [67] = { name = "C_SessionCancel", request = "uu", response = "" },
    [68] = { name = "C_MessageEncryptInit", request = "uMu", response = "" },
    [69] = { name = "C_EncryptMessage", request = "uayayayfy", response = "ay" },
    [70] = { name = "C_EncryptMessageBegin", request = "uayay", response = "" },
    [71] = { name = "C_EncryptMessageNext", request = "uayayfyu", response = "ay" },
    [72] = { name = "C_MessageEncryptFinal", request = "u", response = "" },
    [73] = { name = "C_MessageDecryptInit", request = "uMu", response = "" },
    [74] = { name = "C_DecryptMessage", request = "uayayayfy", response = "ay" },
    [75] = { name = "C_DecryptMessageBegin", request = "uayay", response = "" },
    [76] = { name = "C_DecryptMessageNext", request = "uayayfyu", response = "ay" },
    [77] = { name = "C_MessageDecryptFinal", request = "u", response = "" },
    [78] = { name = "C_MessageSignInit", request = "uMu", response = "" },
    [79] = { name = "C_SignMessage", request = "uayayfy", response = "ay" },
    [80] = { name = "C_SignMessageBegin", request = "uay", response = "" },
    [81] = { name = "C_SignMessageNext", request = "uayayyfy", response = "ay" },
    [82] = { name = "C_MessageSignFinal", request = "u", response = "" },
    [83] = { name = "C_MessageVerifyInit", request = "uMu", response = "" },
    [84] = { name = "C_VerifyMessage", request = "uayayay", response = "" },
    [85] = { name = "C_VerifyMessageBegin", request = "uay", response = "" },
    [86] = { name = "C_VerifyMessageNext", request = "uayayay", response = "" },
    [87] = { name = "C_MessageVerifyFinal", request = "u", response = "" },
    -- Extended functions (Version 2+)
    [88] = { name = "C_InitToken2", request = "uays", response = "" },
    [89] = { name = "C_DeriveKey2", request = "uMuaA", response = "uPu" },
}

-- Helper function to parse signature and dissect message body
local function dissect_signature(tvbuf, pktinfo, tree, offset, signature, is_response)
    local sig_pos = 1
    local sig_len = string.len(signature)

    while sig_pos <= sig_len do
        local type_char = string.sub(signature, sig_pos, sig_pos)

        -- Handle prefix modifiers
        if type_char == 'a' then
            -- Array prefix
            sig_pos = sig_pos + 1
            local elem_type = string.sub(signature, sig_pos, sig_pos)

            if elem_type == 'y' then
                -- Byte array
                local array_len = tvbuf(offset, 4):uint()
                tree:add(f.array_length, tvbuf(offset, 4))
                offset = offset + 4

                if array_len > 0 and offset + array_len <= tvbuf:len() then
                    tree:add(f.byte_array, tvbuf(offset, array_len))
                    offset = offset + array_len
                end
            elseif elem_type == 'u' then
                -- ULONG array
                local count = tvbuf(offset, 4):uint()
                tree:add(f.array_count, tvbuf(offset, 4))
                offset = offset + 4

                for i = 1, count do
                    if offset + 8 <= tvbuf:len() then
                        tree:add(f.ulong, tvbuf(offset, 8))
                        offset = offset + 8
                    end
                end
            elseif elem_type == 'A' then
                -- Attribute array
                local count = tvbuf(offset, 4):uint()
                tree:add(f.array_count, tvbuf(offset, 4))
                offset = offset + 4

                for i = 1, count do
                    if offset + 8 <= tvbuf:len() then
                        local attr_subtree = tree:add(pkcs11_rpc_proto, tvbuf(offset, 8), "Attribute #" .. i)
                        attr_subtree:add(f.attr_type, tvbuf(offset, 4))
                        offset = offset + 4

                        local value_len = tvbuf(offset, 4):uint()
                        attr_subtree:add(f.attr_value_len, tvbuf(offset, 4))
                        offset = offset + 4

                        if value_len > 0 and offset + value_len <= tvbuf:len() then
                            attr_subtree:add(f.attr_value, tvbuf(offset, value_len))
                            offset = offset + value_len
                        end
                    end
                end
            end

        elseif type_char == 'f' then
            -- Buffer prefix
            sig_pos = sig_pos + 1
            local elem_type = string.sub(signature, sig_pos, sig_pos)

            if elem_type == 'u' then
                -- Buffer for ULONG
                local count = tvbuf(offset, 4):uint()
                tree:add(f.array_count, tvbuf(offset, 4), count)
                offset = offset + 4
            elseif elem_type == 'y' then
                -- Buffer for bytes
                local buf_len = tvbuf(offset, 4):uint()
                tree:add(f.array_length, tvbuf(offset, 4))
                offset = offset + 4
            elseif elem_type == 'A' then
                -- Buffer for attributes - this is a template
                -- Read the count and then the attribute types
                local count = tvbuf(offset, 4):uint()
                tree:add(f.array_count, tvbuf(offset, 4))
                offset = offset + 4

                for i = 1, count do
                    if offset + 8 <= tvbuf:len() then
                        local attr_subtree = tree:add(pkcs11_rpc_proto, tvbuf(offset, 8), "Attribute Template #" .. i)
                        attr_subtree:add(f.attr_type, tvbuf(offset, 4))
                        offset = offset + 4

                        local value_len = tvbuf(offset, 4):uint()
                        attr_subtree:add(f.attr_value_len, tvbuf(offset, 4))
                        offset = offset + 4
                    end
                end
            end

        elseif type_char == 'u' then
            -- CK_ULONG
            if offset + 8 <= tvbuf:len() then
                tree:add(f.ulong, tvbuf(offset, 8))
                offset = offset + 8
            end

        elseif type_char == 'y' then
            -- CK_BYTE
            if offset + 1 <= tvbuf:len() then
                tree:add(f.byte, tvbuf(offset, 1))
                offset = offset + 1
            end

        elseif type_char == 'v' then
            -- CK_VERSION
            if offset + 2 <= tvbuf:len() then
                local ver_tree = tree:add(pkcs11_rpc_proto, tvbuf(offset, 2), "CK_VERSION")
                ver_tree:add(f.version_major, tvbuf(offset, 1))
                ver_tree:add(f.version_minor, tvbuf(offset + 1, 1))
                offset = offset + 2
            end

        elseif type_char == 'z' then
            -- Null-terminated string
            if offset + 4 <= tvbuf:len() then
                local str_len = tvbuf(offset, 4):uint()
                tree:add(f.string_len, tvbuf(offset, 4))
                offset = offset + 4

                if str_len > 0 and offset + str_len <= tvbuf:len() then
                    tree:add(f.string_value, tvbuf(offset, str_len))
                    offset = offset + str_len
                end
            end

        elseif type_char == 's' then
            -- Space-padded string
            if offset + 4 <= tvbuf:len() then
                local str_len = tvbuf(offset, 4):uint()
                tree:add(f.string_len, tvbuf(offset, 4))
                offset = offset + 4

                if str_len > 0 and offset + str_len <= tvbuf:len() then
                    tree:add(f.string_value, tvbuf(offset, str_len))
                    offset = offset + str_len
                end
            end

        elseif type_char == 'M' then
            -- CK_MECHANISM
            if offset + 9 <= tvbuf:len() then
                local mech_tree = tree:add(pkcs11_rpc_proto, tvbuf(offset, 9), "CK_MECHANISM")
                mech_tree:add(f.mech_type, tvbuf(offset, 4))
                offset = offset + 4

                mech_tree:add(f.mech_param_type, tvbuf(offset, 1))
                offset = offset + 1

                local param_len = tvbuf(offset, 4):uint()
                mech_tree:add(f.mech_param_len, tvbuf(offset, 4))
                offset = offset + 4

                if param_len > 0 and offset + param_len <= tvbuf:len() then
                    mech_tree:add(f.mech_param, tvbuf(offset, param_len))
                    offset = offset + param_len
                end
            end

        elseif type_char == 'P' then
            -- Mechanism parameter update (version 2+)
            if offset + 1 <= tvbuf:len() then
                local param_type = tvbuf(offset, 1):uint()
                tree:add(f.mech_param_type, tvbuf(offset, 1))
                offset = offset + 1

                if offset + 4 <= tvbuf:len() then
                    local param_len = tvbuf(offset, 4):uint()
                    tree:add(f.mech_param_len, tvbuf(offset, 4))
                    offset = offset + 4

                    if param_len > 0 and offset + param_len <= tvbuf:len() then
                        tree:add(f.mech_param, tvbuf(offset, param_len))
                        offset = offset + param_len
                    end
                end
            end

        elseif type_char == 'A' then
            -- Single CK_ATTRIBUTE
            if offset + 8 <= tvbuf:len() then
                local attr_tree = tree:add(pkcs11_rpc_proto, tvbuf(offset, 8), "CK_ATTRIBUTE")
                attr_tree:add(f.attr_type, tvbuf(offset, 4))
                offset = offset + 4

                local value_len = tvbuf(offset, 4):uint()
                attr_tree:add(f.attr_value_len, tvbuf(offset, 4))
                offset = offset + 4

                if value_len > 0 and offset + value_len <= tvbuf:len() then
                    attr_tree:add(f.attr_value, tvbuf(offset, value_len))
                    offset = offset + value_len
                end
            end
        end

        sig_pos = sig_pos + 1
    end

    return offset
end

-- Main dissector function
function pkcs11_rpc_proto.dissector(tvbuf, pktinfo, root)
    local pktlen = tvbuf:reported_length_remaining()

    -- Set protocol name in packet list
    pktinfo.cols.protocol:set("PKCS11-RPC")

    local tree = root:add(pkcs11_rpc_proto, tvbuf:range(0, pktlen))

    local offset = 0

    -- Check if this is a version negotiation byte (1 byte messages)
    if pktlen == 1 then
        tree:add(f.version, tvbuf(0, 1))
        pktinfo.cols.info:set("Version Negotiation: " .. tvbuf(0, 1):uint())
        return
    end

    -- Parse message header (12 bytes)
    if pktlen < 12 then
        tree:add_expert_info(PI_MALFORMED, PI_ERROR, "Message too short")
        return
    end

    -- Header fields
    local call_code = tvbuf(offset, 4):uint()
    tree:add(f.call_code, tvbuf(offset, 4))
    offset = offset + 4

    local options_length = tvbuf(offset, 4):uint()
    tree:add(f.options_length, tvbuf(offset, 4))
    offset = offset + 4

    local buffer_length = tvbuf(offset, 4):uint()
    tree:add(f.buffer_length, tvbuf(offset, 4))
    offset = offset + 4

    -- Options area (if present)
    if options_length > 0 then
        if offset + options_length <= pktlen then
            tree:add(f.options_data, tvbuf(offset, options_length))
            offset = offset + options_length
        end
    end

    -- Message body
    if buffer_length > 0 and offset + buffer_length <= pktlen then
        local body_tvb = tvbuf(offset, buffer_length)
        local body_tree = tree:add(pkcs11_rpc_proto, body_tvb, "Message Body")
        local body_offset = 0

        -- Read call ID
        if body_offset + 4 <= buffer_length then
            local call_id = body_tvb(body_offset, 4):uint()
            body_tree:add(f.call_id, body_tvb(body_offset, 4))
            body_offset = body_offset + 4

            -- Get call name
            local call_info = call_names[call_id]
            if call_info then
                body_tree:add(f.call_name, call_info.name)
                pktinfo.cols.info:set(call_info.name)
            else
                pktinfo.cols.info:set("Unknown Call ID: " .. call_id)
            end

            -- Read signature (null-terminated)
            if body_offset + 4 <= buffer_length then
                local sig_len = body_tvb(body_offset, 4):uint()
                body_offset = body_offset + 4

                if sig_len > 0 and body_offset + sig_len <= buffer_length then
                    local sig_str = body_tvb(body_offset, sig_len):string()
                    body_tree:add(f.signature, body_tvb(body_offset, sig_len))
                    body_offset = body_offset + sig_len

                    -- Determine if this is request or response
                    local is_response = false
                    if call_info then
                        if sig_str == call_info.response then
                            is_response = true
                            body_tree:add(f.message_type, "Response")
                        elseif sig_str == call_info.request then
                            body_tree:add(f.message_type, "Request")
                        end
                    end

                    -- Parse remaining message body according to signature
                    if call_info and body_offset < buffer_length then
                        local data_tree = body_tree:add(pkcs11_rpc_proto,
                            body_tvb(body_offset, buffer_length - body_offset),
                            "Message Data")
                        dissect_signature(body_tvb, pktinfo, data_tree, body_offset, sig_str, is_response)
                    end
                end
            end
        end
    end
end

-- Register protocol on default ports
-- For now, register on a custom port for testing
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(11111, pkcs11_rpc_proto)

-- Heuristic dissector for identifying PKCS #11 RPC traffic
local function heur_dissect_pkcs11_rpc(tvbuf, pktinfo, root)
    local pktlen = tvbuf:reported_length_remaining()

    -- Check for version negotiation (single byte 0-2)
    if pktlen == 1 then
        local version = tvbuf(0, 1):uint()
        if version <= 2 then
            pkcs11_rpc_proto.dissector(tvbuf, pktinfo, root)
            return true
        end
    end

    -- Check for valid message header
    if pktlen >= 12 then
        local call_code = tvbuf(0, 4):uint()
        local options_length = tvbuf(4, 4):uint()
        local buffer_length = tvbuf(8, 4):uint()

        -- Sanity checks
        if options_length < 10000 and buffer_length < 1000000 then
            -- Check if total size matches
            if pktlen >= 12 + options_length + buffer_length then
                -- Try to read call ID from body
                if buffer_length >= 4 then
                    local body_offset = 12 + options_length
                    local call_id = tvbuf(body_offset, 4):uint()

                    -- Check if call ID is valid
                    if call_names[call_id] then
                        pkcs11_rpc_proto.dissector(tvbuf, pktinfo, root)
                        return true
                    end
                end
            end
        end
    end

    return false
end

-- Register heuristic dissector
pkcs11_rpc_proto:register_heuristic("tcp", heur_dissect_pkcs11_rpc)

-- VSOCK wrapper dissector that chains with the built-in VSOCK dissector
local vsock_wrapper_proto = Proto("pkcs11_vsock_wrapper", "PKCS11-RPC VSOCK Wrapper")

function vsock_wrapper_proto.dissector(tvbuf, pktinfo, root)
    local pktlen = tvbuf:reported_length_remaining()

    -- First, let the built-in VSOCK dissector handle the headers
    local vsock_dissector = Dissector.get("vsock")
    if vsock_dissector then
        vsock_dissector:call(tvbuf, pktinfo, root)
    end

    -- Now find where the payload starts
    -- VSOCK structure: 32 bytes header + trans_len bytes virtio transport header
    if pktlen > 32 then
        local trans_len = tvbuf(28, 4):le_uint()
        local payload_offset = 32 + trans_len

        if pktlen > payload_offset then
            local payload_tvb = tvbuf(payload_offset):tvb()
            local payload_len = pktlen - payload_offset

            -- Check if this looks like PKCS#11 RPC
            if payload_len >= 12 then
                local call_code = payload_tvb(0, 4):uint()
                local options_length = payload_tvb(4, 4):uint()
                local buffer_length = payload_tvb(8, 4):uint()

                -- Sanity check
                if options_length < 10000 and buffer_length < 1000000 then
                    -- Call our PKCS#11 RPC dissector on just the payload
                    pkcs11_rpc_proto.dissector(payload_tvb, pktinfo, root)
                end
            elseif payload_len == 1 then
                -- Could be version negotiation
                local version = payload_tvb(0, 1):uint()
                if version <= 2 then
                    pkcs11_rpc_proto.dissector(payload_tvb, pktinfo, root)
                end
            end
        end
    end
end

-- Register the wrapper on wtap_encap for vsockmon captures (WTAP_ENCAP_VSOCK = 185)
local wtap_encap = DissectorTable.get("wtap_encap")
if wtap_encap then
    print("Registering PKCS11-RPC wrapper on wtap_encap.185 (VSOCK)")
    wtap_encap:add(185, vsock_wrapper_proto)
end
