-- Copyright (C) Yichun Zhang (agentzh)


local ffi = require "ffi"
local base = require "resty.core.base"


local C = ffi.C
local ffi_str = ffi.string
local errmsg = base.get_errmsg_ptr()
local FFI_OK = base.FFI_OK
local FFI_ERROR = base.FFI_ERROR
local int_out = ffi.new("int[1]")
local getfenv = getfenv
local error = error
local type = type
local tonumber = tonumber


ffi.cdef[[
int ngx_http_lua_ffi_body_filter_skip(ngx_http_request_t *r, int skip, char **err);
]]


local _M = { version = base.version }


function _M.skip_body_filter(skip)
    local r = getfenv(0).__ngx_req
    if not r then
        return error("no request found")
    end

    local rc
    if not skip then
        rc = C.ngx_http_lua_ffi_body_filter_skip(r, 0, errmsg)
    else
        rc = C.ngx_http_lua_ffi_body_filter_skip(r, 1, errmsg)
    end

    if rc == FFI_OK then
        return true
    end

    return nil, ffi_str(errmsg[0])
end


return _M
