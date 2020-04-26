-- Copyright (C) Yichun Zhang (agentzh)


local base = require "resty.core.base"
base.allows_subsystem('http', 'stream')


local ffi = require "ffi"
local C = ffi.C
local ffi_str = ffi.string
local ffi_new = ffi.new
local errmsg = base.get_errmsg_ptr()
local FFI_OK = base.FFI_OK
local FFI_ERROR = base.FFI_ERROR
local int_out = ffi.new("int[1]")
local get_request = base.get_request
local error = error
local type = type
local tonumber = tonumber
local max = math.max
local subsystem = ngx.config.subsystem
local pargs
local ngx_lua_ffi_balancer_set_current_peer
local ngx_lua_ffi_balancer_set_more_tries
local ngx_lua_ffi_balancer_get_last_failure
local ngx_lua_ffi_balancer_set_timeouts -- used by both stream and http


if subsystem == 'http' then
    ffi.cdef[[
    typedef struct {
        const unsigned char  *name_data;
        size_t                name_len;
        uintptr_t             max_cached;
        uintptr_t             requests;
        uintptr_t             timeout;
    } ngx_http_lua_ffi_keepalive_args_t;

    int ngx_http_lua_ffi_balancer_set_current_peer(ngx_http_request_t *r,
        const unsigned char *addr, size_t addr_len, int port,
        ngx_http_lua_ffi_keepalive_args_t *args, char **err);

    int ngx_http_lua_ffi_balancer_set_more_tries(ngx_http_request_t *r,
        int count, char **err);

    int ngx_http_lua_ffi_balancer_get_last_failure(ngx_http_request_t *r,
        int *status, char **err);

    int ngx_http_lua_ffi_balancer_set_timeouts(ngx_http_request_t *r,
        long connect_timeout, long send_timeout,
        long read_timeout, char **err);
    ]]

    pargs = ffi_new("ngx_http_lua_ffi_keepalive_args_t [1]")

    ngx_lua_ffi_balancer_set_current_peer =
        C.ngx_http_lua_ffi_balancer_set_current_peer

    ngx_lua_ffi_balancer_set_more_tries =
        C.ngx_http_lua_ffi_balancer_set_more_tries

    ngx_lua_ffi_balancer_get_last_failure =
        C.ngx_http_lua_ffi_balancer_get_last_failure

    ngx_lua_ffi_balancer_set_timeouts =
        C.ngx_http_lua_ffi_balancer_set_timeouts

elseif subsystem == 'stream' then
    ffi.cdef[[
    int ngx_stream_lua_ffi_balancer_set_current_peer(
        ngx_stream_lua_request_t *r,
        const unsigned char *addr, size_t addr_len, int port, char **err);

    int ngx_stream_lua_ffi_balancer_set_more_tries(ngx_stream_lua_request_t *r,
        int count, char **err);

    int ngx_stream_lua_ffi_balancer_get_last_failure(
        ngx_stream_lua_request_t *r, int *status, char **err);

    int ngx_stream_lua_ffi_balancer_set_timeouts(ngx_stream_lua_request_t *r,
        long connect_timeout, long timeout, char **err);
    ]]

    ngx_lua_ffi_balancer_set_current_peer =
        C.ngx_stream_lua_ffi_balancer_set_current_peer

    ngx_lua_ffi_balancer_set_more_tries =
        C.ngx_stream_lua_ffi_balancer_set_more_tries

    ngx_lua_ffi_balancer_get_last_failure =
        C.ngx_stream_lua_ffi_balancer_get_last_failure

    local ngx_stream_lua_ffi_balancer_set_timeouts =
        C.ngx_stream_lua_ffi_balancer_set_timeouts

    ngx_lua_ffi_balancer_set_timeouts =
        function(r, connect_timeout, send_timeout, read_timeout, err)
            local timeout = max(send_timeout, read_timeout)

            return ngx_stream_lua_ffi_balancer_set_timeouts(r, connect_timeout,
                                                            timeout, err)
        end

else
    error("unknown subsystem: " .. subsystem)
end


local peer_state_names = {
    [1] = "keepalive",
    [2] = "next",
    [4] = "failed",
}


local _M = { version = base.version }


local function check_keepalive_args(opt)
    if not opt then
        return
    end

    if type(opt) ~= "table" then
        error("bad opt arg: table expected, got " .. type(opt), 2)
    end

    local pool = opt.pool
    local max_cached = opt.max_cached
    local requests = opt.requests
    local timeout = opt.timeout

    if type(pool) ~= "string" then
        error("bad pool arg: string expected, got " .. type(pool), 2)
    end

    if type(opt.max_cached) ~= "number" then
        error("bad max_cached", 2)
    end

    if type(opt.requests) ~= "number" or opt.requests <= 0 then
        requests = 100
    end

    if type(opt.timeout) ~= "number" or opt.timeout <= 0 then
        timeout = 60000
    end

    pargs[0].name_data = pool
    pargs[0].name_len = #(pool)
    pargs[0].max_cached = max_cached
    pargs[0].requests = requests
    pargs[0].timeout = timeout

    return pargs
end


function _M.set_current_peer(addr, port, opt)
    local r = get_request()
    if not r then
        error("no request found")
    end

    if not port then
        port = 0
    elseif type(port) ~= "number" then
        port = tonumber(port)
    end

    local rc

    if subsystem == 'http' then
        local p = check_keepalive_args(opt)
        rc = C.ngx_http_lua_ffi_balancer_set_current_peer(r, addr, #addr,
                                                          port, p, errmsg)
    else
        rc = C.ngx_stream_lua_ffi_balancer_set_current_peer(r, addr, #addr, port,
                                                            errmsg)
    end

    if rc == FFI_OK then
        return true
    end

    return nil, ffi_str(errmsg[0])
end


function _M.set_more_tries(count)
    local r = get_request()
    if not r then
        error("no request found")
    end

    local rc = ngx_lua_ffi_balancer_set_more_tries(r, count, errmsg)
    if rc == FFI_OK then
        if errmsg[0] == nil then
            return true
        end
        return true, ffi_str(errmsg[0])  -- return the warning
    end

    return nil, ffi_str(errmsg[0])
end


function _M.get_last_failure()
    local r = get_request()
    if not r then
        error("no request found")
    end

    local state = ngx_lua_ffi_balancer_get_last_failure(r, int_out, errmsg)

    if state == 0 then
        return nil
    end

    if state == FFI_ERROR then
        return nil, nil, ffi_str(errmsg[0])
    end

    return peer_state_names[state] or "unknown", int_out[0]
end


function _M.set_timeouts(connect_timeout, send_timeout, read_timeout)
    local r = get_request()
    if not r then
        error("no request found")
    end

    if not connect_timeout then
        connect_timeout = 0
    elseif type(connect_timeout) ~= "number" or connect_timeout <= 0 then
        error("bad connect timeout", 2)
    else
        connect_timeout = connect_timeout * 1000
    end

    if not send_timeout then
        send_timeout = 0
    elseif type(send_timeout) ~= "number" or send_timeout <= 0 then
        error("bad send timeout", 2)
    else
        send_timeout = send_timeout * 1000
    end

    if not read_timeout then
        read_timeout = 0
    elseif type(read_timeout) ~= "number" or read_timeout <= 0 then
        error("bad read timeout", 2)
    else
        read_timeout = read_timeout * 1000
    end

    local rc

    rc = ngx_lua_ffi_balancer_set_timeouts(r, connect_timeout,
                                           send_timeout, read_timeout,
                                           errmsg)

    if rc == FFI_OK then
        return true
    end

    return false, ffi_str(errmsg[0])
end


return _M
