local balancer_resty = require("balancer.resty")
local resty_roundrobin = require("resty.roundrobin")
local util = require("util")
local ck = require("resty.cookie")

local _M = balancer_resty:new({ factory = resty_roundrobin, name = "round_robin_digest" })

-- NOTE:
-- Node refers to the backend that NGINX will forward the
-- request to. Specifically a string, "POD_IP:PORT".
-- Digest is the output of a cryptographic hash function.
-- Cookie is an HTTP header that contains a key:digest pair.
-- https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
-- Arg refers to a URI argument, also known as a query parameter.
-- Digests are used as session IDs in this implementation.

-- NOTE:
-- This implementation forms HTTP sessions via cookie headers
-- and/or URI arguments (aka query param).
-- Not all clients respect HTTP cookie headers and URI args
-- give the ability to ensure all clients respect our load
-- balancing scheme.
-- When necessary new sessions select a backend in a round robin
-- fashion. The digest of a node serves as our session ID.
-- This makes it possible for external applications to 
-- associate an HTTP call to a known backend; given they 
-- know the "IP:PORT" of the desired backend, and the configured
-- cryptographic hash function.
-- If the session ID is not found, round robin will pick an
-- available backend.

function _M.new(self, backend)
  local nodes = util.get_nodes(backend.endpoints)
  local digest_func = util.sha1_digest -- Default hash function
  -- TODO: Allow for annontation based configurations.
  -- Currently GO is not passing the annotations found
  -- on the ingress controller.
  -- They have been commented out and set manually for now.

  -- local digest_func = util.md5_digest
  -- if backend["sessionAffinityConfig"]["cookieSessionAffinity"]["hash"] == "sha1" then
  --   digest_func = util.sha1_digest
  -- end

  -- NOTE: digest_table associates nodes ("IP:PORT"), with their digest value.
  local digest_table = {}
  for id, _ in pairs(nodes) do
    id_hash = digest_func(id)
    digest_table[id_hash] = id
  end

  local o = {
    instance = self.factory:new(nodes),
    -- NOTE: Requires annotation based configuration.
    -- session_key = backend["sessionAffinityConfig"]["cookieSessionAffinity"]["name"] or "route",
    -- cookie_expires = backend["sessionAffinityConfig"]["cookieSessionAffinity"]["expires"],
    -- cookie_max_age = backend["sessionAffinityConfig"]["cookieSessionAffinity"]["maxage"],
    session_key = "route",
    cookie_expires = nil,
    cookie_max_age = nil,
    digest_func = digest_func,
    digest_table = digest_table,
    debug = false,
  }
  setmetatable(o, self)
  self.__index = self
  return o
end

local function log_debug(self, string)
  if self.debug then
    ngx.log(ngx.WARN, string)
  end
end 

local function encrypted_endpoint_string(self, endpoint_string)
  local encrypted, err = self.digest_func(endpoint_string)
  if err ~= nil then
    ngx.log(ngx.ERR, err)
  end

  return encrypted
end

local function set_cookie(self, value)
  local cookie, err = ck:new()
  if not cookie then
    ngx.log(ngx.ERR, err)
  end

  local cookie_data = {
    key = self.session_key,
    value = value,
    path = ngx.var.location_path,
    domain = ngx.var.host,
    httponly = true,
  }

  if self.cookie_expires and self.cookie_expires ~= "" then
      cookie_data.expires = ngx.cookie_time(tonumber(self.cookie_expires))
  end

  if self.cookie_max_age and self.cookie_max_age ~= "" then
    cookie_data.max_age = tonumber(self.cookie_max_age)
  end

  local ok
  ok, err = cookie:set(cookie_data)
  if not ok then
    ngx.log(ngx.ERR, err)
  end
end

local function get_args()
  local args, err = ngx.req.get_uri_args()
  if err == "truncated" then
    ngx.log(ngx.WARN, "too many args in request URI to parse: ", err)
  end
  return args
end

local function set_arg(self, value)
  local args = get_args()
  args[self.session_key] = value
  ngx.req.set_uri_args(args)
end

local function get_arg_value(self)
  local args = get_args()
  if args[self.session_key] == nil or args[self.session_key] == "" then
    -- Key not found
    return nil
  else
    -- Key found in args
    return args[self.session_key]
  end
end

local function get_node(self, digest)
  -- Given a digest / session ID, return the node.
  -- If the digest was not found, return an available node à la round robin.
  local result = self.digest_table[digest]
  if result == nil then
    result = self.instance:find()
  end
  return result
end

function _M.balance(self)
  local cookie, err = ck:new()
  local cookie_digest = cookie:get(self.session_key)
  local arg_digest = get_arg_value(self)
  local endpoint = nil

  if not arg_digest and not cookie_digest then
    -- Case 1: no arg, no cookie
    -- pick random backend node
    -- set cookie
    endpoint = self.instance:find()
    local endpoint_digest = encrypted_endpoint_string(self, endpoint)
    set_cookie(self, endpoint_digest)
    log_debug(self, string.format("Case 1: endpoint, %s digest, %s", endpoint, endpoint_digest))
    return endpoint
  
  elseif arg_digest and not cookie_digest then
    -- Case 2: arg, no cookie
    -- lookup backend node
    endpoint = get_node(self, arg_digest)
    log_debug(self, string.format("Case 2: endpoint, %s digest, %s", endpoint, arg_digest))
    return endpoint
  
  elseif not arg_digest and cookie_digest then
    -- Case 3: no arg, cookie
    -- lookup backend node
    endpoint = get_node(self, cookie_digest)
    log_debug(self, string.format("Case 3: endpoint, %s digest, %s", endpoint, cookie_digest))
    return endpoint
  
  elseif arg_digest and cookie_digest then
    -- Case 4: arg, cookie
    -- lookup backend node by arg_digest
    -- ignore cookie_digest
    endpoint = get_node(self, arg_digest)
    log_debug(self, string.format("Case 4: endpoint, %s digest, %s", endpoint, arg_digest))
    return endpoint
  end

  -- Unexpected state, prevent a crash
  ngx.log(ngx.ERR, "Unexpected state. Using round robin.")
  return self.instance:find()
end

return _M
