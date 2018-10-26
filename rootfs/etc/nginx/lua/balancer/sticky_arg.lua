local balancer_resty = require("balancer.resty")
local resty_chash = require("resty.chash")
local util = require("util")

local _M = balancer_resty:new({ factory = resty_chash, name = "sticky_arg" })

-- TODO: Allow for annontation configurations
-- currently GO is not passing sticky_arg the
-- annotations found on the ingress controller.
-- they have been commented out and set manually.

function _M.new(self, backend)
  local nodes = util.get_nodes(backend.endpoints)
  local digest_func = util.sha1_digest
  -- if backend["sessionAffinityConfig"]["cookieSessionAffinity"]["hash"] == "sha1" then
  --   digest_func = util.sha1_digest
  --   ngx.log(ngx.WARN, "SHA1 in use.")
  -- end

  local o = {
    instance = self.factory:new(nodes),
    -- cookie_name = backend["sessionAffinityConfig"]["cookieSessionAffinity"]["name"] or "route",
    cookie_name = "route",
    digest_func = digest_func,
  }
  setmetatable(o, self)
  self.__index = self
  return o
end

local function encrypted_endpoint_string(self, endpoint_string)
  local encrypted, err = self.digest_func(endpoint_string)
  if err ~= nil then
    ngx.log(ngx.ERR, err)
  end

  return encrypted
end

local function get_args()
  local args, err = ngx.req.get_uri_args()
  if err == "truncated" then
    ngx.log(ngx.WARN, "too many args in request URI to parse: ", err)
  end
  return args
end

local function set_session_key(self, value)
  local args = get_args()
  args[self.cookie_name] = value
  ngx.req.set_uri_args(args)
end

local function get_session_key(self)
  local args = get_args()
  if args[self.cookie_name] == nil or args[self.cookie_name] == "" then
    -- Key not found
    return nil
  else
    -- Key found in args
    return args[self.cookie_name]
  end
end

local function pick_random(instance)
  local index = math.random(instance.npoints)
  return instance:next(index)
end

function _M.balance(self)
  local key = get_session_key(self)
  -- Case 1: Key on request, lookup key
  if not key then
    -- Case 2: No key on request, pick a random backend
    -- Future iterations could optionally return a redirect
    -- which includes a new session in the URI args.
    local tmp_endpoint = pick_random(self.instance)
    key = encrypted_endpoint_string(self, tmp_endpoint)
  end
  return self.instance:find(key)
end

return _M
