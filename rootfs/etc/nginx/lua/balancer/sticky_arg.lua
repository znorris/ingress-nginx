local balancer_resty = require("balancer.resty")
local resty_chash = require("resty.chash")
local util = require("util")
local ck = require("resty.cookie")

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

local function set_cookie(self, value)
  local cookie, err = ck:new()
  if not cookie then
    ngx.log(ngx.ERR, err)
  end

  local ok
  ok, err = cookie:set({
    key = self.cookie_name,
    value = value,
    path = ngx.var.location_path,
    domain = ngx.var.host,
    httponly = true,
  })
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
  local cookie_key = cookie:get(self.cookie_name)
  local arg_key = get_session_key(self)
  local tmp_endpoint
  local new_key

  if not arg_key and not cookie_key then
    -- Case 1: no arg, no cookie
    -- pick random backend
    -- set cookie
    tmp_endpoint = pick_random(self.instance)
    new_key = encrypted_endpoint_string(self, tmp_endpoint) 
    set_cookie(self, new_key)
    return self.instance:find(new_key)
  elseif arg_key and not cookie_key then
    -- Case 2: arg, no cookie
    -- lookup backend
    return self.instance:find(arg_key)
  elseif not arg_key and cookie_key then
    -- Case 3: no arg, cookie
    -- lookup backend
    return self.intance:find(cookie_key)
  elseif arg_key and cookie_key then
    -- Case 4: arg, cookie
    -- lookup backend by arg
    return self.instance:find(arg_key)
  end
end

return _M
