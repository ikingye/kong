local utils      = require "kong.tools.utils"
local cjson_safe = require "cjson.safe"
local cjson      = require "cjson"
local ws_server  = require "resty.websocket.server"


local function string_trim(s)
  local _,i1 = s:find("^%s*")
  return s:sub(i1 + 1, s:find("%s*$") - 1)
end


local function string_beginswith(s, prefix)
  return s:sub(1, #prefix) == prefix
end


local function multipart_parse_part_name(part_headers_text)

  local part_headers_split, err = utils.split(part_headers_text, '\\n')

  if err then
    return nil, err
  end

  local m, err, header_text

  for i = 1, #part_headers_split do
    header_text = string_trim(part_headers_split[i])

    if string_beginswith(header_text:lower(), "content-disposition") then
      m, err = ngx.re.match(header_text, 'name="(.*?)"', "oj")

      if err or not m or not m[1] then
        return nil, "could not parse part name. Error: " .. tostring(err)
      end

      return m[1]
    end
  end

  return nil, "could not find part name in: " .. part_headers_text
end


local function multipart_form_parse(body, content_type)
  if not body then
    return nil, 'missing body'
  elseif not content_type then
    return nil, 'missing content-type'
  end

  local m, err = ngx.re.match(content_type, "boundary=(.+)", "oj")
  if err or not m or not m[1] then
    return nil, "could not find boundary in content type " .. content_type ..
                "error: " .. tostring(err)
  end

  local boundary = m[1]

  local parts_split, err = utils.split(body, '--' .. boundary)
  if err then
    return nil, err
  end

  local form = {}

  for i = 1, #parts_split do
    local part = string_trim(parts_split[i])

    if part ~= '' and part ~= '--' then
      local from, to, err = ngx.re.find(part, '^\\r$', 'ojm')
      if err or (not from and not to) then
        return nil, nil, "could not find part body. Error: " .. tostring(err)
      end

      local part_headers = part:sub(1, from - 1)
      local part_value   = part:sub(to + 2, #part) -- +2: trim leading line jump

      local part_name, err = multipart_parse_part_name(part_headers)
      if not part_name then
        return nil, err
      end

      form[part_name] = part_value
    end
  end

  return form
end


local function send_text_response(text, content_type, headers)
  headers       = headers or {}
  content_type  = content_type or "text/plain"

  text = ngx.req.get_method() == "HEAD" and "" or tostring(text)

  ngx.header["X-Powered-By"]   = "mock_upstream"
  ngx.header["Content-Length"] = #text + 1
  ngx.header["Content-Type"]   = content_type

  for header,value in pairs(headers) do
    if type(value) == "table" then
      ngx.header[header] = table.concat(value, ", ")
    else
      ngx.header[header] = value
    end
  end

  return ngx.say(text)
end

local function send_error(status, text)
  ngx.status = status
  send_text_response(text)
  return ngx.exit(200)
end


local function filter_access_by_method(method)
  if ngx.req.get_method() ~= method then
    return send_error(ngx.HTTP_NOT_ALLOWED, "The method is not allowed for the requested URL")
  end
end


local function find_http_credentials(authorization_header)
  if not authorization_header then
    return
  end

  local iterator, iter_err = ngx.re.gmatch(authorization_header,
                                           "\\s*[Bb]asic\\s*(.+)")
  if not iterator then
    ngx.log(ngx.ERR, iter_err)
    return
  end

  local m, err = iterator()

  if err then
    ngx.log(ngx.ERR, err)
    return
  end

  if m and m[1] then
    local decoded_basic = ngx.decode_base64(m[1])

    if decoded_basic then
      local user_pass = utils.split(decoded_basic, ":")
      return user_pass[1], user_pass[2]
    end
  end
end


local function filter_access_by_basic_auth(expected_username,
                                           expected_password)
   local headers = ngx.req.get_headers()

   local username, password =
   find_http_credentials(headers["proxy-authorization"])

   if not username then
     username, password =
     find_http_credentials(headers["authorization"])
   end

   if username ~= expected_username or password ~= expected_password then
     ngx.header["WWW-Authenticate"] = "mock_upstream"
     ngx.header["X-Powered-By"]     = "mock_upstream"
     return ngx.exit(ngx.HTTP_UNAUTHORIZED)
   end
end


local function get_ngx_vars()
  local var = ngx.var
  return {
    uri                = var.uri,
    host               = var.host,
    hostname           = var.hostname,
    https              = var.https,
    scheme             = var.scheme,
    is_args            = var.is_args,
    server_addr        = var.server_addr,
    server_port        = var.server_port,
    server_name        = var.server_name,
    server_protocol    = var.server_protocol,
    remote_addr        = var.remote_addr,
    remote_port        = var.remote_port,
    realip_remote_addr = var.realip_remote_addr,
    realip_remote_port = var.realip_remote_port,
    binary_remote_addr = var.binary_remote_addr,
    request            = var.request,
    request_uri        = var.request_uri,
    request_time       = var.request_time,
    request_length     = var.request_length,
    request_method     = var.request_method,
    bytes_received     = var.bytes_received,
    ssl_server_name    = var.ssl_server_name or "no SNI",
  }
end


local function get_body_data()
  local req   = ngx.req
  local data  = req.get_body_data()
  if data then
    return data
  end

  local file_path = req.get_body_file()
  if file_path then
    local file = io.open(file_path, "r")
    data       = file:read("*all")
    file:close()
    return data
  end

  return ""
end


local function get_default_json_response()
  local req                = ngx.req
  local headers            = req.get_headers(0)
  local data, form, params = "", {}, cjson_safe.null
  local ct                 = headers["Content-Type"]
  local err
  if ct then
    req.read_body()
    if ct:find("application/x-www-form-urlencoded", nil, true) then
      form = req.get_post_args()

    elseif ct:find("multipart/form-data", nil, true) then

      form, err = multipart_form_parse(get_body_data(), ct)
      if err then
        return send_error(ngx.HTTP_BAD_REQUEST,
                          "could not find multipart boundary. Error: " .. tostring(err))
      end

    elseif ct:find("application/json", nil, true) then
      data = get_body_data()
      -- ignore decoding errors
      params = cjson_safe.decode(data) or cjson_safe.null
    end
  end

  return {
    args    = ngx.req.get_uri_args(),
    data    = data,
    form    = form,
    headers = headers,
    params  = params,
    url     = string.format("%s://%s%s", ngx.var.scheme,
                            ngx.var.host, ngx.var.request_uri),
    vars    = get_ngx_vars(),
  }
end


local function send_default_json_response(extra_fields, response_headers)
  local tbl = utils.table_merge(get_default_json_response(), extra_fields)
  return send_text_response(cjson.encode(tbl),
                            "application/json", response_headers)
end


local function serve_web_sockets()
  local wb, err = ws_server:new({
    timeout         = 5000,
    max_payload_len = 65535,
  })

  if not wb then
    ngx.log(ngx.ERR, "failed to open websocket: ", err)
    return ngx.exit(444)
  end

  while true do
    local data, typ, err = wb:recv_frame()
    if wb.fatal then
      ngx.log(ngx.ERR, "failed to receive frame: ", err)
      return ngx.exit(444)
    end

    if data then
      if typ == "close" then
        break
      end

      if typ == "ping" then
        local bytes, err = wb:send_pong(data)
        if not bytes then
          ngx.log(ngx.ERR, "failed to send pong: ", err)
          return ngx.exit(444)
        end

      elseif typ == "pong" then
        ngx.log(ngx.INFO, "client ponged")

      elseif typ == "text" then
        local bytes, err = wb:send_text(data)
        if not bytes then
          ngx.log(ngx.ERR, "failed to send text: ", err)
          return ngx.exit(444)
        end
      end

    else
      local bytes, err = wb:send_ping()
      if not bytes then
        ngx.log(ngx.ERR, "failed to send ping: ", err)
        return ngx.exit(444)
      end
    end
  end

  wb:send_close()
end


return {
  filter_access_by_method     = filter_access_by_method,
  filter_access_by_basic_auth = filter_access_by_basic_auth,
  send_text_response          = send_text_response,
  send_default_json_response  = send_default_json_response,
  serve_web_sockets           = serve_web_sockets,
}
