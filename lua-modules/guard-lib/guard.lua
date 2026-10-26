-- guard-lib: the demo guard's client, as a Lua module for the Nano Gateway.
--
-- MOCK, for discussion: not deployed. It shows how the logic would live
-- outside the policies, in git, owned by whoever owns the guard.
--
-- How it gets to the gateway:
--   this file → ConfigMap guard-lib-lua (kustomization.yaml next door)
--             → Runtime spec.modules.guard-lib (runtime-modules-patch.yaml)
--             → require() in the LuaScript shims in ../../api-days-workshop
--
-- The gateway cannot fetch code at run time: its Lua sandbox removes load,
-- loadstring, loadfile and dofile. Modules mounted from ConfigMaps are the
-- supported way to keep code outside a policy.
--
-- Rules for writing a module here:
--   * Keep no per-request state at module level. The runtime caches a module
--     per worker and resets the tables it returns between transactions, so
--     everything a call needs is passed in (the transaction context, options).
--   * The policy keeps the actions. A module cannot call the guard on its own;
--     it runs the Invoke and Throw policies the shim's LuaScript names in its
--     `actions` map (here "inspect" and "deny"), so the HTTP call, TLS,
--     timeouts and telemetry stay declarative policies.
--
-- Unverified: the context methods (get, set, get_message, create_message,
-- run_action), the header get/set calls and how bodies are read and written.
-- The names come from the Nano runtime; their signatures are guesses.

local M = {}

-- Defaults; a shim can override any of them: guard.check_call(context, {agent = "executor"})
local DEFAULTS = {
  agent         = "researcher",   -- who the guard judges; later from extractIdentity
  server        = "docs",         -- prefix for the tool name, as in policy.yaml (docs.read_document)
  inspect       = "inspect",      -- action name of the Invoke to the guard
  deny          = "deny",         -- action name of the Throw (403)
  apikey_var    = "guard.apikey", -- context variable holding the guard key (a distributed variable)
}

local function options(opts)
  local o = {}
  for k, v in pairs(DEFAULTS) do o[k] = v end
  for k, v in pairs(opts or {}) do o[k] = v end
  return o
end

-- Build the guard_request message, run the Invoke, return the decoded verdict.
-- The same question the guard's MCP proxy asks inside the demo today.
local function ask(context, o, payload)
  local check = context:create_message("guard_request")
  check.headers:set("content-type", "application/json")
  check.headers:set("apikey", context:get(o.apikey_var))
  check.body = json.encode(payload)
  context:run_action(o.inspect)                       -- Invoke → guard /v1/inspect

  local verdict = json.decode(tostring(context:get_message("guard_response").body))
  context:set("guard.decision_id", verdict.decision_id)  -- for telemetry and the error text
  return verdict
end

-- Before MCPInvoke: may this agent call this tool with these arguments?
-- (allowlist and argument rules). A block ends the request with a 403.
function M.check_call(context, opts)
  local o    = options(opts)
  local req  = context:get_message("request")
  local call = json.decode(tostring(req.body))        -- JSON-RPC tools/call

  local verdict = ask(context, o, {
    stage     = "tool_call",
    agent     = o.agent,
    tool      = o.server .. "." .. call.params.name,
    arguments = call.params.arguments,
    trace     = req.headers:get("traceparent"),       -- joins the demo's trace
  })
  if verdict.verdict == "block" then
    context:set("guard.reason", verdict.reason)
    console.warn("guard blocked %s: %s", call.params.name, verdict.reason)
    context:run_action(o.deny)                        -- Throw 403
  end
  return verdict
end

-- After MCPInvoke: does the result carry an injection? A block doesn't fail
-- the call: the result is replaced with a tool error the agent can reason
-- about, exactly as the guard's MCP proxy answers today.
function M.check_result(context, opts)
  local o      = options(opts)
  local res    = context:get_message("response")
  local result = json.decode(tostring(res.body))      -- JSON-RPC result

  local verdict = ask(context, o, {
    stage   = "tool_result",                          -- injection classifier
    agent   = o.agent,
    content = result.result.content,
  })
  if verdict.verdict == "block" then
    result.result = {
      isError = true,
      content = { { type = "text",
        text = "Content quarantined by policy (decision " .. verdict.decision_id .. ")" } },
    }
    res.body = json.encode(result)
  end
  return verdict
end

return M
