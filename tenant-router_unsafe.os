#! VULNERABLE tenant-router — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant routeTenant

let raw = fetch<web>
privileged { routeTenant(raw) }  # tainted -> tool: REJECTED
