permit(
  principal == Cleopatr::AgentSession::"curl-agent",
  action == Cleopatr::Action::"process.execute",
  resource is Cleopatr::Process
)
when {
  [
    "/workspace/tests/curl-agent.js",
    "/usr/bin/env",
    "/usr/local/bin/node",
    "/usr/bin/curl",
    "/lib/ld-linux-aarch64.so.1"
  ].contains(resource.locator)
};
