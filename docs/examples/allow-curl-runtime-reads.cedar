permit(
  principal == Cleopatr::AgentSession::"curl-agent",
  action == Cleopatr::Action::"file.read",
  resource is Cleopatr::File
)
when {
  ["/usr", "/bin", "/lib", "/etc", "/dev"].contains(resource.locator)
};
