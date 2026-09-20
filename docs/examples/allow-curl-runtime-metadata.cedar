// Runtime loaders and Node inspect file metadata before reading/executing.
// This permits stat-family observations, not chmod/chown/timestamp changes.
permit(
  principal == Cleopatr::AgentSession::"curl-agent",
  action == Cleopatr::Action::"file.metadata",
  resource is Cleopatr::File
)
when { context has operation && context.operation == "stat" };
