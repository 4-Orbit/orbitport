// Resource is a trusted alias for the server-configured test repository.
permit (
  principal == Agent::"developer-agent",
  action == Action::"github.issue.create",
  resource == Repository::"designated-test-repo"
);
