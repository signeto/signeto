# Claude Code

1. Add Signeto as an MCP server (`.mcp.json` in the project root):

   ```json
   {
     "mcpServers": {
       "signeto": { "command": "signeto", "args": ["serve"] }
     }
   }
   ```

   For Signeto Cloud, use the remote endpoint and token from the portal instead.

2. Remove the credentials Signeto now fronts: unset `GITHUB_TOKEN` / `GH_TOKEN` in the environment Claude Code runs in, and disable any GitHub MCP server with write scopes. Otherwise the agent can go around the approval.

3. Ask Claude Code to merge a pull request. The call blocks, your phone shows `Merge PR #42 into main on acme/api (squash) at abc1234…`, you approve with Face ID, and the result comes back to the agent. Deny it and the agent receives your reason.

4. Optional, advisory only: a `PreToolUse` hook can ask Signeto to approve shell commands Claude Code runs directly. Signeto can't enforce those (a shell can go around a hook), and labels them *advisory*.
