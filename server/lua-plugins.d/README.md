# Nauthilus Lua Plugins

This directory contains Lua plugins for the Nauthilus authentication system. These plugins extend and customize the functionality of Nauthilus, allowing for flexible authentication workflows, security features, and integrations with external systems.

## Plugin Directory Structure

The plugins are organized into subdirectories based on their purpose and when they are executed in the authentication workflow:

### [actions](./actions/)
Action plugins are executed in response to authentication events and can perform various tasks such as tracking failed logins, implementing dynamic security responses, and sending notifications.

### [backend](./backend/)
Backend plugins provide integration with external data sources for user authentication, account management, and credential verification.

### [environment](./environment/)
Lua environment source plugins collect pre-authentication signals and can trigger environment-derived decisions.

### [subject](./subject/)
Lua subject source plugins run with subject context and can emit subject-derived policy attributes.

### [hooks](./hooks/)
Hook plugins are executed at specific points in the system's lifecycle or in response to specific events, allowing for custom processing, administrative functions, and integration with external systems.

### [init](./init/)
Initialization plugins are executed when the system starts up, setting up required components, registering services, and preparing the environment for other plugins.

### [policy](./policy/)
Policy registry scripts register the custom Lua-owned attributes emitted by bundled plugins.

### [share](./share/)
Shared utility modules provide common functions and utilities that can be used by other plugins throughout the system, promoting code reuse and consistency.

## Plugin Execution Flow

The policy decision layer owns the effective execution plan for Lua environment and subject attribute sources. A configured
`auth.policy.checks` entry with type `lua.environment` or `lua.subject` selects the script by `config_ref`, applies its
`after` scheduling dependencies, and records the script result as policy attributes:

- Lua environment sources: `auth.lua.environment.<name>.triggered`, `auth.lua.environment.<name>.abort`, and
  `auth.lua.environment.<name>.error`
- Lua subject sources: `auth.lua.subject.<name>.rejected` and `auth.lua.subject.<name>.error`
- Public status messages are attached as the `status_message` detail on triggered or rejected script attributes.

The bundled policy-aware plugins use `share/nauthilus_policy_facts.lua` to emit custom Lua-owned attributes such as
`lua.plugin.blocklist.matched` or `lua.plugin.geoip.rejected` into the request-local policy report. These attributes are
registered by `policy/registry.lua` and must be made available through `auth.policy.registry_scripts` before emitted
plugin attributes can be used by policy rules. Missing or mistyped registrations fail at runtime instead of becoming
silent facts.

The helper still stores the same values under `nauthilus_context.context_get("policy_facts")` for later Lua actions.
Use `emit`/`emit_many` for internal policy attributes, `emit_public`/`emit_many_public` when the value should also be
copied to custom logs, and `status_message` for a normal Nauthilus status message plus a policy-visible message
attribute.

The Nauthilus authentication system executes plugins in a specific order during the authentication process:

1. **Initialization**: When the system starts, all plugins in the `init` directory are executed to set up the environment.

2. **Authentication Request**: When an authentication request is received:
   - **Environment sources**: Lua environment sources run in `pre_auth` when selected by policy.
   - **Backend**: The appropriate backend plugin is used to verify credentials and retrieve user information.
   - **Subject sources**: Lua subject sources run in `subject_analysis` after backend facts are available.
   - **Actions**: Lua actions are configured as `auth.policy.obligation_targets.lua.actions` and run only when selected by policy obligations.

3. **Hooks**: Hook plugins can be executed at various points in the system's lifecycle, either on a schedule or in response to specific events.

## Creating Custom Plugins

Each subdirectory contains a README.md file with detailed information about the plugins in that directory and how to create custom plugins of that type. In general, to create a custom plugin:

1. Identify the appropriate plugin type (action, subject source, environment source, etc.) based on when and how you want your plugin to be executed.
2. Create a new Lua file in the corresponding subdirectory.
3. Implement the required function for that plugin type (e.g., `nauthilus_call_action` for action plugins).
4. Use the shared utility modules and Nauthilus API to implement your plugin's functionality.

## Plugin Development Best Practices

1. **Error Handling**: Use `nauthilus_util.if_error_raise(err)` to handle errors properly.
2. **Logging**: Use `nauthilus_util.print_result()` for consistent logging.
3. **Performance**: Be mindful of performance, especially for plugins that are executed on every authentication request.
4. **Security**: Validate all inputs and be careful with external integrations.
5. **Documentation**: Include detailed comments in your code explaining what the plugin does and how it works.
6. **Testing**: Test your plugins thoroughly before deploying them in production.

## Further Documentation

For more detailed information about the Nauthilus Lua API and plugin development, refer to the [Nauthilus documentation](https://nauthilus.org/docs/lua-api/).
