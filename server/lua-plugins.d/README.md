# Nauthilus Lua Plugins

This directory contains Lua plugins for the Nauthilus authentication system. These plugins extend and customize the functionality of Nauthilus, allowing for flexible authentication workflows, security features, and integrations with external systems.

## Plugin Directory Structure

The plugins are organized into subdirectories based on their purpose and when they are executed in the authentication workflow:

### [actions](./actions/)
Action plugins are executed in response to authentication events and can perform various tasks such as tracking failed logins, implementing dynamic security responses, and sending notifications.

### [backend](./backend/)
Backend plugins provide integration with external data sources for user authentication, account management, and credential verification.

### [features](./features/)
Feature plugins extend the core functionality of Nauthilus by adding new capabilities, integrations, or advanced security features.

### [filters](./filters/)
Filter plugins are executed during the authentication process to analyze, validate, or modify authentication requests before they are processed.

### [hooks](./hooks/)
Hook plugins are executed at specific points in the system's lifecycle or in response to specific events, allowing for custom processing, administrative functions, and integration with external systems.

### [init](./init/)
Initialization plugins are executed when the system starts up, setting up required components, registering services, and preparing the environment for other plugins.

### [share](./share/)
Shared utility modules provide common functions and utilities that can be used by other plugins throughout the system, promoting code reuse and consistency.

## Plugin Execution Flow

The Nauthilus authentication system executes plugins in a specific order during the authentication process:

1. **Initialization**: When the system starts, all plugins in the `init` directory are executed to set up the environment.

2. **Authentication Request**: When an authentication request is received:
   - **Filters**: Filter plugins are executed to validate and potentially modify the request.
   - **Features**: Feature plugins are executed to add additional functionality to the authentication process.
   - **Backend**: The appropriate backend plugin is used to verify credentials and retrieve user information.
   - **Actions**: After authentication (success or failure), action plugins are executed to perform post-authentication tasks.

3. **Hooks**: Hook plugins can be executed at various points in the system's lifecycle, either on a schedule or in response to specific events.

## Creating Custom Plugins

Each subdirectory contains a README.md file with detailed information about the plugins in that directory and how to create custom plugins of that type. In general, to create a custom plugin:

1. Identify the appropriate plugin type (action, filter, feature, etc.) based on when and how you want your plugin to be executed.
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

For more detailed information about the Nauthilus Lua API and plugin development, refer to the [Nauthilus documentation](https://nauthilus.io/docs/lua-api/).
