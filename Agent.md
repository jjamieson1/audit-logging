# Logging agent

## Description

This agent can run on a server, and monitors the logging of an application, as new logs are added to the file based log the agent is monitoring, the agent will copy that entry and send it to the logging service over HTTP REST.

## Requirments

- Written in Golang
- Compiles to a runtime on a server at start
- Is configured by a file that allows the user to:
  - set the destination log REST API
  - set the application name so it can use it wrapping the log data in the request to the log service
  - set the file path to where the log exists
  - set the name of the string that specifies the timestamp
- uses the timestamp from the log it is monitoring to send sequential logs to the log service
- Ensures the same log is not set twice, and that logs are not missed if the agent crashes or does not start.
- The agent ensures that there is integrity between the local log and log created on the log service.
