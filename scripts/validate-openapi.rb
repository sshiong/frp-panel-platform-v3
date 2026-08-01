#!/usr/bin/env ruby

require "yaml"

path = File.expand_path("../contracts/openapi.yaml", __dir__)
document = YAML.load_file(path)
abort "OpenAPI must be 3.1.0" unless document["openapi"] == "3.1.0"
abort "OpenAPI paths are missing" unless document["paths"].is_a?(Hash)
abort "OpenAPI contract has too few paths" if document["paths"].length < 20

operation_ids = []
document["paths"].each do |route, item|
  abort "invalid path #{route}" unless route.start_with?("/")
  item.each do |method, operation|
    next unless %w[get post put patch delete options head].include?(method)
    abort "#{route} #{method} is missing operationId" unless operation.is_a?(Hash) && operation["operationId"]
    operation_ids << operation["operationId"]
  end
end
abort "duplicate operationId" unless operation_ids.uniq.length == operation_ids.length

ws = document["x-websocket"]&.find { |entry| entry["path"] == "/api/v1/ws" }
abort "WebSocket protocol metadata is missing" unless ws && ws["protocol_version"] == "v1"

puts "OpenAPI 3.1 contract valid: #{document["paths"].length} paths, #{operation_ids.length} operations"
