#!/usr/bin/env ruby

require "yaml"
require "json"
require "open3"
require "tmpdir"

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

server_dir = File.expand_path("../server", __dir__)
go_env = {
	"GOCACHE" => ENV.fetch("GOCACHE", File.join(Dir.tmpdir, "frp-panel-go-build-cache")),
	"GOMODCACHE" => ENV.fetch("GOMODCACHE", File.join(Dir.tmpdir, "frp-panel-go-module-cache"))
}
stdout, stderr, status = Open3.capture3(go_env, "go", "run", "./cmd/route-manifest", chdir: server_dir)
abort "implementation route manifest failed:\n#{stderr}\n#{stdout}" unless status.success?
implementation_routes = JSON.parse(stdout).map { |route| [route.fetch("method").downcase, route.fetch("path")] }.sort
contract_routes = document["paths"].flat_map do |route, item|
	item.each_with_object([]) do |(method, operation), routes|
		next unless %w[get post put patch delete options head].include?(method)
		routes << [method, route]
	end
end.sort
abort "OpenAPI/implementation route mismatch:\ncontract only: #{contract_routes - implementation_routes}\nimplementation only: #{implementation_routes - contract_routes}" unless contract_routes == implementation_routes

puts "OpenAPI 3.1 contract valid: #{document["paths"].length} paths, #{operation_ids.length} operations; implementation routes match"
