#!/usr/bin/env ruby

require "json"
require "digest"
require "time"

root = File.expand_path("..", __dir__)
build_dir = File.join(root, "build")

def required_env(name)
  value = ENV[name].to_s.strip
  abort "#{name} is required for a release manifest" if value.empty?
  value
end

def sha256(path)
  abort "release binary is missing: #{path}" unless File.file?(path)
  Digest::SHA256.file(path).hexdigest
end

frps_path = required_env("FRPS_BINARY")
frpc_path = required_env("FRPC_BINARY")
server_artifact = File.join(build_dir, "frp-panel-server")
client_artifact = File.join(build_dir, "frp-panel-client")

manifest = {
  "manifest_version" => "v1",
  "generated_at" => Time.now.utc.iso8601,
  "protocol_version" => "v1",
  "config_schema_version" => "v1",
  "frp_compatibility" => {
    "frps" => { "version" => ENV.fetch("FRPS_VERSION", "0.68.0"), "sha256" => sha256(frps_path) },
    "frpc" => { "version" => ENV.fetch("FRPC_VERSION", "0.68.0"), "sha256" => sha256(frpc_path) }
  },
  "compatibility" => {
    "minimum_client_version" => ENV.fetch("MINIMUM_CLIENT_VERSION", "0.1.0"),
    "latest_client_version" => ENV.fetch("LATEST_CLIENT_VERSION", ENV.fetch("CLIENT_VERSION", "0.1.0")),
    "minimum_frpc_version" => ENV.fetch("MINIMUM_FRPC_VERSION", "0.68.0")
  },
  "panel_versions" => {
    "server" => ENV.fetch("SERVER_VERSION", "0.1.0"),
    "client" => ENV.fetch("CLIENT_VERSION", "0.1.0")
  },
  "panel_artifacts" => {
    "frp-panel-server" => { "sha256" => sha256(server_artifact) },
    "frp-panel-client" => { "sha256" => sha256(client_artifact) }
  },
  "release_policy" => {
    "native_transport_auth" => "file-backed-token-source",
    "plugin_authorization" => "required",
    "runtime_downloads" => false
  }
}

output = File.join(build_dir, "release-manifest.json")
Dir.mkdir(build_dir) unless Dir.exist?(build_dir)
File.write(output, JSON.pretty_generate(manifest) + "\n")
puts "release manifest written to #{output}"
