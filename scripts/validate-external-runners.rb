#!/usr/bin/env ruby

require "fileutils"
require "json"
require "optparse"
require "time"

options = {}
OptionParser.new do |parser|
  parser.on("--cloudflare PATH") { |value| options[:cloudflare] = value }
  parser.on("--acme PATH") { |value| options[:acme] = value }
  parser.on("--output PATH") { |value| options[:output] = value }
end.parse!

required = %i[cloudflare acme output]
missing = required.reject { |key| options[key] }
abort("missing options: #{missing.join(", ")}") unless missing.empty?

expected_commit = ENV.fetch("FRP_ACCEPTANCE_EXPECTED_COMMIT")
unless expected_commit.match?(/\A[0-9a-f]{40}\z/)
  abort("FRP_ACCEPTANCE_EXPECTED_COMMIT must be a 40-character commit SHA")
end

repository = "sshiong/frp-panel-platform-v3"
runner_specs = {
  "cloudflare" => [options[:cloudflare], "Cloudflare Sandbox"],
  "acme" => [options[:acme], "ACME Staging"]
}

parsed = runner_specs.each_with_object({}) do |(id, (path, provider)), result|
  document = JSON.parse(File.read(path))
  abort("#{id} runner evidence must be a JSON object") unless document.is_a?(Hash)
  abort("#{id} runner evidence schema_version must be v1") unless document["schema_version"] == "v1"
  abort("#{id} runner evidence repository mismatch") unless document["repository"] == repository
  abort("#{id} runner evidence commit mismatch") unless document["commit"] == expected_commit
  abort("#{id} runner evidence status must be passed") unless document["status"] == "passed"
  abort("#{id} runner evidence provider mismatch") unless document.dig("environment", "provider") == provider || document.dig("environment", "ca") == provider
  abort("#{id} runner evidence steps must be a non-empty array") unless document["steps"].is_a?(Array) && !document["steps"].empty?
  result[id] = {
    "status" => document["status"],
    "commit" => document["commit"],
    "steps" => document["steps"].map { |step| step.is_a?(Hash) ? step["id"] : step },
    "source" => path
  }
rescue Errno::ENOENT => e
  abort("#{id} runner evidence is missing: #{e.message}")
rescue JSON::ParserError => e
  abort("#{id} runner evidence is not valid JSON: #{e.message}")
end

document = {
  "schema_version" => "v1",
  "status" => "passed",
  "repository" => repository,
  "commit" => expected_commit,
  "generated_at" => Time.now.utc.iso8601(6),
  "runners" => parsed
}
output = File.expand_path(options[:output])
FileUtils.mkdir_p(File.dirname(output), mode: 0o700)
File.open(output, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |file|
  file.write(JSON.pretty_generate(document))
  file.write("\n")
end
puts "external runner evidence valid: #{output}"
