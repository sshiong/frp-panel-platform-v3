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
  begin
    Time.iso8601(document.fetch("generated_at").to_s)
  rescue KeyError, ArgumentError
    abort("#{id} runner evidence generated_at must be an ISO-8601 timestamp")
  end

  environment = document["environment"]
  abort("#{id} runner evidence environment must be an object") unless environment.is_a?(Hash)
  if id == "cloudflare"
    abort("#{id} runner evidence provider mismatch") unless environment["provider"] == provider
    abort("#{id} runner evidence zone_name must be non-empty") unless environment["zone_name"].is_a?(String) && !environment["zone_name"].strip.empty?
    abort("#{id} runner evidence record_name must be non-empty") unless environment["record_name"].is_a?(String) && !environment["record_name"].strip.empty?
    abort("#{id} runner evidence must confirm zone_id presence") unless environment["zone_id_present"] == true
  else
    abort("#{id} runner evidence provider mismatch") unless environment["ca"] == provider
    %w[domain zone].each do |field|
      abort("#{id} runner evidence #{field} must be non-empty") unless environment[field].is_a?(String) && !environment[field].strip.empty?
    end
  end

  steps = document["steps"]
  abort("#{id} runner evidence steps must be a non-empty array") unless steps.is_a?(Array) && !steps.empty?
  steps.each_with_index do |step, index|
    abort("#{id} runner evidence step #{index} must be an object") unless step.is_a?(Hash)
    abort("#{id} runner evidence step #{index} must have a non-empty id") unless step["id"].is_a?(String) && !step["id"].strip.empty?
    abort("#{id} runner evidence step #{index} must be passed") unless step["status"] == "passed"
    begin
      Time.iso8601(step.fetch("executed_at").to_s)
    rescue KeyError, ArgumentError
      abort("#{id} runner evidence step #{index} executed_at must be an ISO-8601 timestamp")
    end
  end
  request_ids = document["request_ids"]
  abort("#{id} runner evidence request_ids must be an array") unless request_ids.is_a?(Array)
  abort("#{id} runner evidence must not contain an error") if document.key?("error") && !document["error"].nil?
  abort("#{id} runner evidence cleanup failed") if document.key?("cleanup_error") && !document["cleanup_error"].nil?
  result[id] = {
    "status" => document["status"],
    "commit" => document["commit"],
    "generated_at" => document["generated_at"],
    "environment" => environment,
    "steps" => document["steps"].map { |step| step.is_a?(Hash) ? step["id"] : step },
    "request_ids" => request_ids,
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
