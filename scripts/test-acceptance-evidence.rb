#!/usr/bin/env ruby

require "json"
require "rbconfig"
require "tmpdir"

ROOT = File.expand_path("..", __dir__)
SCRIPT = File.join(ROOT, "scripts", "acceptance-evidence.rb")

Dir.mktmpdir("acceptance-evidence") do |directory|
  output = File.join(directory, "acceptance-evidence.json")
  artifact_dir = File.join(directory, "items")
  command = [RbConfig.ruby, SCRIPT, "--output", output, "--artifact-dir", artifact_dir]
  abort("acceptance evidence generator failed") unless system(*command)

  document = JSON.parse(File.read(output))
  abort("acceptance evidence status must remain blocked") unless document["status"] == "blocked"
  items = document.fetch("items")
  abort("expected 142 acceptance records, got #{items.length}") unless items.length == 142
  abort("acceptance IDs are not unique") unless items.map { |item| item.fetch("id") }.uniq.length == items.length

  required = %w[environment steps expected actual artifacts operator executed_at]
  items.each do |item|
    missing = required.reject { |field| item.key?(field) }
    abort("#{item["id"]} missing fields: #{missing.join(", ")}") unless missing.empty?
    logs = item.fetch("artifacts").fetch("logs")
    abort("#{item["id"]} has no traceability log") if logs.empty?
    log_path = File.join(directory, "items", "#{item.fetch("id")}.log")
    abort("missing log for #{item["id"]}") unless File.file?(log_path)
    abort("log for #{item["id"]} is not mode 0600") unless (File.stat(log_path).mode & 0o777) == 0o600
  end

  abort("index is not mode 0600") unless (File.stat(output).mode & 0o777) == 0o600
end

puts "acceptance evidence index schema checks passed"
