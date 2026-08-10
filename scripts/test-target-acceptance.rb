#!/usr/bin/env ruby

require_relative "target-acceptance"
require "tmpdir"

valid_step = {
  "id" => "fixture",
  "status" => "blocked",
  "environment" => { "host_os" => "linux" },
  "steps" => ["inspect target"],
  "expected" => "pass",
  "actual" => "blocked without target host",
  "artifacts" => { "logs" => ["output/target-acceptance/fixture.log"], "screenshots" => [], "request_ids" => [] },
  "operator" => "tester",
  "executed_at" => "2026-08-10T00:00:00Z"
}
valid_report = {
  "schema_version" => "v1",
  "kind" => "target-acceptance-report",
  "status" => "blocked",
  "repository" => TargetAcceptance::REPOSITORY,
  "commit" => "0" * 40,
  "generated_at" => "2026-08-10T00:00:00Z",
  "operator" => "tester",
  "environment" => { "host_os" => "linux" },
  "constraints" => { "os" => "Linux", "cpu" => "2 vCPU", "memory" => "2 GiB", "memory_swap" => "2 GiB", "sqlite" => "WAL" },
  "steps" => [valid_step]
}

abort("valid blocked target report was rejected") unless TargetAcceptance.validate!(valid_report).empty?

invalid_report = Marshal.load(Marshal.dump(valid_report))
invalid_report["status"] = "passed"
abort("incomplete target report was accepted as passed") unless TargetAcceptance.validate!(invalid_report).any? { |error| error.include?("status must remain blocked") }

missing_constraint = Marshal.load(Marshal.dump(valid_report))
missing_constraint["constraints"]["memory"] = "4 GiB"
abort("wrong target memory constraint was accepted") unless TargetAcceptance.validate!(missing_constraint).any? { |error| error.include?("2 vCPU/2 GiB") }

Dir.mktmpdir("target-acceptance-artifacts") do |directory|
  collector = TargetAcceptance.new(artifact_dir: directory)
  log_path = collector.send(:write_log, "fixture", "raw command output")
  collector.write(valid_report, output: File.join(directory, "report.json"))
  raw_log = File.join(directory, "fixture.log")
  abort("target acceptance raw log was overwritten") unless File.read(raw_log).include?("raw command output")
  abort("target acceptance raw log mode is not 0600") unless (File.stat(raw_log).mode & 0o777) == 0o600
  abort("target acceptance report mode is not 0600") unless (File.stat(File.join(directory, "report.json")).mode & 0o777) == 0o600
  abort("target acceptance artifact path was not relative") unless log_path == "output/target-acceptance/fixture.log" || log_path == raw_log
end

puts "target acceptance report schema checks passed"
