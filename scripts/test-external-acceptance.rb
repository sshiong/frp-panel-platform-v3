#!/usr/bin/env ruby

require_relative "external-acceptance"

collector = AcceptanceCollector.new
valid_gate = {
  "status" => "passed",
  "environment" => { "os" => "test" },
  "steps" => ["execute"],
  "expected" => "pass",
  "actual" => "pass",
  "artifacts" => { "logs" => ["test.log"], "screenshots" => [], "request_ids" => [] },
  "operator" => "tester",
  "executed_at" => "2026-08-03T00:00:00Z"
}
valid_bundle = {
  "schema_version" => "v1",
  "status" => "passed",
  "repository" => AcceptanceCollector::REPOSITORY,
  "commit" => collector.send(:git_revision),
  "gates" => AcceptanceCollector::PROVIDER_GATES.to_h { |gate| [gate, valid_gate] }
}

unless collector.send(:validate_evidence_bundle, valid_bundle).empty?
  abort("valid evidence bundle was rejected")
end

invalid_bundle = Marshal.load(Marshal.dump(valid_bundle))
invalid_bundle["gates"]["DNS-012"]["artifacts"] = {}
unless collector.send(:validate_evidence_bundle, invalid_bundle).any? { |error| error.include?("DNS-012.artifacts") }
  abort("malformed evidence artifacts were accepted")
end

stale_bundle = Marshal.load(Marshal.dump(valid_bundle))
stale_bundle["commit"] = "0" * 40
unless collector.send(:validate_evidence_bundle, stale_bundle).any? { |error| error.include?("commit 必须为当前仓库 HEAD") }
  abort("evidence from another commit was accepted")
end

wrong_repository_bundle = Marshal.load(Marshal.dump(valid_bundle))
wrong_repository_bundle["repository"] = "another/repository"
unless collector.send(:validate_evidence_bundle, wrong_repository_bundle).any? { |error| error.include?("repository 必须为") }
  abort("evidence from another repository was accepted")
end

puts "external acceptance evidence schema checks passed"
