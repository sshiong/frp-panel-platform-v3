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

puts "external acceptance evidence schema checks passed"
