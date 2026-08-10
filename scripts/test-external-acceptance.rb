#!/usr/bin/env ruby

require_relative "external-acceptance"
require "tmpdir"

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
valid_bundle["gates"]["SEC-008"]["signature"] = {
  "tool" => "cosign",
  "verified" => true,
  "identity" => "https://github.com/sshiong/frp-panel-platform-v3/.github/workflows/release.yml@refs/tags/v0.1.0",
  "issuer" => "https://token.actions.githubusercontent.com",
  "artifacts_verified" => ["build/frp-panel-server"]
}
valid_bundle["gates"]["DOD-001"]["approvals"] = [
  { "role" => "release", "name" => "release-owner", "commit" => valid_bundle["commit"], "approval_ref" => "review-release-1", "signed_at" => "2026-08-03T00:00:00Z" },
  { "role" => "security", "name" => "security-owner", "commit" => valid_bundle["commit"], "approval_ref" => "review-security-1", "signed_at" => "2026-08-03T00:00:00Z" },
  { "role" => "test", "name" => "test-owner", "commit" => valid_bundle["commit"], "approval_ref" => "review-test-1", "signed_at" => "2026-08-03T00:00:00Z" }
]

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

missing_signature_bundle = Marshal.load(Marshal.dump(valid_bundle))
missing_signature_bundle["gates"]["SEC-008"].delete("signature")
unless collector.send(:validate_evidence_bundle, missing_signature_bundle).any? { |error| error.include?("SEC-008.signature") }
  abort("cosign signature metadata was not required")
end

missing_owner_bundle = Marshal.load(Marshal.dump(valid_bundle))
missing_owner_bundle["gates"]["DOD-001"]["approvals"] = missing_owner_bundle["gates"]["DOD-001"]["approvals"][0, 2]
unless collector.send(:validate_evidence_bundle, missing_owner_bundle).any? { |error| error.include?("DOD-001.approvals") }
  abort("three-owner sign-off was not required")
end

Dir.mktmpdir("external-acceptance-evidence") do |artifact_dir|
  structured_collector = AcceptanceCollector.new(artifact_dir: artifact_dir)
  structured_collector.run("structured-fixture", "structured evidence fixture", [RbConfig.ruby, "-e", "puts :ok"])
  step = structured_collector.report.fetch("steps").fetch(0)
  required_fields = %w[environment steps expected actual artifacts operator executed_at]
  missing_fields = required_fields.reject { |field| step.key?(field) }
  abort("local collector evidence fields missing: #{missing_fields.join(', ')}") unless missing_fields.empty?

  artifact_path = File.join(artifact_dir, "structured-fixture.log")
  abort("local collector did not write a log artifact") unless File.file?(artifact_path)
  abort("local collector log artifact is not mode 0600") unless (File.stat(artifact_path).mode & 0o777) == 0o600
end

original_token = ENV["CLOUDFLARE_E2E_API_TOKEN"]
begin
  ENV["CLOUDFLARE_E2E_API_TOKEN"] = "fixture-cloudflare-secret"
  redacting_collector = AcceptanceCollector.new
  redacted = redacting_collector.send(:redact, "Bearer fixture-cloudflare-secret")
  unless !redacted.include?("fixture-cloudflare-secret") && redacted.include?("[REDACTED]")
    abort("Cloudflare E2E token was not redacted")
  end
ensure
  if original_token
    ENV["CLOUDFLARE_E2E_API_TOKEN"] = original_token
  else
    ENV.delete("CLOUDFLARE_E2E_API_TOKEN")
  end
end

puts "external acceptance evidence schema checks passed"
