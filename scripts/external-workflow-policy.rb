#!/usr/bin/env ruby

workflow = File.read(File.expand_path("../.github/workflows/external-acceptance.yml", __dir__))
required = {
  "manual-only trigger" => "workflow_dispatch:",
  "exact source revision checkout" => "ref: ${{ github.sha }}",
  "protected environment" => "name: external-acceptance",
  "Cloudflare secret" => "CLOUDFLARE_E2E_API_TOKEN: ${{ secrets.CLOUDFLARE_E2E_API_TOKEN }}",
  "ACME email secret" => "FRP_ACME_E2E_EMAIL: ${{ secrets.FRP_ACME_E2E_EMAIL }}",
  "Cloudflare write confirmation" => "CLOUDFLARE_E2E_CONFIRM: disposable-zone",
  "Cloudflare expected Zone binding" => "CLOUDFLARE_E2E_EXPECTED_ZONE_NAME: ${{ inputs.expected_zone_name }}",
  "ACME staging confirmation" => "FRP_ACME_E2E_CONFIRM: acme-staging",
  "ACME Zone binding" => "FRP_ACME_E2E_EXPECTED_ZONE_NAME: ${{ inputs.expected_zone_name }}",
  "redacted artifact upload" => "actions/upload-artifact@v4",
  "runner revision binding" => "FRP_ACCEPTANCE_EXPECTED_COMMIT: ${{ github.sha }}",
  "structured runner evidence validator" => "scripts/validate-external-runners.rb",
  "both-runner final gate" => "Require both external smoke runners to pass"
}
missing = required.each_with_object([]) do |(label, fragment), errors|
  errors << "#{label}: #{fragment}" unless workflow.include?(fragment)
end
abort("external acceptance workflow policy invalid: #{missing.join('; ')}") unless missing.empty?
if workflow.match?(/^\s*(push|pull_request):\s*$/)
  abort("external acceptance workflow must not run automatically on push or pull_request")
end
puts "external acceptance workflow policy valid: manual trigger, protected environment, secret boundaries, and final gate"
