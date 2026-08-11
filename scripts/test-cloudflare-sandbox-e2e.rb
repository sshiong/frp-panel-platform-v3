#!/usr/bin/env ruby

require_relative "cloudflare-sandbox-e2e"
require "open3"
require "rbconfig"

valid = [
  "https://api.cloudflare.com/client/v4",
  "https://api.cloudflare.com/client/v4/"
]
invalid = [
  "http://api.cloudflare.com/client/v4",
  "https://evil.example/client/v4",
  "https://user:password@api.cloudflare.com/client/v4",
  "https://api.cloudflare.com:8443/client/v4",
  "https://api.cloudflare.com/client/v3",
  "https://api.cloudflare.com/client/v4?redirect=https://evil.example",
  "https://api.cloudflare.com/client/v4#fragment"
]

valid.each do |value|
  CloudflareSandboxE2E.validate_api_base_url(value)
end

invalid.each do |value|
  begin
    CloudflareSandboxE2E.validate_api_base_url(value)
  rescue StandardError
    next
  end
  abort "untrusted Cloudflare API base URL was accepted: #{value}"
end

zone_cases = {
  ["a.example.com", "example.com"] => true,
  ["A.Example.Com.", "example.com."] => true,
  ["example.com", "example.com"] => true,
  ["a.not-example.com", "example.com"] => false,
  ["example.com.evil.test", "example.com"] => false,
  ["", "example.com"] => false
}
zone_cases.each do |(hostname, zone_name), expected|
  actual = CloudflareSandboxE2E.hostname_in_zone?(hostname, zone_name)
  abort "zone ownership check mismatch for #{hostname.inspect}/#{zone_name.inspect}: #{actual.inspect}" unless actual == expected
end

puts "Cloudflare sandbox API endpoint policy valid"

env = {
  "CLOUDFLARE_E2E_API_TOKEN" => "redacted-test-token",
  "CLOUDFLARE_E2E_ZONE_ID" => "0123456789abcdef",
  "CLOUDFLARE_E2E_RECORD_NAME" => "frp-e2e.example.com",
  "CLOUDFLARE_E2E_CONFIRM" => "disposable-zone"
}
command = [RbConfig.ruby, File.expand_path("cloudflare-sandbox-e2e.rb", __dir__)]
_stdout, stderr, status = Open3.capture3(env, *command, chdir: File.expand_path("..", __dir__))
abort "direct Cloudflare runner accepted missing expected Zone name" if status.success?
abort "direct Cloudflare runner did not require expected Zone name" unless stderr.include?("CLOUDFLARE_E2E_EXPECTED_ZONE_NAME")

puts "Cloudflare sandbox runner requires an expected Zone name"
