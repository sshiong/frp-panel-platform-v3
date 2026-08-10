#!/usr/bin/env ruby

require_relative "cloudflare-sandbox-e2e"

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
