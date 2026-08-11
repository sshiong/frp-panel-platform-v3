#!/usr/bin/env ruby

SEMVER = /\A(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\z/

defaults = {
  "SERVER_VERSION" => "0.1.0",
  "CLIENT_VERSION" => "0.1.0",
  "MINIMUM_CLIENT_VERSION" => "0.1.0",
  "LATEST_CLIENT_VERSION" => ENV.fetch("CLIENT_VERSION", "0.1.0"),
  "FRPS_VERSION" => "0.68.0",
  "FRPC_VERSION" => "0.68.0"
}

errors = []
defaults.each do |name, fallback|
  value = ENV.fetch(name, fallback).to_s.strip
  errors << "#{name}=#{value.inspect} is not SemVer" unless value.match?(SEMVER)
end

if errors.empty?
  minimum = ENV.fetch("MINIMUM_CLIENT_VERSION", defaults["MINIMUM_CLIENT_VERSION"]).split(".").map(&:to_i)
  latest = ENV.fetch("LATEST_CLIENT_VERSION", defaults["LATEST_CLIENT_VERSION"]).split(".").map(&:to_i)
  errors << "MINIMUM_CLIENT_VERSION must not exceed LATEST_CLIENT_VERSION" if (minimum <=> latest) == 1
end

abort errors.join("\n") unless errors.empty?
puts "Release version policy valid: independent Server/Client SemVer and FRP compatibility versions"
