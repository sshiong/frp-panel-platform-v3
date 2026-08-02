#!/usr/bin/env ruby

require "json"

root = File.expand_path("..", __dir__)
allowed = %w[Apache-2.0 BSD-2-Clause BSD-3-Clause BlueOak-1.0.0 ISC MIT Python-2.0]
forbidden = /(?:GPL|AGPL|SSPL|BUSL)/i
violations = []

%w[admin client].each do |app_name|
  path = File.join(root, "web", app_name, "package-lock.json")
  lock = JSON.parse(File.read(path))
  (lock.fetch("packages", {})).each do |location, item|
    next if location.empty? || !item["version"]
    license = item["license"]
    package_name = location.sub(%r{^node_modules/}, "")
    if !license.is_a?(String) || license.empty?
      violations << "#{app_name}: #{package_name}@#{item["version"]} has no SPDX license"
    elsif license.match?(forbidden) || !allowed.include?(license)
      violations << "#{app_name}: #{package_name}@#{item["version"]} uses disallowed license #{license}"
    end
  end
end

abort "license policy failed:\n#{violations.join("\n")}" unless violations.empty?
puts "license policy valid: npm dependency licenses are present and allowlisted"
