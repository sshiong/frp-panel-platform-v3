#!/usr/bin/env ruby

require "json"
require "time"

root = File.expand_path("..", __dir__)
packages = []

%w[server client].each do |module_name|
  File.read(File.join(root, module_name, "go.mod")).scan(/^\s*([\w.\/-]+)\s+v([^\s]+)(?:\s+\/\/\s+indirect)?$/).each do |name, version|
    packages << { "name" => name, "versionInfo" => version, "downloadLocation" => "NOASSERTION", "licenseConcluded" => "NOASSERTION" }
  end
end

%w[admin client].each do |app_name|
  lock_path = File.join(root, "web", app_name, "package-lock.json")
  next unless File.file?(lock_path)
  lock = JSON.parse(File.read(lock_path))
  (lock["packages"] || {}).each do |location, item|
    next if location == ""
    next unless item["version"]
    package_name = location.sub(%r{^node_modules/}, "")
    packages << { "name" => "npm:#{package_name}", "versionInfo" => item["version"], "downloadLocation" => "NOASSERTION", "licenseConcluded" => "NOASSERTION" }
  end
end

packages = packages.uniq { |item| [item["name"], item["versionInfo"]] }.sort_by { |item| [item["name"], item["versionInfo"]] }
document = {
  "spdxVersion" => "SPDX-2.3",
  "dataLicense" => "CC0-1.0",
  "SPDXID" => "SPDXRef-DOCUMENT",
  "name" => "frp-panel-platform-v3",
  "documentNamespace" => "https://github.com/sshiong/frp-panel-platform-v3/sbom/local",
  "creationInfo" => { "created" => Time.now.utc.iso8601, "creators" => ["Tool: frp-panel-sbom"] },
  "packages" => packages.each_with_index.map { |item, index| item.merge("SPDXID" => "SPDXRef-Package-#{index + 1}") }
}

output = File.join(root, "build", "sbom.spdx.json")
Dir.mkdir(File.dirname(output)) unless Dir.exist?(File.dirname(output))
File.write(output, JSON.pretty_generate(document) + "\n")
puts "SBOM written to #{output} (#{packages.length} packages)"
