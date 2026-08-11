#!/usr/bin/env ruby

require "open3"
require "tmpdir"

ROOT = File.expand_path("..", __dir__)
MINIMUM_TOTAL = 75.0
MINIMUM_CRITICAL = 90.0

CRITICAL_PACKAGES = {
  "server/internal/auth" => "Server authentication",
  "server/internal/crypto" => "Server purpose-specific encryption",
  "server/internal/router" => "Server Router runtime and snapshot"
}.freeze

def run!(*command, chdir: ROOT)
  stdout, stderr, status = Open3.capture3(*command, chdir: chdir)
  return stdout if status.success?

  warn stdout
  warn stderr
  abort "coverage command failed: #{command.join(' ')}"
end

def parse_profile(path)
  totals = Hash.new { |hash, key| hash[key] = { statements: 0, covered: 0 } }
  File.foreach(path).drop(1).each do |line|
    location, statements, executions = line.split
    next if location.nil? || statements.nil? || executions.nil?

    source_path = location.split(":", 2).first
    bucket = totals[source_path]
    bucket[:statements] += statements.to_i
    bucket[:covered] += statements.to_i if executions.to_i.positive?
  end
  totals
end

def percentage(statements, covered)
  return 100.0 if statements.zero?

  covered.to_f * 100.0 / statements
end

def report(label, totals)
  statements = totals.values.sum { |value| value[:statements] }
  covered = totals.values.sum { |value| value[:covered] }
  value = percentage(statements, covered)
  puts format("%s internal coverage: %.2f%% (%d/%d statements)", label, value, covered, statements)
  value
end

failures = []
Dir.mktmpdir("frp-panel-coverage") do |directory|
  module_totals = {}
  %w[server client].each do |mod|
    profile = File.join(directory, "#{mod}.out")
    run!("go", "test", "-coverprofile=#{profile}", "./internal/...", chdir: File.join(ROOT, mod))
    totals = parse_profile(profile)
    module_totals[mod] = totals
    total = report(mod.capitalize, totals)
    failures << "#{mod} total #{format('%.2f', total)}% < #{MINIMUM_TOTAL}%" if total < MINIMUM_TOTAL
  end

  CRITICAL_PACKAGES.each do |package, label|
    totals = module_totals.fetch(package.split("/", 2).first)
    matching = totals.select { |path, _| path.include?("/#{package}/") }
    statements = matching.values.sum { |value| value[:statements] }
    covered = matching.values.sum { |value| value[:covered] }
    value = percentage(statements, covered)
    puts format("%s coverage: %.2f%% (%d/%d statements)", label, value, covered, statements)
    failures << "#{package} #{format('%.2f', value)}% < #{MINIMUM_CRITICAL}%" if value < MINIMUM_CRITICAL
  end
end

abort "coverage policy failed: #{failures.join('; ')}" unless failures.empty?
puts "coverage policy valid: internal Go totals and critical package thresholds are satisfied"
