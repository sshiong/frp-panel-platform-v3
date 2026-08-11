#!/usr/bin/env ruby

require "yaml"

ROOT = File.expand_path("..", __dir__)
STANDARD_PATH = File.join(ROOT, "frp_cloudflare_platform_v3_development_acceptance_standard.md")
MATRIX_PATH = File.join(ROOT, "docs/acceptance-matrix.md")
ALLOWED_MATRIX_STATUSES = ["本地通过", "本地/CI 通过", "部分通过", "待外部"].freeze
DERIVED_MATRIX_IDS = ["DOD-001"].freeze
OPENAPI_METHODS = %w[get post put patch delete options head].freeze
CONTRACTS = {
  "Server OpenAPI" => File.join(ROOT, "contracts", "openapi.yaml"),
  "Client Local API" => File.join(ROOT, "contracts", "client-openapi.yaml")
}.freeze

standard = File.read(STANDARD_PATH)
matrix = File.read(MATRIX_PATH)
standard_ids = {}
standard.scan(/\*\*([A-Z]+-\d{3}) \/ (P[0-3])\*\*/) do |id, priority|
  standard_ids[id] = priority
end

matrix_rows = {}
matrix.lines.each do |line|
  match = line.match(/^\|\s*([A-Z]+-\d{3})\s*\|\s*([^|]+)\s*\|\s*(.*?)\s*\|/)
  next unless match

  matrix_rows[match[1]] = {
    "status" => match[2].strip,
    "detail" => match[3].strip
  }
end

errors = []
missing = standard_ids.keys - matrix_rows.keys
errors << "验收矩阵缺少标准条目：#{missing.join(', ')}" unless missing.empty?

unexpected = matrix_rows.keys - standard_ids.keys - DERIVED_MATRIX_IDS
errors << "验收矩阵包含未在标准中声明的条目：#{unexpected.join(', ')}" unless unexpected.empty?

matrix_rows.each do |id, row|
  unless ALLOWED_MATRIX_STATUSES.include?(row["status"])
    errors << "#{id} 使用了未知状态：#{row["status"]}"
  end
  errors << "#{id} 缺少结果说明" if row["detail"].empty?
end

api_detail = matrix_rows.dig("API-001", "detail")
if api_detail
  CONTRACTS.each do |label, path|
    expected = api_detail.match(/#{Regexp.escape(label)}(?: 3\.1)? (\d+) paths\/(\d+) operations/)
    if expected.nil?
      errors << "API-001 缺少 #{label} 的当前 OpenAPI 路由数量"
      next
    end

    document = YAML.load_file(path)
    paths = document.fetch("paths")
    actual_paths = paths.length
    actual_operations = paths.sum do |_route, item|
      item.keys.count { |method| OPENAPI_METHODS.include?(method) }
    end
    expected_paths, expected_operations = expected.captures.map(&:to_i)
    if [expected_paths, expected_operations] != [actual_paths, actual_operations]
      errors << "API-001 的 #{label} 数量 #{expected_paths}/#{expected_operations} 与契约 #{actual_paths}/#{actual_operations} 不一致"
    end
  end
end

if matrix_rows["DOD-001"] && matrix_rows["DOD-001"]["status"] != "待外部"
  errors << "DOD-001 必须在所有外部发布条件完成前保持待外部"
end

unless errors.empty?
  abort errors.join("\n")
end

puts "Acceptance matrix policy valid: #{standard_ids.length} standard items and #{matrix_rows.length} tracked rows"
