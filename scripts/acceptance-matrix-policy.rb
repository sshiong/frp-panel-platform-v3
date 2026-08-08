#!/usr/bin/env ruby

ROOT = File.expand_path("..", __dir__)
STANDARD_PATH = File.join(ROOT, "frp_cloudflare_platform_v3_development_acceptance_standard.md")
MATRIX_PATH = File.join(ROOT, "docs/acceptance-matrix.md")
ALLOWED_MATRIX_STATUSES = ["本地通过", "本地/CI 通过", "部分通过", "待外部"].freeze
DERIVED_MATRIX_IDS = ["DOD-001"].freeze

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

if matrix_rows["DOD-001"] && matrix_rows["DOD-001"]["status"] != "待外部"
  errors << "DOD-001 必须在所有外部发布条件完成前保持待外部"
end

unless errors.empty?
  abort errors.join("\n")
end

puts "Acceptance matrix policy valid: #{standard_ids.length} standard items and #{matrix_rows.length} tracked rows"
