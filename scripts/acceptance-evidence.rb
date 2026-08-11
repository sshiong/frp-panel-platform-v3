#!/usr/bin/env ruby

require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "time"

module AcceptanceEvidence
  ROOT = File.expand_path("..", __dir__)
  STANDARD_PATH = File.join(ROOT, "frp_cloudflare_platform_v3_development_acceptance_standard.md")
  MATRIX_PATH = File.join(ROOT, "docs/acceptance-matrix.md")
  REPOSITORY = "sshiong/frp-panel-platform-v3".freeze
  ALLOWED_STATUSES = ["本地通过", "本地/CI 通过", "部分通过", "待外部"].freeze
  DERIVED_ITEMS = {
    "DOD-001" => {
      "priority" => "release-gate",
      "requirement" => "完成所有 P0/P1 外部验收，并由发布、安全、测试负责人对同一 revision 签字。"
    }
  }.freeze

  module_function

  def build(artifact_dir: "output/acceptance-evidence")
    standard = parse_standard
    matrix = parse_matrix
    validate_sources!(standard, matrix)

    generated_at = Time.now.utc.iso8601(6)
    commit = current_commit
    operator = ENV["ACCEPTANCE_OPERATOR"] || ENV["GITHUB_ACTOR"] || ENV["USER"] || "unknown"
    items = (standard.keys + DERIVED_ITEMS.keys).uniq.sort.map do |id|
      requirement = standard[id] || DERIVED_ITEMS.fetch(id)
      row = matrix.fetch(id)
      log_path = relative_path(File.join(ROOT, artifact_dir, "#{id}.log"))
      {
        "id" => id,
        "priority" => requirement["priority"],
        "status" => row["status"],
        "environment" => environment_snapshot,
        "steps" => [
          "读取标准条目 #{id}（#{requirement["source"] || "derived release gate"}）",
          "读取验收矩阵 #{row["source"]} 的当前状态和结果说明",
          "记录可追溯性证据；不把部分通过或待外部提升为通过"
        ],
        "expected" => requirement["requirement"],
        "actual" => "#{row["status"]}：#{row["detail"]}",
        "artifacts" => {
          "logs" => [log_path],
          "screenshots" => [],
          "request_ids" => [],
          "references" => ["docs/acceptance-matrix.md", "docs/acceptance-report.md"]
        },
        "operator" => operator,
        "executed_at" => generated_at,
        "evidence_type" => "traceability-index",
        "source" => {
          "standard" => requirement["source"] || "derived",
          "matrix" => row["source"]
        }
      }
    end

    status = items.any? { |item| ["部分通过", "待外部"].include?(item["status"]) } ? "blocked" : "passed"
    {
      "schema_version" => "v1",
      "kind" => "acceptance-evidence-index",
      "status" => status,
      "repository" => REPOSITORY,
      "commit" => commit,
      "generated_at" => generated_at,
      "operator" => operator,
      "source" => {
        "standard" => relative_path(STANDARD_PATH),
        "matrix" => relative_path(MATRIX_PATH)
      },
      "rules" => {
        "incomplete_status_is_not_passed" => true,
        "traceability_index_does_not_execute_acceptance" => true,
        "traceability_index_does_not_replace_underlying_logs_or_external_review" => true
      },
      "items" => items
    }
  end

  def validate!(document)
    errors = []
    errors << "root must be an object" unless document.is_a?(Hash)
    return errors unless document.is_a?(Hash)

    errors << "schema_version must be v1" unless document["schema_version"] == "v1"
    errors << "kind must be acceptance-evidence-index" unless document["kind"] == "acceptance-evidence-index"
    errors << "repository must be #{REPOSITORY}" unless document["repository"] == REPOSITORY
    errors << "commit must be a 40-character SHA-1" unless document["commit"].to_s.match?(/\A[0-9a-f]{40}\z/)
    errors << "items must be a non-empty array" unless document["items"].is_a?(Array) && !document["items"].empty?
    errors << "status must be blocked when an item is incomplete" if document["status"] == "passed" && document.fetch("items", []).any? { |item| ["部分通过", "待外部"].include?(item["status"]) }

    items = document["items"].is_a?(Array) ? document["items"] : []
    ids = items.map { |item| item.is_a?(Hash) ? item["id"] : nil }
    errors << "items contain duplicate IDs" unless ids.compact.uniq.length == ids.compact.length
    expected_ids = (parse_standard.keys + DERIVED_ITEMS.keys).uniq.sort
    errors << "items do not cover all standard IDs" unless ids.compact.sort == expected_ids

    items.each do |item|
      unless item.is_a?(Hash)
        errors << "each item must be an object"
        next
      end
      id = item["id"] || "unknown"
      errors << "#{id}.status is invalid" unless ALLOWED_STATUSES.include?(item["status"])
      %w[priority environment steps expected actual artifacts operator executed_at].each do |field|
        errors << "#{id}.#{field} is missing" unless item.key?(field)
      end
      errors << "#{id}.steps must be non-empty" unless item["steps"].is_a?(Array) && item["steps"].any? { |step| step.to_s.strip != "" }
      errors << "#{id}.expected must be non-empty" unless nonempty?(item["expected"])
      errors << "#{id}.actual must be non-empty" unless nonempty?(item["actual"])
      errors << "#{id}.artifacts must be an object" unless item["artifacts"].is_a?(Hash)
      if item["artifacts"].is_a?(Hash)
        logs = item["artifacts"]["logs"]
        errors << "#{id}.artifacts.logs must be non-empty" unless logs.is_a?(Array) && logs.any? { |log| log.to_s.strip != "" }
      end
      begin
        Time.iso8601(item["executed_at"].to_s)
      rescue ArgumentError
        errors << "#{id}.executed_at must be ISO-8601"
      end
    end
    errors
  end

  def write(document, output:, artifact_dir:)
    FileUtils.mkdir_p(artifact_dir)
    document.fetch("items").each do |item|
      path = File.join(artifact_dir, "#{item.fetch("id")}.log")
      File.open(path, "w", 0o600) do |file|
        file.write(JSON.pretty_generate({
          "record_type" => "acceptance-traceability",
          "warning" => "This record indexes the tracked result; it does not execute or upgrade the acceptance.",
          "item" => item
        }))
        file.write("\n")
      end
      File.chmod(0o600, path)
    end
    FileUtils.mkdir_p(File.dirname(output))
    File.open(output, "w", 0o600) { |file| file.write(JSON.pretty_generate(document) + "\n") }
    File.chmod(0o600, output)
  end

  def parse_standard
    entries = {}
    File.readlines(STANDARD_PATH, chomp: true).each_with_index do |line, index|
      match = line.match(/\A- \*\*([A-Z]+-\d{3}) \/ (P[0-3])\*\*：(.+)\z/)
      next unless match

      id, priority, requirement = match.captures
      entries[id] = { "priority" => priority, "requirement" => requirement.strip, "source" => "#{relative_path(STANDARD_PATH)}:#{index + 1}" }
    end
    entries
  end

  def parse_matrix
    rows = {}
    File.readlines(MATRIX_PATH, chomp: true).each_with_index do |line, index|
      match = line.match(/\A\|\s*([A-Z]+-\d{3})\s*\|\s*([^|]+)\s*\|\s*(.*?)\s*\|\s*\z/)
      next unless match

      id, status, detail = match.captures
      rows[id] = { "status" => status.strip, "detail" => detail.strip, "source" => "#{relative_path(MATRIX_PATH)}:#{index + 1}" }
    end
    rows
  end

  def validate_sources!(standard, matrix)
    errors = []
    expected = standard.keys + DERIVED_ITEMS.keys
    missing = expected - matrix.keys
    errors << "matrix is missing #{missing.join(", ")}" unless missing.empty?
    unexpected = matrix.keys - expected
    errors << "matrix contains unexpected #{unexpected.join(", ")}" unless unexpected.empty?
    matrix.each do |id, row|
      errors << "#{id} has invalid status" unless ALLOWED_STATUSES.include?(row["status"])
      errors << "#{id} has no result detail" if row["detail"].strip.empty?
    end
    errors << "DOD-001 must remain 待外部" if matrix["DOD-001"] && matrix["DOD-001"]["status"] != "待外部"
    raise errors.join("\n") unless errors.empty?
  end

  def environment_snapshot
    {
      "host_os" => RbConfig::CONFIG["host_os"],
      "ci" => ENV.fetch("CI", "false"),
      "working_directory" => ROOT,
      "revision" => current_commit
    }
  end

  def current_commit
    candidate = ENV["GITHUB_SHA"].to_s
    return candidate if candidate.match?(/\A[0-9a-f]{40}\z/)

    stdout, _stderr, status = Open3.capture3("git", "rev-parse", "HEAD", chdir: ROOT)
    status.success? ? stdout.strip : "unknown"
  end

  def relative_path(path)
    absolute = File.expand_path(path, ROOT)
    absolute.start_with?("#{ROOT}/") ? absolute.delete_prefix("#{ROOT}/") : absolute
  end

  def nonempty?(value)
    case value
    when String then !value.strip.empty?
    when Array then value.any? { |item| nonempty?(item) }
    when Hash then !value.empty?
    else !value.nil?
    end
  end
end

options = { check: false, output: nil, artifact_dir: "output/acceptance-evidence" }
OptionParser.new do |parser|
  parser.banner = "Usage: acceptance-evidence.rb [--check] [--output PATH] [--artifact-dir PATH]"
  parser.on("--check", "validate the generated index without writing files") { options[:check] = true }
  parser.on("--output PATH", "write the JSON index to PATH") { |value| options[:output] = value }
  parser.on("--artifact-dir PATH", "write per-item 0600 logs below PATH") { |value| options[:artifact_dir] = value }
end.parse!

document = AcceptanceEvidence.build(artifact_dir: options[:artifact_dir])
errors = AcceptanceEvidence.validate!(document)
abort errors.join("\n") unless errors.empty?

unless options[:check]
  output = options[:output] || File.join("output", "acceptance-evidence.json")
  AcceptanceEvidence.write(document, output: File.expand_path(output, AcceptanceEvidence::ROOT), artifact_dir: File.expand_path(options[:artifact_dir], AcceptanceEvidence::ROOT))
end

puts "Acceptance evidence index valid: #{document.fetch("items").count - 1} standard items, #{document.fetch("items").length} records, status=#{document.fetch("status")}" 
