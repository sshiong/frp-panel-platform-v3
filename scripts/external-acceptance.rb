#!/usr/bin/env ruby

require "fileutils"
require "json"
require "open3"
require "time"

ROOT = File.expand_path("..", __dir__)
REPORT_PATH = File.expand_path(ENV.fetch("EXTERNAL_ACCEPTANCE_REPORT", "output/external-acceptance.json"), ROOT)
TAIL_LIMIT = 12_000

class AcceptanceCollector
  REPOSITORY = "sshiong/frp-panel-platform-v3".freeze
  PROVIDER_GATES = %w[
    FRPS-009 DNS-012 DNS-013 CF-007 TLS-009 TLS-010 TLS-012 KEY-004
    PERF-003 REL-005 REL-007 REL-008 SEC-008 DOD-001
  ].freeze
  EVIDENCE_ARTIFACT_FIELDS = %w[logs screenshots request_ids].freeze

  def initialize
    @steps = []
    @secret_values = ENV.values_at(
      "CLOUDFLARE_API_TOKEN", "ACME_DNS_API_TOKEN", "COSIGN_KEY",
      "FRP_E2E_FRPS_SHA256", "FRP_E2E_FRPC_SHA256"
    ).compact.reject(&:empty?)
  end

  def run(id, title, command, cwd: ROOT, env: {})
    started = Time.now.utc
    stdout, stderr, status = Open3.capture3(env, *command, chdir: cwd)
    finished = Time.now.utc
    @steps << {
      "id" => id,
      "title" => title,
      "status" => status.success? ? "passed" : "failed",
      "started_at" => started.iso8601(6),
      "finished_at" => finished.iso8601(6),
      "duration_ms" => ((finished - started) * 1000).round,
      "command" => command.map { |part| redact(part.to_s) },
      "working_directory" => cwd,
      "environment_presence" => env.keys.sort.to_h { |name| [name, !env[name].to_s.empty?] },
      "exit_code" => status.exitstatus,
      "stdout_tail" => tail(stdout),
      "stderr_tail" => tail(stderr)
    }
  rescue Errno::ENOENT => e
    @steps << {
      "id" => id,
      "title" => title,
      "status" => "failed",
      "started_at" => started.iso8601(6),
      "finished_at" => Time.now.utc.iso8601(6),
      "command" => command.map { |part| redact(part.to_s) },
      "working_directory" => cwd,
      "exit_code" => nil,
      "stderr_tail" => redact(e.message)
    }
  end

  def blocked(id, title, requirements, detail = nil)
    @steps << {
      "id" => id,
      "title" => title,
      "status" => "blocked",
      "requirements" => requirements,
      "detail" => detail || "外部环境尚未提供该验收所需的安全依赖。"
    }
  end

  def skipped(id, title, detail)
    @steps << { "id" => id, "title" => title, "status" => "skipped", "detail" => detail }
  end

  def evidence(path)
    unless File.file?(path)
      blocked("provider-evidence", "Provider、目标环境与发布签字证据", [path], "证据文件不存在。")
      return
    end

    document = JSON.parse(File.read(path))
    errors = validate_evidence_bundle(document)

    if errors.empty?
      @steps << {
        "id" => "provider-evidence",
        "title" => "Provider、目标环境与发布签字证据",
        "status" => "passed",
        "source" => path,
        "gates" => PROVIDER_GATES
      }
    else
      blocked(
        "provider-evidence",
        "Provider、目标环境与发布签字证据",
        [path],
        "证据包不符合 v1 结构：#{errors.join('；')}"
      )
    end
  rescue JSON::ParserError, KeyError => e
    @steps << {
      "id" => "provider-evidence",
      "title" => "Provider、目标环境与发布签字证据",
      "status" => "failed",
      "source" => path,
      "stderr_tail" => redact("证据文件格式无效：#{e.message}")
    }
  end

  def validate_evidence_gate(gate_id, gate)
    return ["#{gate_id} 必须是对象"] unless gate.is_a?(Hash)

    errors = []
    errors << "#{gate_id}.status 必须为 passed" unless gate["status"] == "passed"
    {
      "environment" => "对象或非空字符串",
      "steps" => "非空数组",
      "expected" => "非空字符串",
      "actual" => "非空字符串",
      "operator" => "非空字符串",
      "executed_at" => "ISO-8601 时间"
    }.each do |field, description|
      value = gate[field]
      type_valid = case field
      when "environment"
        value.is_a?(Hash) || value.is_a?(String)
      when "steps"
        value.is_a?(Array)
      else
        value.is_a?(String)
      end
      next if type_valid && nonempty_value?(value)

      errors << "#{gate_id}.#{field} 必须是#{description}"
    end

    artifacts = gate["artifacts"]
    if !artifacts.is_a?(Hash)
      errors << "#{gate_id}.artifacts 必须是对象"
    elsif !EVIDENCE_ARTIFACT_FIELDS.any? { |field| nonempty_value?(artifacts[field]) }
      errors << "#{gate_id}.artifacts 至少包含一项 logs、screenshots 或 request_ids"
    end

    begin
      Time.iso8601(gate["executed_at"].to_s)
    rescue ArgumentError
      errors << "#{gate_id}.executed_at 不是有效的 ISO-8601 时间"
    end unless gate["executed_at"].nil?

    errors
  end

  def validate_evidence_bundle(document)
    return ["证据根节点必须是对象"] unless document.is_a?(Hash)

    errors = []
    errors << "schema_version 必须为 v1" unless document["schema_version"] == "v1"
    errors << "bundle status 必须为 passed" unless document["status"] == "passed"
    errors << "repository 必须为 #{REPOSITORY}" unless document["repository"] == REPOSITORY
    current_commit = git_revision
    evidence_commit = document["commit"].to_s
    unless evidence_commit.match?(/\A[0-9a-f]{40}\z/) && evidence_commit == current_commit
      errors << "commit 必须为当前仓库 HEAD（#{current_commit}）"
    end
    gates = document["gates"]
    unless gates.is_a?(Hash)
      errors << "gates 必须是对象"
      return errors
    end

    missing = PROVIDER_GATES.reject { |gate| gates[gate].is_a?(Hash) && gates[gate]["status"] == "passed" }
    errors << "缺少或未通过：#{missing.join(', ')}" unless missing.empty?
    PROVIDER_GATES.each do |gate_id|
      errors.concat(validate_evidence_gate(gate_id, gates[gate_id]))
    end
    errors
  end

  def nonempty_value?(value)
    case value
    when String
      !value.strip.empty?
    when Array
      value.any? { |item| nonempty_value?(item) }
    when Hash
      !value.empty?
    else
      !value.nil?
    end
  end

  def report
    statuses = @steps.map { |step| step["status"] }
    overall = if statuses.include?("failed")
      "failed"
    elsif statuses.include?("blocked")
      "blocked"
    elsif statuses.empty? || statuses.all? { |status| status == "skipped" }
      "blocked"
    else
      "passed"
    end

    {
      "schema_version" => "v1",
      "status" => overall,
      "generated_at" => Time.now.utc.iso8601(6),
      "repository" => "sshiong/frp-panel-platform-v3",
      "commit" => git_revision,
      "operator" => ENV.fetch("USER", "unknown"),
      "rules" => {
        "blocked_is_not_passed" => true,
        "provider_mutations_are_not_started_without_explicit_external_evidence" => true,
        "secrets_are_never_written_to_this_report" => true
      },
      "steps" => @steps
    }
  end

  private

  def git_revision
    stdout, _stderr, status = Open3.capture3("git", "rev-parse", "HEAD", chdir: ROOT)
    status.success? ? stdout.strip : "unknown"
  end

  def tail(value)
    redact(value.to_s[-TAIL_LIMIT, TAIL_LIMIT] || "")
  end

  def redact(value)
    output = value.to_s
    @secret_values.each { |secret| output = output.gsub(secret, "[REDACTED]") }
    output.gsub!(/(?i)(authorization\s*:\s*bearer\s+|(?:token|password|secret|private[_-]?key)\s*[:=]\s*)\S+/, '\\1[REDACTED]')
    output
  end
end

def run_external_acceptance
  collector = AcceptanceCollector.new

if ENV.fetch("EXTERNAL_ACCEPTANCE_LOCAL", "1") != "0"
  collector.run("local-contract", "OpenAPI 与实现路由契约", ["ruby", "scripts/validate-openapi.rb"])
  collector.run("local-migration", "空库与上一稳定版 Migration", ["make", "migration-check"])
  collector.run("local-security", "Secret 扫描与安全策略", ["make", "security"])
  collector.run("local-license", "依赖 SPDX 许可证策略", ["make", "license"])
  collector.run("local-build", "Server/Client 双发行物构建", ["make", "build"])
else
  collector.skipped("local-gates", "本地仓库门禁", "EXTERNAL_ACCEPTANCE_LOCAL=0，已由调用方显式跳过。")
end

network_required = %w[
  FRP_E2E_FRPS_BINARY FRP_E2E_FRPS_CONFIG FRP_E2E_FRPC_BINARY
  FRP_E2E_FRPC_CONFIG FRP_E2E_URL
]
missing_network = network_required.reject { |name| !ENV.fetch(name, "").empty? }
if missing_network.empty?
  network_env = ENV.slice(*network_required, "FRP_E2E_FRPS_READY_PORT", "FRP_E2E_FRPS_READY_HOST", "FRP_E2E_READY_WAIT_SECONDS", "FRP_E2E_WAIT_SECONDS", "FRP_E2E_FRPS_SHA256", "FRP_E2E_FRPC_SHA256")
  collector.run("frp-network-e2e", "固定 FRPS/FRPC 真实网络代理 E2E", ["./scripts/frp-network-e2e.sh"], env: network_env)
else
  collector.blocked("frp-network-e2e", "固定 FRPS/FRPC 真实网络代理 E2E", missing_network, "需要固定版本二进制、配置和隔离代理 URL；缺少项不会被模拟。")
end

if ENV.fetch("FRPC_VERIFY_BINARY", "").empty?
  collector.blocked("frpc-verify", "固定版本 FRPC 配置 verify", ["FRPC_VERIFY_BINARY"], "没有固定 FRPC 二进制时不接受仅凭配置渲染的结论。")
else
  collector.run("frpc-verify", "固定版本 FRPC 配置 verify", ["make", "frpc-verify"], env: ENV.slice("FRPC_VERIFY_BINARY", "FRPC_VERIFY_VERSION"))
end

plugin_required = %w[FRP_E2E_FRPS_BINARY FRP_E2E_FRPC_BINARY]
missing_plugin = plugin_required.reject { |name| !ENV.fetch(name, "").empty? }
if missing_plugin.empty?
  collector.run("frp-plugin-network-e2e", "真实 FRPS Plugin 网络 E2E", ["make", "plugin-e2e"], env: ENV.slice(*plugin_required, "FRP_E2E_FRPS_SHA256", "FRP_E2E_FRPC_SHA256"))
else
  collector.blocked("frp-plugin-network-e2e", "真实 FRPS Plugin 网络 E2E", missing_plugin, "需要 Linux/固定 FRP 二进制；协议单测不能替代真实 Plugin E2E。")
end

evidence_path = ENV.fetch("EXTERNAL_ACCEPTANCE_EVIDENCE", "")
if evidence_path.empty?
  collector.blocked("provider-evidence", "Provider、目标环境与发布签字证据", ["EXTERNAL_ACCEPTANCE_EVIDENCE"], "需要 Cloudflare Sandbox、ACME Staging、TLS、目标硬件、故障注入、签名和负责人签字的机器可读证据。")
else
  collector.evidence(File.expand_path(evidence_path, ROOT))
end

report = collector.report
FileUtils.mkdir_p(File.dirname(REPORT_PATH))
File.open(REPORT_PATH, "w", 0o600) { |file| file.write(JSON.pretty_generate(report) + "\n") }
File.chmod(0o600, REPORT_PATH)
puts JSON.pretty_generate(report)
warn "external acceptance report: #{REPORT_PATH} (status=#{report["status"]})"
  exit(report["status"] == "passed" ? 0 : report["status"] == "blocked" ? 2 : 1)
end

run_external_acceptance if $PROGRAM_NAME == __FILE__
