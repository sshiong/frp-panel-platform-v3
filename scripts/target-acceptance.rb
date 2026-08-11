#!/usr/bin/env ruby

require "fileutils"
require "json"
require "open3"
require "optparse"
require "rbconfig"
require "time"

class TargetAcceptance
  ROOT = File.expand_path("..", __dir__)
  REPOSITORY = "sshiong/frp-panel-platform-v3".freeze
  REQUIRED_NETWORK = %w[
    FRP_E2E_FRPS_BINARY FRP_E2E_FRPS_CONFIG FRP_E2E_FRPC_BINARY
    FRP_E2E_FRPC_CONFIG FRP_E2E_URL
  ].freeze
  NETWORK_ENV = (REQUIRED_NETWORK + %w[
    FRP_E2E_FRPS_READY_HOST FRP_E2E_FRPS_READY_PORT FRP_E2E_READY_WAIT_SECONDS
    FRP_E2E_WAIT_SECONDS FRP_E2E_FRPS_SHA256 FRP_E2E_FRPC_SHA256
    FRP_E2E_FIXTURE_DIR FRP_E2E_FIXTURE_HOST FRP_E2E_FIXTURE_PORT
    FRP_E2E_FIXTURE_WAIT_SECONDS
  ]).freeze

  attr_reader :steps

  def initialize(artifact_dir: File.join(ROOT, "output", "target-acceptance"))
    @artifact_dir = File.expand_path(artifact_dir, ROOT)
    @operator = ENV["ACCEPTANCE_OPERATOR"] || ENV["GITHUB_ACTOR"] || ENV["USER"] || "unknown"
    @steps = []
    @secret_values = ENV.values_at(
      "CLOUDFLARE_API_TOKEN", "CLOUDFLARE_E2E_API_TOKEN", "ACME_DNS_API_TOKEN",
      "FRP_ACME_E2E_EMAIL", "COSIGN_KEY", "FRP_E2E_FRPS_SHA256", "FRP_E2E_FRPC_SHA256"
    ).compact.reject { |value| value.to_s.empty? }
  end

  def report
    statuses = @steps.map { |step| step["status"] }
    overall = if statuses.include?("failed")
      "failed"
    elsif statuses.include?("blocked") || statuses.empty?
      "blocked"
    else
      "passed"
    end

    {
      "schema_version" => "v1",
      "kind" => "target-acceptance-report",
      "status" => overall,
      "repository" => REPOSITORY,
      "commit" => git_revision,
      "generated_at" => Time.now.utc.iso8601(6),
      "operator" => @operator,
      "environment" => environment_snapshot,
      "constraints" => {
        "os" => "Linux",
        "cpu" => "2 vCPU",
        "memory" => "2 GiB",
        "memory_swap" => "2 GiB",
        "storage" => "local SSD or documented target disk",
        "sqlite" => "WAL"
      },
      "rules" => {
        "blocked_is_not_passed" => true,
        "target_profile_is_not_production_signoff" => true,
        "secrets_are_never_written_to_this_report" => true
      },
      "steps" => @steps
    }
  end

  def run
    if RbConfig::CONFIG["host_os"].to_s !~ /linux/i
      blocked("target-linux", "Linux target environment", ["Linux runner"], "target acceptance requires a Linux runner; local development host is #{RbConfig::CONFIG["host_os"]}.")
    else
      run_command("fixed-performance", "固定 2 vCPU/2 GiB SQLite WAL 性能 profile", ["./scripts/fixed-performance.sh"], {
        "FRP_FIXED_PERF_LOG_PATH" => File.join(ROOT, "target-acceptance-performance-fixed-2vcpu-2g.log")
      })
      run_command("fault-injection", "Linux 磁盘满、WAL 压力和时钟偏差故障注入", ["./scripts/linux-fault-injection.sh"])
    end

    missing_network = REQUIRED_NETWORK.reject { |name| !ENV.fetch(name, "").empty? }
    if missing_network.empty?
      run_command("frp-network-e2e", "固定 FRPS/FRPC 真实网络代理 E2E", ["./scripts/frp-network-e2e.sh"], env_slice(NETWORK_ENV))
    else
      blocked("frp-network-e2e", "固定 FRPS/FRPC 真实网络代理 E2E", missing_network, "缺少固定版本二进制、配置或隔离代理 URL；不会使用协议模拟替代真实网络检查。")
    end

    if ENV.fetch("FRPC_VERIFY_BINARY", "").empty?
      blocked("frpc-verify", "固定版本 FRPC 配置 verify", ["FRPC_VERIFY_BINARY"], "没有固定 FRPC 二进制时不接受仅凭配置渲染的结论。")
    else
      run_command("frpc-verify", "固定版本 FRPC 配置 verify", ["make", "frpc-verify"], env_slice(%w[FRPC_VERIFY_BINARY FRPC_VERIFY_VERSION]))
    end

    plugin_missing = %w[FRP_E2E_FRPS_BINARY FRP_E2E_FRPC_BINARY].reject { |name| !ENV.fetch(name, "").empty? }
    if plugin_missing.empty?
      run_command("frp-plugin-network-e2e", "真实 FRPS Plugin 网络 E2E", ["make", "plugin-e2e"], env_slice(%w[FRP_E2E_FRPS_BINARY FRP_E2E_FRPC_BINARY FRP_E2E_FRPS_SHA256 FRP_E2E_FRPC_SHA256]))
    else
      blocked("frp-plugin-network-e2e", "真实 FRPS Plugin 网络 E2E", plugin_missing, "需要固定 Linux FRP 二进制；协议单测不能替代真实 Plugin E2E。")
    end

    report
  end

  def write(document, output: File.join(ROOT, "output", "target-acceptance.json"))
    FileUtils.mkdir_p(@artifact_dir, mode: 0o700)
    FileUtils.mkdir_p(File.dirname(output), mode: 0o700)
    File.open(output, "w", 0o600) { |file| file.write(JSON.pretty_generate(document) + "\n") }
    File.chmod(0o600, output)
  end

  def self.validate!(document)
    errors = []
    errors << "root must be an object" unless document.is_a?(Hash)
    return errors unless document.is_a?(Hash)

    errors << "schema_version must be v1" unless document["schema_version"] == "v1"
    errors << "kind must be target-acceptance-report" unless document["kind"] == "target-acceptance-report"
    errors << "repository must be #{REPOSITORY}" unless document["repository"] == REPOSITORY
    errors << "commit must be a 40-character SHA-1" unless document["commit"].to_s.match?(/\A[0-9a-f]{40}\z/)
    errors << "constraints must declare 2 vCPU/2 GiB" unless document["constraints"].is_a?(Hash) && document["constraints"]["cpu"] == "2 vCPU" && document["constraints"]["memory"] == "2 GiB"
    errors << "steps must be a non-empty array" unless document["steps"].is_a?(Array) && !document["steps"].empty?
    errors << "status must remain blocked when a step is incomplete" if document["status"] == "passed" && document.fetch("steps", []).any? { |step| ["blocked", "failed"].include?(step["status"]) }

    document.fetch("steps", []).each do |step|
      id = step["id"] || "unknown"
      errors << "#{id}.status is invalid" unless ["passed", "failed", "blocked"].include?(step["status"])
      %w[environment steps expected actual artifacts operator executed_at].each do |field|
        errors << "#{id}.#{field} is missing" unless step.key?(field)
      end
      errors << "#{id}.steps must be non-empty" unless step["steps"].is_a?(Array) && step["steps"].any? { |value| !value.to_s.strip.empty? }
      errors << "#{id}.artifacts.logs must be non-empty" unless step["artifacts"].is_a?(Hash) && step["artifacts"]["logs"].is_a?(Array) && step["artifacts"]["logs"].any? { |value| !value.to_s.strip.empty? }
      begin
        Time.iso8601(step["executed_at"].to_s)
      rescue ArgumentError
        errors << "#{id}.executed_at must be ISO-8601"
      end
    end
    errors
  end

  def run_command(id, title, command, env = {})
    started = Time.now.utc
    stdout, stderr, status = Open3.capture3(env, *command, chdir: ROOT)
    finished = Time.now.utc
    artifact_path = write_log(id, "STDOUT\n#{stdout}\nSTDERR\n#{stderr}")
    @steps << base_step(id, title, status.success? ? "passed" : "failed", command.map { |part| redact(part.to_s) }.join(" "), artifact_path, started).merge(
      "exit_code" => status.exitstatus,
      "stdout_tail" => tail(stdout),
      "stderr_tail" => tail(stderr),
      "duration_ms" => ((finished - started) * 1000).round,
      "environment_presence" => env.keys.sort.to_h { |name| [name, !env[name].to_s.empty?] }
    )
  rescue Errno::ENOENT => error
    started ||= Time.now.utc
    artifact_path = write_log(id, "COMMAND NOT FOUND\n#{error.message}")
    @steps << base_step(id, title, "failed", redact(error.message), artifact_path, started)
  end

  def blocked(id, title, requirements, detail)
    started = Time.now.utc
    artifact_path = write_log(id, "BLOCKED\n#{detail}\nREQUIREMENTS\n#{requirements.join("\n")}")
    @steps << base_step(id, title, "blocked", detail, artifact_path, started).merge("requirements" => requirements)
  end

  private

  def base_step(id, title, status, actual, artifact_path, started)
    {
      "id" => id,
      "title" => title,
      "status" => status,
      "environment" => environment_snapshot,
      "steps" => ["执行目标环境验收命令并保存脱敏日志"],
      "expected" => "目标环境验收命令返回退出码 0",
      "actual" => actual,
      "artifacts" => { "logs" => [artifact_path], "screenshots" => [], "request_ids" => [] },
      "operator" => @operator,
      "executed_at" => started.iso8601(6)
    }
  end

  def environment_snapshot
    snapshot = {
      "host_os" => RbConfig::CONFIG["host_os"],
      "ci" => ENV.fetch("CI", "false"),
      "working_directory" => ROOT,
      "revision" => git_revision,
      "target_profile" => "Linux / 2 vCPU / 2 GiB / SQLite WAL"
    }
    expected = ENV.fetch("ACCEPTANCE_EXPECTED_COMMIT", "")
    snapshot["expected_revision"] = expected unless expected.empty?
    snapshot
  end

  def write_log(id, content)
    FileUtils.mkdir_p(@artifact_dir, mode: 0o700)
    path = File.join(@artifact_dir, "#{id}.log")
    File.open(path, "w", 0o600) { |file| file.write(redact(content.to_s)) }
    File.chmod(0o600, path)
    path.start_with?("#{ROOT}/") ? path.delete_prefix("#{ROOT}/") : path
  end

  def env_slice(names)
    names.each_with_object({}) { |name, result| result[name] = ENV[name] if ENV.key?(name) }
  end

  def git_revision
    stdout, _stderr, status = Open3.capture3("git", "rev-parse", "HEAD", chdir: ROOT)
    status.success? ? stdout.strip : "unknown"
  end

  def tail(value)
    redact(value.to_s[-12_000, 12_000] || "")
  end

  def redact(value)
    output = value.to_s
    @secret_values.each { |secret| output = output.gsub(secret, "[REDACTED]") }
    output.gsub!(/(?i)(authorization\s*:\s*bearer\s+|(?:token|password|secret|private[_-]?key)\s*[:=]\s*)\S+/, '\\1[REDACTED]')
    output
  end
end

if $PROGRAM_NAME == __FILE__
  options = { output: File.join(TargetAcceptance::ROOT, "output", "target-acceptance.json"), artifact_dir: File.join(TargetAcceptance::ROOT, "output", "target-acceptance") }
  OptionParser.new do |parser|
    parser.banner = "Usage: target-acceptance.rb [--output PATH] [--artifact-dir PATH]"
    parser.on("--output PATH", "write the target report to PATH") { |value| options[:output] = File.expand_path(value, TargetAcceptance::ROOT) }
    parser.on("--artifact-dir PATH", "write mode 0600 step logs below PATH") { |value| options[:artifact_dir] = File.expand_path(value, TargetAcceptance::ROOT) }
  end.parse!

  collector = TargetAcceptance.new(artifact_dir: options[:artifact_dir])
  document = collector.run
  expected_revision = ENV.fetch("ACCEPTANCE_EXPECTED_COMMIT", "")
  if !expected_revision.empty? && document["commit"] != expected_revision
    abort "target acceptance revision mismatch: expected #{expected_revision}, got #{document["commit"]}"
  end
  errors = TargetAcceptance.validate!(document)
  abort errors.join("\n") unless errors.empty?
  collector.write(document, output: options[:output])
  puts JSON.pretty_generate(document)
  warn "target acceptance report: #{options[:output]} (status=#{document["status"]})"
  exit(document["status"] == "passed" ? 0 : document["status"] == "blocked" ? 2 : 1)
end
