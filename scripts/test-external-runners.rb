#!/usr/bin/env ruby

require "json"
require "open3"
require "rbconfig"
require "tmpdir"

ROOT = File.expand_path("..", __dir__)
VALIDATOR = File.join(ROOT, "scripts", "validate-external-runners.rb")
commit, status = Open3.capture2("git", "rev-parse", "HEAD", chdir: ROOT)
abort("cannot resolve test commit: #{status}") unless status.success?
commit = commit.strip

def write_json(path, document)
  File.open(path, File::WRONLY | File::CREAT | File::TRUNC, 0o600) do |file|
    file.write(JSON.generate(document))
  end
end

base = {
  "schema_version" => "v1",
  "status" => "passed",
  "repository" => "sshiong/frp-panel-platform-v3",
  "commit" => commit,
  "generated_at" => "2026-08-10T00:00:00Z",
  "steps" => [{ "id" => "smoke", "status" => "passed" }]
}

Dir.mktmpdir("external-runners-test") do |dir|
  cloudflare = base.merge("environment" => { "provider" => "Cloudflare Sandbox" })
  acme = base.merge("environment" => { "ca" => "ACME Staging" })
  cloudflare_path = File.join(dir, "cloudflare.json")
  acme_path = File.join(dir, "acme.json")
  output_path = File.join(dir, "index.json")
  write_json(cloudflare_path, cloudflare)
  write_json(acme_path, acme)

  env = { "FRP_ACCEPTANCE_EXPECTED_COMMIT" => commit }
  command = [RbConfig.ruby, VALIDATOR, "--cloudflare", cloudflare_path, "--acme", acme_path, "--output", output_path]
  _stdout, stderr, status = Open3.capture3(env, *command, chdir: ROOT)
  abort("valid runner evidence was rejected: #{stderr}") unless status.success?
  parsed = JSON.parse(File.read(output_path))
  abort("runner index did not preserve the exact commit") unless parsed["commit"] == commit
  abort("runner index did not use mode 0600") unless (File.stat(output_path).mode & 0o777) == 0o600

  stale = acme.merge("commit" => "0" * 40)
  write_json(acme_path, stale)
  _stdout, _stderr, status = Open3.capture3(env, *command, chdir: ROOT)
  abort("stale runner evidence was accepted") if status.success?
end

puts "external runner evidence validation checks passed"
