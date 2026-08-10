workflow_path = File.expand_path("../.github/workflows/target-acceptance.yml", __dir__)
workflow = File.read(workflow_path)
errors = []

required_fragments = {
  "manual trigger" => "workflow_dispatch:",
  "Ubuntu target runner" => "runs-on: ubuntu-24.04",
  "Ruby runtime" => "ruby-version: '3.3'",
  "Go runtime" => "go-version: '1.25.x'",
  "fixed FRP release" => "frp_0.68.0_linux_amd64.tar.gz",
  "release digest verification" => "sha256sum --check --status",
  "target collector" => "ruby scripts/target-acceptance.rb",
  "target report" => "output/target-acceptance.json",
  "target artifacts" => "output/target-acceptance/",
  "fixed performance log" => "target-acceptance-performance-fixed-2vcpu-2g.log",
  "artifact upload" => "actions/upload-artifact@v4"
}

required_fragments.each do |name, fragment|
  errors << "missing #{name}: #{fragment}" unless workflow.include?(fragment)
end

errors << "target acceptance must remain manual-only" if workflow.match?(/^\s*(push|pull_request):\s*$/)
errors << "target acceptance must upload artifacts after failures" unless workflow.include?("if: always()")
errors << "target acceptance must not use production credentials" if workflow.match?(/CLOUDFLARE|ACME|COSIGN|PRODUCTION/i)

abort "target acceptance workflow policy failed:\n#{errors.join("\n")}" unless errors.empty?
puts "target acceptance workflow policy valid: manual Ubuntu 24.04 target profile with fixed FRP evidence"
