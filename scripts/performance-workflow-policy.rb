workflow_path = File.expand_path("../.github/workflows/performance.yml", __dir__)
workflow = File.read(workflow_path)
errors = []

required_fragments = {
  "fixed profile job" => "fixed-2vcpu-2g:",
  "Ubuntu runner" => "runs-on: ubuntu-24.04",
  "CPU limit" => "--cpus=2",
  "memory limit" => "--memory=2g",
  "no swap expansion" => "--memory-swap=2g",
  "Linux Go image" => "golang:1.25-bookworm",
  "server performance profile" => "^TestPerformance(Baseline|Scale|SessionReplacement)$",
  "client performance profile" => "^TestPerformanceConfigSubmitToClientApply$",
  "performance scale flag" => "FRP_PERF_SCALE=1",
  "fixed evidence artifact" => "linux-fixed-2vcpu-2g-performance"
}

required_fragments.each do |name, fragment|
  errors << "missing #{name}: #{fragment}" unless workflow.include?(fragment)
end

fixed_job_start = workflow.index("fixed-2vcpu-2g:")
artifact_index = workflow.index("linux-fixed-2vcpu-2g-performance")
errors << "fixed performance artifact must be declared inside the fixed profile" if fixed_job_start.nil? || artifact_index.nil? || artifact_index < fixed_job_start

abort "performance workflow policy failed:\n#{errors.join("\n")}" unless errors.empty?
puts "performance workflow policy valid: fixed 2 vCPU/2 GiB Linux profile and complete PERF suite"
