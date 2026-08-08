#!/usr/bin/env ruby

workflow_path = File.expand_path("../.github/workflows/release.yml", __dir__)
workflow = File.read(workflow_path)
errors = []

required_fragments = {
  "revision-bound external evidence" => "EXTERNAL_ACCEPTANCE_EVIDENCE: release-evidence.json",
  "fixed FRP release acceptance" => "make external-acceptance",
  "keyless signing" => "cosign sign-blob",
  "signature verification" => "cosign verify-blob",
  "OIDC issuer verification" => "--certificate-oidc-issuer",
  "workflow identity verification" => "--certificate-identity",
  "GitHub release publication" => "softprops/action-gh-release@v2"
}
required_fragments.each do |name, fragment|
  errors << "missing #{name}: #{fragment}" unless workflow.include?(fragment)
end

sign_index = workflow.index("cosign sign-blob")
verify_index = workflow.index("cosign verify-blob")
publish_index = workflow.index("softprops/action-gh-release@v2")
evidence_index = workflow.index("EXTERNAL_ACCEPTANCE_EVIDENCE: release-evidence.json")

if evidence_index && sign_index && evidence_index > sign_index
  errors << "external evidence gate must precede signing"
end
if sign_index && verify_index && sign_index > verify_index
  errors << "signature verification must follow signing"
end
if verify_index && publish_index && verify_index > publish_index
  errors << "signature verification must precede release publication"
end

unless workflow.include?("identity=\"https://github.com/${GITHUB_REPOSITORY}/.github/workflows/release.yml@${GITHUB_REF}\"")
  errors << "keyless identity must bind the repository, workflow path, and current ref"
end

abort "release workflow policy failed:\n#{errors.join("\n")}" unless errors.empty?
puts "release workflow policy valid: evidence gate, keyless signing, identity verification, and publication order"
