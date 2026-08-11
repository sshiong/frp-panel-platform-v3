#!/usr/bin/env ruby

# Keep frontend callers on the generated OpenAPI path/method contract. The
# small wrapper in each panel's api.ts owns transport concerns; feature code
# must not fall back to untyped DTOs, JSON-stringified bodies, or URL assembly.

root = File.expand_path("..", __dir__)
sources = Dir[File.join(root, "web", "{admin,client}", "src", "**", "*.{ts,vue}")].sort
violations = []

sources.each do |path|
  next if File.basename(path) == "api.ts"

  File.readlines(path, encoding: "UTF-8").each_with_index do |line, index|
    line_number = index + 1
    violations << "#{path}:#{line_number}: generic api<T> bypasses generated response types" if line.match?(/\bapi\s*</)
    violations << "#{path}:#{line_number}: API callers must pass method before the OpenAPI schema path" if line.match?(/\bapi\(\s*[`\"']\/api\/v1/)
    violations << "#{path}:#{line_number}: API paths must not be assembled with template literals" if line.match?(/\bapi\(\s*`/)
    violations << "#{path}:#{line_number}: request bodies must be objects typed by openapi-fetch" if line.include?("JSON.stringify(")
    violations << "#{path}:#{line_number}: direct generated client access must stay inside api.ts" if line.match?(/\b(?:serverAPI|clientAPI)\./)
  end
end

if violations.empty?
  puts "OpenAPI client policy valid: frontend requests use generated paths, methods, parameters, bodies, and response types"
else
  warn violations.join("\n")
  exit 1
end
