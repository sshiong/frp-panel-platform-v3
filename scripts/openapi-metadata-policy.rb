#!/usr/bin/env ruby

require "yaml"

ROOT = File.expand_path("..", __dir__)
MUTATING_METHODS = %w[post put patch delete].freeze
METHODS = %w[get post put patch delete options head].freeze
IDEMPOTENCY_REF = "#/components/parameters/IdempotencyKey"
PROBLEM_REF_SUFFIX = "/Problem"

CONTRACTS = [
  {
    path: File.join(ROOT, "contracts", "openapi.yaml"),
    public: [
      ["get", "/api/v1/compatibility"],
      ["post", "/api/v1/auth/client-login"],
      ["post", "/api/v1/auth/admin-login"]
    ]
  },
  {
    path: File.join(ROOT, "contracts", "client-openapi.yaml"),
    public: [
      ["post", "/api/v1/login"],
      ["post", "/api/v1/server/inspect"]
    ]
  }
].freeze

errors = []
operation_count = 0

CONTRACTS.each do |contract|
  document = YAML.load_file(contract[:path])
  public_operations = contract[:public]

  document.fetch("paths").each do |route, item|
    item.each do |method, operation|
      next unless METHODS.include?(method)

      operation_count += 1
      key = [method, route]
      is_public = public_operations.include?(key)
      security = operation["security"]
      parameters = item.fetch("parameters", []) + operation.fetch("parameters", [])

      if is_public
        errors << "#{contract[:path]}: #{method.upcase} #{route} must not declare security" unless security.nil? || security.empty?
      else
        errors << "#{contract[:path]}: #{method.upcase} #{route} must declare security" unless security.is_a?(Array) && !security.empty?
      end

      if MUTATING_METHODS.include?(method) && !is_public
        refs = parameters.each_with_object([]) do |parameter, values|
          values << parameter["$ref"] if parameter.is_a?(Hash) && parameter["$ref"]
        end
        errors << "#{contract[:path]}: #{method.upcase} #{route} must require Idempotency-Key" unless refs.include?(IDEMPOTENCY_REF)
      end

      route.scan(/\{([^}]+)\}/).flatten.each do |name|
        parameter = parameters.find do |candidate|
          candidate.is_a?(Hash) && candidate["in"] == "path" && candidate["name"] == name
        end
        unless parameter && parameter["required"] == true
          errors << "#{contract[:path]}: #{method.upcase} #{route} must declare required path parameter #{name}"
        end
      end

      operation.fetch("responses", {}).each do |status, response|
        status_text = status.to_s
        next unless status_text.match?(/\A(?:4|5)\d{2}\z/) || status_text == "default"

        ref = response.is_a?(Hash) ? response["$ref"].to_s : ""
        errors << "#{contract[:path]}: #{method.upcase} #{route} #{status} must use Problem Details" unless ref.end_with?(PROBLEM_REF_SUFFIX)
      end
    end
  end
end

if errors.empty?
  puts "OpenAPI metadata policy valid: #{operation_count} operations have explicit public/authenticated, idempotency, path, and error boundaries"
else
  warn errors.join("\n")
  exit 1
end
