#!/usr/bin/env ruby

# A deliberately small, redacted Cloudflare Sandbox smoke runner. It performs
# writes only after the caller names a disposable test zone and provides the
# exact confirmation string below. It is not invoked by pull-request CI.

require "json"
require "net/http"
require "time"
require "uri"

class CloudflareSandboxE2E
  CONFIRMATION = "disposable-zone"
  OFFICIAL_API_BASE_URL = "https://api.cloudflare.com/client/v4"
  INITIAL_CONTENT = "192.0.2.10"
  UPDATED_CONTENT = "192.0.2.11"

  def initialize
    @token = ENV.fetch("CLOUDFLARE_E2E_API_TOKEN")
    @zone_id = ENV.fetch("CLOUDFLARE_E2E_ZONE_ID")
    @record_name = ENV.fetch("CLOUDFLARE_E2E_RECORD_NAME")
    @base_url = ENV.fetch("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4").sub(%r{/\z}, "")
    @steps = []
    @request_ids = []
    @created_id = nil
    @candidate_contents = [INITIAL_CONTENT, UPDATED_CONTENT]
    @commit = ENV["FRP_ACCEPTANCE_EXPECTED_COMMIT"] || ENV["GITHUB_SHA"]
    validate_inputs
  rescue KeyError => e
    abort("missing required environment variable: #{e.key}")
  end

  def run
    require_confirmation
    step("token-verify", "Verify the scoped API token") do
      response = request(:get, "/user/tokens/verify")
      raise "Cloudflare token verification returned success=false" unless response.fetch("success")
    end

    zone = nil
    step("zone-read", "Read the explicitly selected disposable zone") do
      response = request(:get, "/zones/#{path_escape(@zone_id)}")
      zone = response.fetch("result")
      expected = ENV["CLOUDFLARE_E2E_EXPECTED_ZONE_NAME"]
      if expected && zone.fetch("name") != expected
        raise "selected zone name #{zone.fetch("name")} does not match expected #{expected}"
      end
    end

    ensure_no_existing_record

    begin
      create_record
      verify_record(INITIAL_CONTENT, "create-readback")
      update_record
      verify_record(UPDATED_CONTENT, "update-readback")
    ensure
      cleanup_record
    end

    status = @cleanup_error ? "failed" : "passed"
    finish(status)
    exit(status == "passed" ? 0 : 1)
  rescue StandardError => e
    @error = redact(e.message)
    finish("failed")
    exit 1
  end

  private

  def validate_inputs
    raise "CLOUDFLARE_E2E_API_TOKEN must not be empty" if @token.strip.empty?
    unless @zone_id.match?(/\A[a-zA-Z0-9_-]{8,128}\z/)
      raise "CLOUDFLARE_E2E_ZONE_ID has an invalid format"
    end
    unless @record_name.match?(/\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\z/)
      raise "CLOUDFLARE_E2E_RECORD_NAME must be a fully-qualified DNS name"
    end
    self.class.validate_api_base_url(@base_url)
    validate_commit(@commit) if @commit
  rescue URI::InvalidURIError
    raise "CLOUDFLARE_API_BASE_URL is invalid"
  end

  def validate_commit(commit)
    return if commit.match?(/\A[0-9a-f]{40}\z/)

    raise "FRP_ACCEPTANCE_EXPECTED_COMMIT must be a 40-character commit SHA"
  end

  def self.validate_api_base_url(raw)
    normalized = raw.to_s.sub(%r{/\z}, "")
    uri = URI.parse(normalized)
    return if uri.is_a?(URI::HTTPS) && normalized == OFFICIAL_API_BASE_URL && uri.user.nil? && uri.query.nil? && uri.fragment.nil?

    raise "CLOUDFLARE_API_BASE_URL must be exactly the official HTTPS Cloudflare API endpoint"
  end

  def require_confirmation
    return if ENV["CLOUDFLARE_E2E_CONFIRM"] == CONFIRMATION

    raise "set CLOUDFLARE_E2E_CONFIRM=#{CONFIRMATION} to authorize disposable-zone DNS writes"
  end

  def ensure_no_existing_record
    step("record-preflight", "Refuse to touch an existing record with the same name") do
      records = list_records
      raise "record name already exists; choose a fresh disposable name" unless records.empty?
    end
  end

  def create_record
    step("record-create", "Create one disposable A record") do
      response = request(:post, dns_records_path, {
        "type" => "A",
        "name" => @record_name,
        "content" => INITIAL_CONTENT,
        "ttl" => 60,
        "proxied" => false
      })
      @created_id = response.fetch("result").fetch("id")
      raise "Cloudflare returned an empty record id" if @created_id.empty?
    end
  end

  def update_record
    step("record-upsert", "Update the same record without creating a duplicate") do
      raise "record id is unavailable" if @created_id.to_s.empty?

      request(:put, "#{dns_records_path}/#{path_escape(@created_id)}", {
        "type" => "A",
        "name" => @record_name,
        "content" => UPDATED_CONTENT,
        "ttl" => 60,
        "proxied" => false
      })
    end
  end

  def verify_record(expected_content, step_id)
    step(step_id, "Query the record and verify a single expected state") do
      records = list_records
      raise "expected one record, found #{records.length}" unless records.length == 1
      record = records.first
      unless record["id"] == @created_id && record["content"] == expected_content && record["type"] == "A"
        raise "record state did not match expected content"
      end
    end
  end

  def cleanup_record
    step("record-cleanup", "Delete the disposable record and verify absence") do
      record_id = @created_id
      if record_id.to_s.empty?
        candidates = list_records.select { |record| @candidate_contents.include?(record["content"]) }
        raise "ambiguous cleanup after an uncertain create response" if candidates.length > 1
        record_id = candidates.first&.fetch("id")
      end
      if record_id
        request(:delete, "#{dns_records_path}/#{path_escape(record_id)}")
        raise "record remained after cleanup" unless list_records.empty?
      end
    end
  rescue StandardError => e
    @cleanup_error = redact(e.message)
  end

  def list_records
    query = URI.encode_www_form("type" => "A", "name" => @record_name, "per_page" => 100)
    request(:get, "#{dns_records_path}?#{query}").fetch("result")
  end

  def dns_records_path
    "/zones/#{path_escape(@zone_id)}/dns_records"
  end

  def path_escape(value)
    URI::DEFAULT_PARSER.escape(value.to_s, /[^A-Za-z0-9_.~-]/)
  end

  def request(method, path, body = nil)
    uri = URI.parse("#{@base_url}#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = true
    http.open_timeout = Integer(ENV.fetch("CLOUDFLARE_E2E_OPEN_TIMEOUT", "10"))
    http.read_timeout = Integer(ENV.fetch("CLOUDFLARE_E2E_READ_TIMEOUT", "30"))
    request_class = { get: Net::HTTP::Get, post: Net::HTTP::Post, put: Net::HTTP::Put, delete: Net::HTTP::Delete }.fetch(method)
    request = request_class.new(uri)
    request["Authorization"] = "Bearer #{@token}"
    request["Accept"] = "application/json"
    if body
      request["Content-Type"] = "application/json"
      request.body = JSON.generate(body)
    end
    response = http.request(request)
    @request_ids << (response["cf-ray"] || response["x-request-id"] || "http-#{response.code}")
    payload = response.body.to_s.empty? ? {} : JSON.parse(response.body)
    unless response.is_a?(Net::HTTPSuccess) && payload.fetch("success", true)
      errors = payload.fetch("errors", []).map { |error| error["message"] }.compact.join(", ")
      raise "Cloudflare API #{response.code}: #{errors.empty? ? response.message : errors}"
    end
    payload
  rescue JSON::ParserError
    raise "Cloudflare API returned invalid JSON"
  end

  def step(id, title)
    started = Time.now.utc
    yield
    @steps << { "id" => id, "title" => title, "status" => "passed", "executed_at" => started.iso8601(6) }
  rescue StandardError => e
    @steps << { "id" => id, "title" => title, "status" => "failed", "executed_at" => started.iso8601(6), "error" => redact(e.message) }
    raise
  end

  def finish(status)
    status = "failed" if @cleanup_error
    puts JSON.pretty_generate(
      "schema_version" => "v1",
      "status" => status,
      "repository" => "sshiong/frp-panel-platform-v3",
      "commit" => @commit,
      "generated_at" => Time.now.utc.iso8601(6),
      "environment" => { "provider" => "Cloudflare Sandbox", "zone_id_present" => true, "record_name" => @record_name },
      "steps" => @steps,
      "request_ids" => @request_ids.uniq,
      "error" => @error,
      "cleanup_error" => @cleanup_error
    ).sub(/\n\z/, "")
    puts
  end

  def redact(value)
    value.to_s.gsub(@token, "[REDACTED]")
  end
end

CloudflareSandboxE2E.new.run if $PROGRAM_NAME == __FILE__
