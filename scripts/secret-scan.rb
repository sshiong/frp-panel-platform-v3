#!/usr/bin/env ruby

root = File.expand_path("..", __dir__)
ignored_directories = %w[.git node_modules dist build output]
patterns = {
  "private key material" => /-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP|PRIVATE) KEY-----/,
  "GitHub token" => /\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/,
  "AWS access key" => /\bAKIA[0-9A-Z]{16}\b/,
  "Slack token" => /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/,
  "OpenAI-style secret" => /\bsk-[A-Za-z0-9]{20,}\b/,
  "long bearer token" => /Authorization\s*:\s*Bearer\s+[A-Za-z0-9._~+\/=\-]{24,}/i
}

findings = []
Dir.glob(File.join(root, "**", "*")).sort.each do |path|
  next unless File.file?(path)
  relative = path.delete_prefix("#{root}/")
  next if ignored_directories.any? { |directory| relative == directory || relative.start_with?("#{directory}/") }
  begin
    bytes = File.binread(path)
    next if bytes.include?("\x00") || bytes.bytesize > 4 * 1024 * 1024
    text = bytes.force_encoding(Encoding::UTF_8)
    next unless text.valid_encoding?
    text.each_line.with_index(1) do |line, line_number|
      patterns.each do |label, pattern|
        findings << "#{relative}:#{line_number}: #{label}" if line.match?(pattern)
      end
    end
  rescue StandardError => error
    warn "secret scan skipped #{relative}: #{error.message}"
  end
end

if findings.empty?
  puts "secret scan clean"
  exit 0
end

warn findings.join("\n")
exit 1
