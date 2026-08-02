#!/usr/bin/env ruby

root = File.expand_path("..", __dir__)
sources = [
  File.join(root, "web", "admin", "src", "style.css"),
  File.join(root, "web", "client", "src", "style.css"),
  File.join(root, "web", "client", "src", "domain.css")
]

forbidden_literals = {
  "rail surface" => /#1b2426/i,
  "panel surface" => /#171d20/i,
  "input surface" => /#151a1d/i,
  "sidebar surface" => /#151b1e/i,
  "dialog surface" => /#1a2124/i,
  "navigation active surface" => /#202a2d/i,
  "navigation hover surface" => /#1d2528/i,
  "sidebar pill surface" => /#182023/i,
  "avatar surface" => /#2e454c/i,
  "dashed border" => /#3a4649/i,
  "shared line" => /#30393d/i,
  "subtle line" => /rgba\(\s*48\s*,\s*57\s*,\s*61\s*,\s*\.65\s*\)/i
}

violations = []
sources.each do |path|
  text = File.read(path)
  # The base palette is declared in the first :root rule. Repeated component
  # surfaces below it must use semantic aliases from the app's tokens.css.
  body = text.include?(":root") ? text.sub(/\A.*?\}/m, "") : text
  forbidden_literals.each do |label, pattern|
    violations << "#{path.delete_prefix("#{root}/")}: #{label} must use a semantic token" if body.match?(pattern)
  end
end

abort "CSS token policy failed:\n#{violations.join("\n")}" unless violations.empty?
puts "CSS token policy valid: repeated surface and border literals use semantic tokens"
