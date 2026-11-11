#!/usr/bin/env ruby
# frozen_string_literal: true

# SPDX-FileCopyrightText: Copyright © 2026 ReallyMe Technologies Limited. All rights reserved
# SPDX-License-Identifier: MIT OR Apache-2.0

require "rbconfig"

root = File.expand_path("..", __dir__)
taxonomy_root = ENV.fetch("REALLYME_IDENTITY_TAXONOMY_ROOT", File.expand_path("../identity-taxonomy", root))
output_pair = ARGV.each_cons(2).find { |argument, _value| argument == "--output" }
unless output_pair
  warn "error: --output is required; conformance evidence must be generated outside the tracked tree"
  exit 2
end
output_path = File.expand_path(output_pair.fetch(1), Dir.pwd)
repository_prefix = "#{root}#{File::SEPARATOR}"
if output_path == root || output_path.start_with?(repository_prefix)
  warn "error: --output must be outside the repository tree"
  exit 2
end
arguments = [
  RbConfig.ruby,
  File.join(taxonomy_root, "scripts", "generate_repository_conformance_ledger.rb"),
  "--repository", "reallyme/zk",
  "--consumer-root", root,
  "--inventory", File.join(taxonomy_root, "conformance", "inventory", "requirements.json"),
  "--evidence-map", File.join(root, "conformance", "taxonomy", "conformance-evidence.yaml"),
  "--artifact-map", File.join(root, "conformance", "taxonomy", "conformance-artifacts.yaml"),
  *ARGV
]
exec(*arguments)
