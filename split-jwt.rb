#!/usr/bin/env ruby
#
# INSTALL
# -------
#
#   chmod +x split-jwt.rb
#
# USAGE
# -----
#
#   split-jwt.rb
#     [--indent={INDENT_LENGTH}]               # -i {INDENT_LENGTH}
#     --jwt={JWT_STRING}                       # -j {JWT_STRING}
#     --line-length={LINE_LENGTH}              # -l {LINE_LENGTH}
#
# AUTHORS
# -------
#
#   AI Assistant
#
# CHANGELOG
# -------
#   2023-05-10
#     - Initial release
#

require 'bundler/inline'

gemfile do
  source 'https://rubygems.org'
  gem 'optparse'
end

#------------------------------------------------------------
# main
#------------------------------------------------------------
def main(args)
  # Process the command line options.
  options = Options.process(args)

  # Split the JWT
  split_jwt = split_jwt(options.jwt, options.line_length, options.indent)

  # Print the split JWT
  puts split_jwt
end

#------------------------------------------------------------
# Split the JWT into lines
#------------------------------------------------------------
def split_jwt(jwt, line_length, indent)
  first_line_length = line_length - indent
  first_line = jwt[0...first_line_length]
  remaining_jwt = jwt[first_line_length..]

  lines = [first_line]
  lines += remaining_jwt.scan(/.{1,#{line_length}}/)

  lines[0] = "#{' ' * indent}#{lines[0]}"
  lines[1..].map! { |line| "#{' ' * indent}#{line}" }

  lines.join("\n")
end


#------------------------------------------------------------
# Command line options
#------------------------------------------------------------
class Options < OptionParser
  DESC_JWT = "The JWT string to be split."
  DESC_LINE_LENGTH = "The length of each line after splitting."
  DESC_INDENT = "Number of spaces to indent each line (default: 0)."

  attr_reader :jwt, :line_length, :indent

  def initialize
    super

    @jwt = nil
    @line_length = nil
    @indent = 0

    self.on('-i INDENT', '--indent=INDENT', Integer, DESC_INDENT) do |indent|
      @indent = indent
    end
    self.on('-j JWT', '--jwt=JWT', DESC_JWT) do |jwt|
      @jwt = jwt
    end

    self.on('-l LENGTH', '--line-length=LENGTH', Integer, DESC_LINE_LENGTH) do |length|
      @line_length = length
    end
  end

  def error_if_missing(value, option)
    if value.nil?
      raise OptionParser::ParseError.new "'#{option}' is missing."
    end
  end

  def verify
    error_if_missing(@jwt, '--jwt=JWT')
    error_if_missing(@line_length, '--line-length=LENGTH')
  end

  def self.process(args)
    options = Options.new
    options.parse(args)
    options.verify()

    return options
  end
end

#------------------------------------------------------------
# Entry Point
#------------------------------------------------------------
main(ARGV)
