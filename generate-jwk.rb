#!/usr/bin/env ruby
#
# INSTALL
# -------
#
#   Make sure the script is executable
#   chmod +x generate-jwk.rb
#
# USAGE
# -----
#
#   generate-jwk.rb
#     --key={PRIVATE_KEY_IN_JWK_FORMAT}
#
# AUTHORS
# -------
#
#   Jan Vereecken <jan.vereecken@hey.com>
#

require 'bundler/inline'

gemfile do
  source 'https://rubygems.org'
  gem 'json-jwt'
  gem 'optparse'
end

require 'openssl'
require 'securerandom'
require 'time'


#------------------------------------------------------------
# main
#------------------------------------------------------------
def main(args)
  # Process the command line options.
  options = Options.process(args)

  # Prepare the payload of the client assertion.
  jwk = generate_jwk(options)

  # Write the client assertion to the standard output.
  puts jwk
end


#------------------------------------------------------------
# Prepare the payload of the client assertion.
#------------------------------------------------------------
def generate_jwk(options)
  ec = OpenSSL::PKey::EC.generate('prime256v1')
  jwk = JSON::JWK.new(ec, { alg: 'ES256' })

  if options.key
      File.open(options.key, 'w') do |f|
        f.write(jwk.to_json)
      end
  end

  jwk
end

#------------------------------------------------------------
# Command line options
#------------------------------------------------------------
class Options < OptionParser
    DESC_KEY      = "A file containing a private key in the JWK format."

    attr_reader :key

  def initialize
    super

    @key      = nil

    self.on('-k FILE', '--key=FILE', DESC_KEY) do |file|
      @key = file
    end
  end

  private

  def error_if_missing(value, option)
    if value.nil?
      raise OptionParser::ParseError.new "'#{option}' is missing."
    end
  end

  public

  def verify
    error_if_missing(@key,      '--key=FILE')
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
