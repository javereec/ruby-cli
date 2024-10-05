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
#     --output={PRIVATE_KEY_IN_JWK_FORMAT}
#
# AUTHORS
# -------
#
#   Jan Vereecken <ciao@janvereecken.com>
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

  # Generate the JWK
  jwk = generate_jwk(options)

  # Write the jwk to the standard output.
  puts jwk
end


#------------------------------------------------------------
# Generate the JWK.
#------------------------------------------------------------
def generate_jwk(options)
  case options.alg
  when 'ES256'
    ec = OpenSSL::PKey::EC.generate('prime256v1')
    jwk = JSON::JWK.new(ec, { alg: options.alg })
  when 'RS256'
    rsa = OpenSSL::PKey::RSA.new(2048)
    jwk = JSON::JWK.new(rsa, { alg: options.alg })
  else
    raise "Unsupported algorithm: #{options.alg}"
  end

  if options.out
    File.open(options.out, 'w') do |f|
      f.write(jwk.to_json)
    end
  end

  jwk
end

#------------------------------------------------------------
# Command line options
#------------------------------------------------------------
class Options < OptionParser
  DESC_ALG = "The algorithm to use for the JWK (ES256, or RS256, default: ES256)."
  DESC_OUT = "A file containing a private key in the JWK format."

    attr_reader :out, :alg

  def initialize
    super

    @out = nil
    @alg = 'ES256'

    self.on('-a ALG', '--alg=ALG', DESC_ALG) do |alg|
      @alg = alg
    end

    self.on('-o FILE', '--out=FILE', DESC_OUT) do |file|
      @out = file
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
