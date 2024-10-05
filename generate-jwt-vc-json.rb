#!/usr/bin/env ruby
#
# INSTALL
# -------
#
#   chmod +x generate-jwt-vc-json.rb
#
# USAGE
# -----
#
#   generate-jwt-vc-json.rb
#     --key={PRIVATE_KEY_IN_JWK_FORMAT}        # -k {PRIVATE_KEY_IN_JWK_FORMAT}
#     --vc={VC_IN_JSON_FORMAT}                 # -v {VC_IN_JSON_FORMAT}
#
# AUTHORS
# -------
#
#   Jan Vereecken <ciao@janvereecken.com>
#
# CHANGELOG
# -------
#   2024-10-04
#     - Initial release
#

require 'bundler/inline'

gemfile do
  source 'https://rubygems.org'
  gem 'json-jwt'
  gem 'optparse'
end

require 'securerandom'
require 'time'

#------------------------------------------------------------
# main
#------------------------------------------------------------
def main(args)
  # Process the command line options.
  options = Options.process(args)

  # Prepare the payload of the jwt_vc_json credential.
  payload = build_payload(options)

  # Generate a JWS by signing with the key.
  jwt_vc_json = sign(payload, options.key)

  # Write the jwt_vc_json credential to standard output.
  puts jwt_vc_json
end


#------------------------------------------------------------
# Prepare the payload of the jwt_vc_json credential.
#------------------------------------------------------------
def build_payload(options)
  {
    vc: options.vc,
    iss: options.vc[:issuer],
    nbf: Time.parse(options.vc[:issuanceDate]).to_i,
    jti: options.vc[:id],
    sub: options.vc[:credentialSubject][:id]
  }
end


#------------------------------------------------------------
# Generate a JWS by signing with the key.
#------------------------------------------------------------
def sign(payload, jwk)
  # Prepare a JWT with the header and the payload.
  jwt = JSON::JWT.new(payload)

  # Sign the JWT with the key and convert it to JWS.
  jwt.sign(jwk).to_s
end


#------------------------------------------------------------
# Command line options
#------------------------------------------------------------
class Options < OptionParser
  DESC_KEY = "A file containing a private key in the JWK format."
  DESC_VC  = "A file containing a verifiable credential in JSON format."

  attr_reader :key, :vc

  def initialize
    super

    @key = nil
    @vc  = nil

    self.on('-k FILE', '--key=FILE', DESC_KEY) do |file|
      @key = self.read_jwk(file)
    end

    self.on('-v FILE', '--vc=FILE', DESC_VC) do |file|
      @vc = read_vc(file)
    end
  end

  private

  def read_jwk(file)
    json = File.read(file)
    hash = JSON.parse(json, {symbolize_names: true})
    JSON::JWK.new(hash)
  end

  def read_vc(file)
    json = File.read(file)
    JSON.parse(json, {symbolize_names: true})
  end

  def error_if_missing(value, option)
    if value.nil?
      raise OptionParser::ParseError.new "'#{option}' is missing."
    end
  end

  public

  def verify
    error_if_missing(@key, '--key=FILE')
    error_if_missing(@vc,  '--vc=FILE')
  end

  def self.process(args)
    options = Options.new
    options.parse(args)
    options.verify()

    return options
  end
end


#------------------------------------------------------------
# Extension of the json-jwt library
#------------------------------------------------------------
module JSON
  class JWT
    # Override the 'sign' method not to include 'kid'.
    def sign(private_key_or_secret, algorithm = :autodetect)
      jws = JWS.new self
      jws.alg = algorithm
      jws.sign! private_key_or_secret
    end
  end
end


#------------------------------------------------------------
# Entry Point
#------------------------------------------------------------
main(ARGV)
