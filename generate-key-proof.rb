#!/usr/bin/env ruby
#
# INSTALL
# -------
#
#   chmod +x generate-key-proof.rb
#
# USAGE
# -----
#
#   generate-key-proof.rb
#     --client-id={CLIENT_ID}                  # -c {CLIENT_ID}
#     --credential-issuer={CREDENTIAL_ISSUER}  # -i {CREDENTIAL_ISSUER}
#     --key={PRIVATE_KEY_IN_JWK_FORMAT}        # -k {PRIVATE_KEY_IN_JWK_FORMAT}
#     --nonce={C_NONCE}                        # -n {C_NONCE}
#
# AUTHORS
# -------
#
#   Takahiko Kawasaki <taka@authlete.com>
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

  # Prepare the payload of the key proof.
  payload = build_payload(options)

  # Generate a JWS by signing with the key.
  proof = sign(payload, options.key)

  # Write the key proof to the standard output.
  puts proof
end


#------------------------------------------------------------
# Prepare the payload of the key proof.
#------------------------------------------------------------
def build_payload(options)
  # The current time in seconds for time-related claims
  now = Time.now.to_i

  # Payload of a key proof
  {
    iss:   options.client_id,
    aud:   options.credential_issuer,
    iat:   now,
    nonce: options.nonce
  }
end


#------------------------------------------------------------
# Generate a JWS by signing with the key.
#------------------------------------------------------------
def sign(payload, jwk)
  # Prepare a JWT with the header and the payload.
  jwt = JSON::JWT.new(payload)

  # Set up some header parameters.
  jwt.typ = 'openid4vci-proof+jwt'
  jwt.jwk = jwk.normalize  # to a public key

  # Sign the JWT with the key and convert it to JWS.
  jwt.sign(jwk).to_s
end


#------------------------------------------------------------
# Command line options
#------------------------------------------------------------
class Options < OptionParser
  DESC_CLIENT_ID         = "The identifier of the client application (wallet)."
  DESC_CREDENTIAL_ISSUER = "The identifier of the credential issuer."
  DESC_KEY               = "A file containing a private key in the JWK format."
  DESC_NONCE             = "The 'c_nonce' value that has been issued from the token endpoint or the credential endpoint."

  attr_reader :client_id, :credential_issuer, :key, :nonce

  def initialize
    super

    @client_id         = nil
    @credential_issuer = nil
    @key               = nil
    @nonce             = nil

    self.on('-c CLIENT_ID', '--client-id=CLIENT_ID', DESC_CLIENT_ID) do |client_id|
      @client_id = client_id
    end

    self.on('-i CREDENTIAL_ISSUER', '--credential-issuer=CREDENTIAL_ISSUER', DESC_CREDENTIAL_ISSUER) do |issuer|
      @credential_issuer = issuer
    end

    self.on('-k FILE', '--key=FILE', DESC_KEY) do |file|
      @key = self.read_jwk(file)
    end

    self.on('-n NONCE', '--nonce=NONCE', DESC_NONCE) do |nonce|
      @nonce = nonce
    end
  end

  private

  def read_jwk(file)
    json = File.read(file)
    hash = JSON.parse(json, {symbolize_names: true})
    JSON::JWK.new(hash)
  end

  def error_if_missing(value, option)
    if value.nil?
      raise OptionParser::ParseError.new "'#{option}' is missing."
    end
  end

  public

  def verify
    error_if_missing(@client_id,         '--client-id=CLIENT_ID')
    error_if_missing(@credential_issuer, '--credential-issuer=CREDENTIAL_ISSUER')
    error_if_missing(@key,               '--key=FILE')
    error_if_missing(@nonce,             '--nonce=NONCE')
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
