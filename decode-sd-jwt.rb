#!/usr/bin/env ruby

require "base64"
require "digest/sha2"
require "json"

def prettify_json(input)
  JSON.pretty_generate(JSON.parse(input))
end

def sha256(input)
  Digest::SHA256.digest(input)
end

def decode_base64url(input)
  Base64.urlsafe_decode64(input)
end

def encode_base64url(input)
  Base64.urlsafe_encode64(input, padding: false)
end

def decode_disclosure(input)
  encode_base64url(sha256(input)) + " => " +
  decode_base64url(input)
end

def decode_jwt(input)
  fields = input.split('.')

  prettify_json(decode_base64url(fields[0])) + "\n" +
  prettify_json(decode_base64url(fields[1]))
end

def decode_sd_jwt(input)
  fields = input.split('~')

  fields.each.with_index(1) do |field, index|
    if index == 1
      # Issuer-signed JWT
      puts decode_jwt(field)
    elsif index == fields.length and field.include?('.')
      # Key binding JWT
      puts decode_jwt(field)
    else
      # Disclosure
      puts decode_disclosure(field)
    end
  end
end

decode_sd_jwt(ARGV[0])
