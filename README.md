# hpke-rb

Hybrid Public Key Encryption (HPKE; [RFC 9180](https://datatracker.ietf.org/doc/html/rfc9180)) in Ruby

## Note

This is still in very early development, so:

- APIs are subject to change
    - Especially the instantation interface of KEM and HPKE suite
- This is tested against test vectors supplied by the authors of the RFC, but is not formally audited for security. Please be aware of this when using in production.

## Supported Features

Supports all modes, KEMs, AEAD functions in RFC 9180.

- HPKE Modes
    - Base
    - PSK
    - Auth
    - AuthPSK
- Key Encapsulation Mechanisms (KEMs)
    - DHKEM(P-256, HKDF-SHA256)
    - DHKEM(P-384, HKDF-SHA384)
    - DHKEM(P-521, HKDF-SHA512)
    - DHKEM(X25519, HKDF-SHA256)
    - DHKEM(X448, HKDF-SHA512)
- Key Derivation Functions (KDFs)
    - HKDF-SHA256
    - HKDF-SHA384
    - HKDF-SHA512
- AEAD Functions
    - AES-128-GCM
    - AES-256-GCM
    - ChaCha20-Poly1305
    - Export Only

## Supported Environments

- OpenSSL 3.0 or higher
    - This is due to the changes in instantiation of public/private key pairs from OpenSSL 1.1 series to OpenSSL 3.0 series
- Ruby 3.1 or higher
    - Ruby 3.1 comes with OpenSSL 3.0 support

## Installation

Install the gem and add to the application's Gemfile by executing:

    $ bundle add hpke

If bundler is not being used to manage dependencies, install the gem by executing:

    $ gem install hpke

## Usage

(example shows Base mode)

```ruby
# instantiate HPKE suite
# first 2 parameters specify the curve and hash to be used in the KEM,
# third parameter specifies the hash to be used in the KDF (of HPKE suite),
# fourth parameter specifies the AEAD function

# we will generate a different instance just for demonstration to show that nothing secret is stored in the HPKE suite instance
hpke_s = HPKE.new(:x25519, :sha256, :sha256, :aes_128_gcm)
hpke_r = HPKE.new(:x25519, :sha256, :sha256, :aes_128_gcm)

# get a OpenSSL::PKey::PKey instance by either generating a key or loading a key from a PEM
# see https://ruby-doc.org/3.2.2/exts/openssl/OpenSSL/PKey/PKey.html
# on the sender's end
sender_key_pair = OpenSSL::PKey.generate_key('X25519')
receiver_key_pair = OpenSSL::PKey.generate_key('X25519')

# Sender setup
# Sender knows the receiver's public key (in PEM format, in most cases), so load that into a PKey
receiver_public_key = OpenSSL::PKey.read(receiver_key_pair.public_to_pem)
encap_result = hpke_s.setup_base_s(receiver_public_key, 'info')
# This returns a hash where :enc key contains the key encapsulation,
# and :context_s contains a HPKE::ContextS instance, which is used for encryption later on.
context_s = encap_result[:context_s]
# Note that :enc contains raw bytes, so when passing to the receiver, it is advised to pass the encapsulation using Base64-encoded values
enc_base64 = Base64.encode64(encap_result[:enc])

# Then on the receiver's end
# decode the encapsulated value
enc = Base64.decode64(enc_base64)
# then use that value to generate a HPKE::ContextR instance to use for decryption
context_r = hpke_r.setup_base_r(enc, receiver_key_pair, 'info')

# sender encrypts a message
# note that the "sequence number" is incremented each time `seal` and `open` is used
ciphertext = context_s.seal('authentication_associated_data', 'plaintext')
# this is also in raw bytes, so when sending, encoding with Base64 is advised

# then receiver decrypts the ciphertext
context_r.open('authentication_associated_data', ciphertext)
```

- Curve names (parameter 1)
    - `:p_256`, `:p_384`, `:p_521`, `:x25519`, `:x448`
        - Note: `:p_256` corresponds to `prime256v1`, `:p_384` corresponds to `secp384r1`, and `:p_521` corresponds to `secp521r1` in OpenSSL
- Hash names (parameter 2 and 3)
    - `:sha256`, `:sha384`, `:sha512`
- AEAD function names (parameter 4)
    - `:aes_128_gcm`, `:aes_256_gcm`, `:chacha20_poly1305`, `:`

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sylph01/hpke-rb.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
