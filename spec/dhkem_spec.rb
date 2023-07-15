# frozen_string_literal: true

require 'securerandom'

RSpec.describe HPKE::DHKEM do
  context "derive_key_pair" do
    context "for P-256/SHA256" do
      it "derives correct key pair" do
        # RFC 9180 A.3.1
        ikme = ['4270e54ffd08d79d5928020af4686d8f6b7d35dbe470265f1f5aa22816ce860e'].pack('H*')
        pkem = '04a92719c6195d5085104f469a8b9814d5838ff72b60501e2c4466e5e67b325ac98536d7b61a1af4b78e5b7f951c0900be863c403ce65c9bfcb9382657222d18c4'

        dhkem = HPKE::DHKEM::EC::P_256.new(:sha256)
        pkey = dhkem.derive_key_pair(ikme)
        expect(dhkem.serialize_public_key(pkey).unpack1('H*')).to eq(pkem)
      end
    end

    context "for P-521/SHA512" do
      it "derives correct key pair" do
        # RFC 9180 A.3.1
        ikme = ['7f06ab8215105fc46aceeb2e3dc5028b44364f960426eb0d8e4026c2f8b5d7e7a986688f1591abf5ab753c357a5d6f0440414b4ed4ede71317772ac98d9239f70904'].pack('H*')
        pkem = '040138b385ca16bb0d5fa0c0665fbbd7e69e3ee29f63991d3e9b5fa740aab8900aaeed46ed73a49055758425a0ce36507c54b29cc5b85a5cee6bae0cf1c21f2731ece2013dc3fb7c8d21654bb161b463962ca19e8c654ff24c94dd2898de12051f1ed0692237fb02b2f8d1dc1c73e9b366b529eb436e98a996ee522aef863dd5739d2f29b0'

        dhkem = HPKE::DHKEM::EC::P_521.new(:sha512)
        pkey = dhkem.derive_key_pair(ikme)
        expect(dhkem.serialize_public_key(pkey).unpack1('H*')).to eq(pkem)
      end
    end
    
    context "for X25519/SHA256" do
      it "derives correct key pair" do
        # RFC 9180 A.1.1
        ikme = ['7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234'].pack('H*')
        pkem = '37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431'

        dhkem = HPKE::DHKEM::X25519.new(:sha256)
        pkey = dhkem.derive_key_pair(ikme)
        expect(dhkem.serialize_public_key(pkey).unpack1('H*')).to eq(pkem)
      end
    end
  end

  context "create_key_pair_from_secret" do
    context "for X25519" do
      it "creates OpenSSL::PKey::PKey instance" do
        dhkem = HPKE::DHKEM::X25519.new(:sha256)

        pkey = dhkem.create_key_pair_from_secret(SecureRandom.random_bytes(32))
        expect(pkey).to be_an_instance_of(OpenSSL::PKey::PKey)
      end
    end

    context "for X448" do
      it "creates OpenSSL::PKey::PKey instance" do
        dhkem = HPKE::DHKEM::X448.new(:sha512)

        pkey = dhkem.create_key_pair_from_secret(SecureRandom.random_bytes(56))
        expect(pkey).to be_an_instance_of(OpenSSL::PKey::PKey)
      end
    end
  end
end
