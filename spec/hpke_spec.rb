# frozen_string_literal: true

require 'json'

RSpec.describe HPKE do
  test_vectors = JSON.parse(File.read('spec/fixtures/test-vectors.json'))
  KEMS = {
      0x0010 => [:p_256, :sha256],
      0x0011 => [:p_384, :sha384],
      0x0012 => [:p_521, :sha512],
      0x0020 => [:x25519, :sha256],
      0x0021 => [:x448, :sha512]
    }

  KDFS = {
      0x0001 => :sha256,
      0x0002 => :sha384,
      0x0003 => :sha512
    }

  AEAD_CIPHERS = {
      0x0001 => :aes_128_gcm,
      0x0002 => :aes_256_gcm,
      0x0003 => :chacha20_poly1305,
      0xffff => :export_only
    }

  test_vectors.each do |vec|
    context "mode #{vec['mode']}, DHKEM(#{KEMS[vec['kem_id']][0]}, #{KEMS[vec['kem_id']][1]}), HKDF(#{KDFS[vec['kdf_id']]}), #{AEAD_CIPHERS[vec['aead_id']]}" do
      it "instantiates a HPKE instance" do
        hpke = HPKE.new(KEMS[vec['kem_id']][0], KEMS[vec['kem_id']][1], KDFS[vec['kdf_id']], AEAD_CIPHERS[vec['aead_id']])
        expect(hpke).to be_an_instance_of(HPKE)
      end

      context "DHKEM(#{KEMS[vec['kem_id']][0]}, #{KEMS[vec['kem_id']][1]})" do
        it "derives key pair as expected" do
          ikme = [vec['ikmE']].pack('H*')
          ikmr = [vec['ikmR']].pack('H*')
          hpke = HPKE.new(KEMS[vec['kem_id']][0], KEMS[vec['kem_id']][1], KDFS[vec['kdf_id']], AEAD_CIPHERS[vec['aead_id']])
          pkey_r = hpke.kem.derive_key_pair(ikmr)
          expect(hpke.kem.serialize_public_key(pkey_r).unpack1('H*')).to eq(vec['pkRm'])
        end
      end

      context "HPKE suite" do
        it "encapsulates as expected" do
          info = [vec['info']].pack('H*')
          ikme = [vec['ikmE']].pack('H*')
          ikmr = [vec['ikmR']].pack('H*')
          hpke = HPKE.new(KEMS[vec['kem_id']][0], KEMS[vec['kem_id']][1], KDFS[vec['kdf_id']], AEAD_CIPHERS[vec['aead_id']])
          pkey_r = hpke.kem.derive_key_pair(ikmr)
          encap_result = case vec['mode']
          when 0
            hpke.setup_base_s_fixed(pkey_r, info, ikme)
          when 1
            psk = [vec['psk']].pack('H*')
            psk_id = [vec['psk_id']].pack('H*')
            hpke.setup_psk_s_fixed(pkey_r, info, psk, psk_id, ikme)
          when 2
            ikms = [vec['ikmS']].pack('H*')
            pkey_s = hpke.kem.derive_key_pair(ikms)
            hpke.setup_auth_s_fixed(pkey_r, info, pkey_s, ikme)
          when 3
            psk = [vec['psk']].pack('H*')
            psk_id = [vec['psk_id']].pack('H*')
            ikms = [vec['ikmS']].pack('H*')
            pkey_s = hpke.kem.derive_key_pair(ikms)
            hpke.setup_auth_psk_s_fixed(pkey_r, info, psk, psk_id, pkey_s, ikme)
          end
          expect(encap_result[:enc].unpack1('H*')).to eq(vec['enc'])

          context_s = encap_result[:context_s]

          unless vec['aead_id'] == 0xffff
            expect(context_s.key.unpack1('H*')).to eq(vec['key'])
            expect(context_s.base_nonce.unpack1('H*')).to eq(vec['base_nonce'])
          end
          expect(context_s.exporter_secret.unpack1('H*')).to eq(vec['exporter_secret'])
        end

        it "decapsulates as expected" do
          info = [vec['info']].pack('H*')
          ikmr = [vec['ikmR']].pack('H*')
          hpke = HPKE.new(KEMS[vec['kem_id']][0], KEMS[vec['kem_id']][1], KDFS[vec['kdf_id']], AEAD_CIPHERS[vec['aead_id']])
          pkey_r = hpke.kem.derive_key_pair(ikmr)
          enc = [vec['enc']].pack('H*') 
          
          context_r = case vec['mode']
          when 0
            hpke.setup_base_r(enc, pkey_r, info)
          when 1
            psk = [vec['psk']].pack('H*')
            psk_id = [vec['psk_id']].pack('H*')
            hpke.setup_psk_r(enc, pkey_r, info, psk, psk_id)
          when 2
            pkey_s = hpke.kem.create_key_pair_from_secret([vec['skSm']].pack('H*'))
            hpke.setup_auth_r(enc, pkey_r, info, pkey_s)
          when 3
            psk = [vec['psk']].pack('H*')
            psk_id = [vec['psk_id']].pack('H*')
            pkey_s = hpke.kem.create_key_pair_from_secret([vec['skSm']].pack('H*'))
            hpke.setup_auth_psk_r(enc, pkey_r, info, psk, psk_id, pkey_s)
          end

          unless vec['aead_id'] == 0xffff
            expect(context_r.key.unpack1('H*')).to eq(vec['key'])
            expect(context_r.base_nonce.unpack1('H*')).to eq(vec['base_nonce'])
          end
          expect(context_r.exporter_secret.unpack1('H*')).to eq(vec['exporter_secret'])
        end

        it "encrypts as expected" do
          hpke = HPKE.new(KEMS[vec['kem_id']][0], KEMS[vec['kem_id']][1], KDFS[vec['kdf_id']], AEAD_CIPHERS[vec['aead_id']])

          info = [vec['info']].pack('H*')
          ikme = [vec['ikmE']].pack('H*')
          ikmr = [vec['ikmR']].pack('H*')

          pkey_r = hpke.kem.derive_key_pair(ikmr)
          encap_result = case vec['mode']
          when 0
            hpke.setup_base_s_fixed(pkey_r, info, ikme)
          when 1
            psk = [vec['psk']].pack('H*')
            psk_id = [vec['psk_id']].pack('H*')
            hpke.setup_psk_s_fixed(pkey_r, info, psk, psk_id, ikme)
          when 2
            ikms = [vec['ikmS']].pack('H*')
            pkey_s = hpke.kem.derive_key_pair(ikms)
            hpke.setup_auth_s_fixed(pkey_r, info, pkey_s, ikme)
          when 3
            psk = [vec['psk']].pack('H*')
            psk_id = [vec['psk_id']].pack('H*')
            ikms = [vec['ikmS']].pack('H*')
            pkey_s = hpke.kem.derive_key_pair(ikms)
            hpke.setup_auth_psk_s_fixed(pkey_r, info, psk, psk_id, pkey_s, ikme)
          end
          context_s = encap_result[:context_s]

          enc = [vec['enc']].pack('H*') 
          context_r = case vec['mode']
          when 0
            hpke.setup_base_r(enc, pkey_r, info)
          when 1
            psk = [vec['psk']].pack('H*')
            psk_id = [vec['psk_id']].pack('H*')
            hpke.setup_psk_r(enc, pkey_r, info, psk, psk_id)
          when 2
            pkey_s = hpke.kem.create_key_pair_from_secret([vec['skSm']].pack('H*'))
            hpke.setup_auth_r(enc, pkey_r, info, pkey_s)
          when 3
            psk = [vec['psk']].pack('H*')
            psk_id = [vec['psk_id']].pack('H*')
            pkey_s = hpke.kem.create_key_pair_from_secret([vec['skSm']].pack('H*'))
            hpke.setup_auth_psk_r(enc, pkey_r, info, psk, psk_id, pkey_s)
          end

          unless vec['aead_id'] == 0xffff
            vec['encryptions'].each do |encryption|
              aad = [encryption['aad']].pack('H*')
              ct = [encryption['ct']].pack('H*')
              pt = [encryption['pt']].pack('H*')
            
              sealed_pt = context_s.seal(aad, pt)
              expect(sealed_pt).to eq(ct)
              opened_ct = context_r.open(aad, ct)
              expect(opened_ct).to eq(pt)
            end
          end
        end
      end
    end
  end
end
