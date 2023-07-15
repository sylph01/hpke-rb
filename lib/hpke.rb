# frozen_string_literal: true

require_relative "hpke/version"

require 'openssl'
require_relative './hpke/dhkem'
require_relative './hpke/util'

class HPKE
  include HPKE::Util

  attr_reader :kem, :hkdf, :aead_name, :n_k, :n_n, :n_t

  MODES = {
    base: 0x00,
    psk: 0x01,
    auth: 0x02,
    auth_psk: 0x03
  }
  CIPHERS = {
    aes_128_gcm: {
      name: 'aes-128-gcm',
      aead_id: 0x0001,
      n_k: 16,
      n_n: 12,
      n_t: 16
    },
    aes_256_gcm: {
      name: 'aes-256-gcm',
      aead_id: 0x0002,
      n_k: 32,
      n_n: 12,
      n_t: 16
    },
    chacha20_poly1305: {
      name: 'chacha20-poly1305',
      aead_id: 0x0003,
      n_k: 32,
      n_n: 12,
      n_t: 16
    },
    export_only: {
      aead_id: 0xffff
    }
  }
  HASHES = {
    sha256: {
      name: 'SHA256',
      kdf_id: 1
    },
    sha384: {
      name: 'SHA384',
      kdf_id: 2
    },
    sha512: {
      name: 'SHA512',
      kdf_id: 3
    }
  }
  KEM_CURVES = {
    p_256: DHKEM::EC::P_256,
    p_384: DHKEM::EC::P_384,
    p_521: DHKEM::EC::P_521,
    x25519: DHKEM::X25519,
    x448: DHKEM::X448
  }

  def initialize(kem_curve_name, kem_hash, kdf_hash, aead_cipher)
    raise Exception.new('Unsupported KEM curve name') if KEM_CURVES[kem_curve_name].nil?
    raise Exception.new('Unsupported AEAD cipher name') if CIPHERS[aead_cipher].nil?

    @kem = KEM_CURVES[kem_curve_name].new(kem_hash)
    @hkdf = HKDF.new(kdf_hash)
    @aead_name = CIPHERS[aead_cipher][:name]
    @aead_id = CIPHERS[aead_cipher][:aead_id]
    @n_k = CIPHERS[aead_cipher][:n_k]
    @n_n = CIPHERS[aead_cipher][:n_n]
    @n_t = CIPHERS[aead_cipher][:n_t]
  end

  # public facing APIs
  def setup_base_s(pk_r, info)
    encap_result = @kem.encap(pk_r)
    {
      enc: encap_result[:enc],
      context_s: key_schedule_s(MODES[:base], encap_result[:shared_secret], info, DEFAULT_PSK, DEFAULT_PSK_ID)
    }
  end

  def setup_base_r(enc, sk_r, info)
    shared_secret = @kem.decap(enc, sk_r)
    key_schedule_r(MODES[:base], shared_secret, info, DEFAULT_PSK, DEFAULT_PSK_ID)
  end

  def setup_psk_s(pk_r, info, psk, psk_id)
    encap_result = @kem.encap(pk_r)
    {
      enc: encap_result[:enc],
      context_s: key_schedule_s(MODES[:psk], encap_result[:shared_secret], info, psk, psk_id)
    }
  end

  def setup_psk_r(enc, sk_r, info, psk, psk_id)
    shared_secret = @kem.decap(enc, sk_r)
    key_schedule_r(MODES[:psk], shared_secret, info, psk, psk_id)
  end

  def setup_auth_s(pk_r, info, sk_s)
    encap_result = @kem.auth_encap(pk_r, sk_s)
    {
      enc: encap_result[:enc],
      context_s: key_schedule_s(MODES[:auth], encap_result[:shared_secret], info, DEFAULT_PSK, DEFAULT_PSK_ID)
    }
  end

  def setup_auth_r(enc, sk_r, info, pk_s)
    shared_secret = @kem.auth_decap(enc, sk_r, pk_s)
    key_schedule_r(MODES[:auth], shared_secret, info, DEFAULT_PSK, DEFAULT_PSK_ID)
  end

  def setup_auth_psk_s(pk_r, info, psk, psk_id, sk_s)
    encap_result = @kem.auth_encap(pk_r, sk_s)
    {
      enc: encap_result[:enc],
      context_s: key_schedule_s(MODES[:auth_psk], encap_result[:shared_secret], info, psk, psk_id)
    }
  end

  def setup_auth_psk_r(enc, sk_r, info, psk, psk_id, pk_s)
    shared_secret = @kem.auth_decap(enc, sk_r, pk_s)
    key_schedule_r(MODES[:auth_psk], shared_secret, info, psk, psk_id)
  end

  # for testing purposes
  def setup_base_s_fixed(pk_r, info, ikm_e)
    encap_result = @kem.encap_fixed(pk_r, ikm_e)
    {
      enc: encap_result[:enc],
      context_s: key_schedule_s(MODES[:base], encap_result[:shared_secret], info, DEFAULT_PSK, DEFAULT_PSK_ID)
    }
  end

  def setup_psk_s_fixed(pk_r, info, psk, psk_id, ikm_e)
    encap_result = @kem.encap_fixed(pk_r, ikm_e)
    {
      enc: encap_result[:enc],
      context_s: key_schedule_s(MODES[:psk], encap_result[:shared_secret], info, psk, psk_id)
    }
  end

  def setup_auth_s_fixed(pk_r, info, sk_s, ikm_e)
    encap_result = @kem.auth_encap_fixed(pk_r, sk_s, ikm_e)
    {
      enc: encap_result[:enc],
      context_s: key_schedule_s(MODES[:auth], encap_result[:shared_secret], info, DEFAULT_PSK, DEFAULT_PSK_ID)
    }
  end

  def setup_auth_psk_s_fixed(pk_r, info, psk, psk_id, sk_s, ikm_e)
    encap_result = @kem.auth_encap_fixed(pk_r, sk_s, ikm_e)
    {
      enc: encap_result[:enc],
      context_s: key_schedule_s(MODES[:auth_psk], encap_result[:shared_secret], info, psk, psk_id)
    }
  end

  def export(exporter_secret, exporter_context, len)
    @hkdf.labeled_expand(exporter_secret, 'sec', exporter_context, len, suite_id)
  end

  private

  def suite_id
    'HPKE' + i2osp(@kem.kem_id, 2) + i2osp(@hkdf.kdf_id, 2) + i2osp(@aead_id, 2)
  end

  DEFAULT_PSK = ''
  DEFAULT_PSK_ID = ''

  def verify_psk_inputs(mode, psk, psk_id)
    got_psk = (psk != DEFAULT_PSK)
    got_psk_id = (psk_id != DEFAULT_PSK_ID)

    raise Exception.new('Inconsistent PSK inputs') if got_psk != got_psk_id
    raise Exception.new('PSK input provided when not needed') if got_psk && [MODES[:base], MODES[:auth]].include?(mode)
    raise Exception.new('Missing required PSK input') if !got_psk && [MODES[:psk], MODES[:auth_psk]].include?(mode)

    true
  end

  def key_schedule(mode, shared_secret, info, psk = '', psk_id = '')
    verify_psk_inputs(mode, psk, psk_id)

    psk_id_hash = @hkdf.labeled_extract('', 'psk_id_hash', psk_id, suite_id)
    info_hash = @hkdf.labeled_extract('', 'info_hash', info, suite_id)
    key_schedule_context = mode.chr + psk_id_hash + info_hash

    secret = @hkdf.labeled_extract(shared_secret, 'secret', psk, suite_id)

    unless @aead_id == CIPHERS[:export_only][:aead_id]
      key = @hkdf.labeled_expand(secret, 'key', key_schedule_context, @n_k, suite_id)
      base_nonce = @hkdf.labeled_expand(secret, 'base_nonce', key_schedule_context, @n_n, suite_id)
    end
    exporter_secret = @hkdf.labeled_expand(secret, 'exp', key_schedule_context, @hkdf.n_h, suite_id)

    {
      key: key,
      base_nonce: base_nonce,
      sequence_number: 0,
      exporter_secret: exporter_secret
    }
  end

  def key_schedule_s(mode, shared_secret, info, psk = '', psk_id = '')
    ks = key_schedule(mode, shared_secret, info, psk, psk_id)
    HPKE::ContextS.new(ks, self)
  end

  def key_schedule_r(mode, shared_secret, info, psk = '', psk_id = '')
    ks = key_schedule(mode, shared_secret, info, psk, psk_id)
    HPKE::ContextR.new(ks, self)
  end
end

class HPKE::Context
  include HPKE::Util
  attr_reader :key, :base_nonce, :sequence_number, :exporter_secret

  def initialize(initializer_hash, hpke)
    @hpke = hpke
    @key = initializer_hash[:key]
    @base_nonce = initializer_hash[:base_nonce]
    @sequence_number = initializer_hash[:sequence_number]
    @exporter_secret = initializer_hash[:exporter_secret]
  end

  def compute_nonce(seq)
    seq_bytes = i2osp(seq, @hpke.n_n)
    xor(@base_nonce, seq_bytes)
  end

  def increment_seq
    raise Exception.new('MessageLimitReachedError') if @sequence_number >= (1 << (8 * @hpke.n_n)) - 1

    @sequence_number += 1
  end

  def export(exporter_context, len)
    @hpke.export(@exporter_secret, exporter_context, len)
  end
end

class HPKE::ContextS < HPKE::Context
  def seal(aad, pt)
    raise Exception.new('AEAD is export only') if @hpke.aead_name == :export_only

    ct = cipher_seal(@key, compute_nonce(@sequence_number), aad, pt)
    increment_seq
    ct
  end

  private

  def cipher_seal(key, nonce, aad, pt)
    cipher = OpenSSL::Cipher.new(@hpke.aead_name)
    cipher.encrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_data = aad
    cipher.padding = 0
    s = cipher.update(pt) << cipher.final
    s + cipher.auth_tag
  end
end

class HPKE::ContextR < HPKE::Context
  def open(aad, ct)
    raise Exception.new('AEAD is export only') if @hpke.aead_name == :export_only

    pt = cipher_open(@key, compute_nonce(@sequence_number), aad, ct)
    # TODO: catch openerror then send out own openerror
    increment_seq
    pt
  end

  private

  def cipher_open(key, nonce, aad, ct)
    ct_body = ct[0, ct.length - @hpke.n_t]
    tag = ct[-@hpke.n_t, @hpke.n_t]
    cipher = OpenSSL::Cipher.new(@hpke.aead_name)
    cipher.decrypt
    cipher.key = key
    cipher.iv = nonce
    cipher.auth_tag = tag
    cipher.auth_data = aad
    cipher.padding = 0
    cipher.update(ct_body) << cipher.final
  end
end