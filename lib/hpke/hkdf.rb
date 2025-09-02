require 'openssl'
require_relative 'util'

class HPKE::HKDF
  include HPKE::Util

  attr_reader :kdf_id

  def n_h
    @digest.digest_length
  end

  def initialize(kdf_id)
    case kdf_id
    when HPKE::HKDF_SHA256
      @digest = OpenSSL::Digest.new('SHA256')
    when HPKE::HKDF_SHA384
      @digest = OpenSSL::Digest.new('SHA384')
    when HPKE::HKDF_SHA512
      @digest = OpenSSL::Digest.new('SHA512')
    else
      raise Exception.new('Unknown hash algorithm')
    end
    @kdf_id = kdf_id
  end

  def hmac(key, data)
    OpenSSL::HMAC.digest(@digest, key, data)
  end

  def extract(salt, ikm)
    hmac(salt, ikm)
  end

  def expand(prk, info, len)
    n = (len.to_f / @digest.digest_length).ceil
    t = ['']
    for i in 0..n do
      t << hmac(prk, t[i] + info + (i + 1).chr)
    end
    t_concat = t.join
    t_concat[0..(len - 1)]
  end

  def labeled_extract(salt, label, ikm, suite_id)
    labeled_ikm = 'HPKE-v1' + suite_id + label + ikm
    extract(salt, labeled_ikm)
  end

  def labeled_expand(prk, label, info, l, suite_id)
    labeled_info = i2osp(l, 2) + 'HPKE-v1' + suite_id + label + info
    expand(prk, labeled_info, l)
  end
end
