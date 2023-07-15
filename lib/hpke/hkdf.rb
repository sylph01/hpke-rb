require 'openssl'
require_relative 'util'

class HPKE::HKDF
  include HPKE::Util

  attr_reader :kdf_id

  ALGORITHMS = {
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

  def n_h
    @digest.digest_length
  end

  def initialize(alg_name)
    if algorithm = ALGORITHMS[alg_name]
      @digest = OpenSSL::Digest.new(algorithm[:name])
      @kdf_id = algorithm[:kdf_id]
    else
      raise Exception.new('Unknown hash algorithm')
    end
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

class HPKE::HKDF::HMAC_SHA256 < HPKE::HKDF
  private

  def digest_algorithm
    'SHA256'
  end

  def kdf_id
    1
  end
end

class HPKE::HKDF::HMAC_SHA384 < HPKE::HKDF
  private

  def digest_algorithm
    'SHA384'
  end

  def kdf_id
    2
  end
end

class HPKE::HKDF::HMAC_SHA512 < HPKE::HKDF
  private
  
  def digest_algorithm
    'SHA512'
  end

  def kdf_id
    3
  end
end