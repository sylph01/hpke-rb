module HPKE::Util
  def i2osp(n, w)
    # check n > 0 and n < 256 ** w
    ret = []
    for i in 0..(w - 1)
      ret[w - (i + 1)] = n % 256
      n = n >> 8
    end
    ret.map(&:chr).join
  end

  def os2ip(x)
    x.bytes.reduce { |a, b| a * 256 + b }
  end

  def xor(a, b)
    if a.bytesize != b.bytesize
      return false
    end
    c = ""
    for i in 0 .. (a.bytesize - 1)
      c += (a.bytes[i] ^ b.bytes[i]).chr
    end
    c
  end
end