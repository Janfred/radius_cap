class MacVendor
  def self.init_data
    @@vendorhash = {}
    File.open("./oui.txt") do |f|
      f.each do |line|
        match = line.match /^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})   \(hex\)\t\t(.*)\r$/
        next unless match
        key = match[1].downcase + ":" + match[2].downcase + ":" + match[3].downcase
        @@vendorhash[key] = match[4]
      end
    end
  end
  def self.by_oid(oid)
    @@vendorhash[oid]
  end
end
