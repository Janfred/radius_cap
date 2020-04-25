require 'singleton'

# Helper Class for finding out the Vendor
class MacVendor
  include Singleton

  attr_reader :vendorhash

  # Private handler for initializing the OUI Database
  # @private
  def priv_init_data
    @vendorhash = {}
    File.open("./oui.txt") do |f|
      f.each do |line|
        match = line.match /^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2}) {3}\(hex\)\t\t(.*)\r$/
        next unless match
        key = match[1].downcase + ":" + match[2].downcase + ":" + match[3].downcase
        @vendorhash[key] = match[4]
      end
    end
  end

  # Initializes the OUI Database.
  # Reads the oui.txt File
  def self.init_data
    instance.priv_init_data
  end

  # Find out the Vendor by the OID
  # @param oid [String] OID in Format "xx:xx:xx"
  # @return [String] Vendor registered with the given OID
  def self.by_oid(oid)
    self.instance.vendorhash[oid] || "UNKNOWN"
  end
end
