#!/usr/bin/env ruby

# Helper Class for finding out the assumed Operating system by a given Handshake Fingerprint
class Fingerprint
  # Fingerprintversion to use.
  # Used for switching to a new fingerprint version which includes different information in the Hash
  VERSION="v2"

  @@fingerprintdb = {}
  @@fingerprintdb_lastupdate = nil

  # Get the current fingerprint Database
  def self.get_fp_db
    @@fingerprintdb
  end

  # Fetch assumed Operating system by given fingerprint
  # @param fp [String] Handshake Fingerprint (SHA2-Hash as downcase hex string)
  # @return [Hash] Assumed Operating System from given Fingerprint, or a Hash with os, os_version and detail set to "Not in FP-DB" if no match is found
  def self.to_h(fp)
    self.check_new_file
    to_ret = @@fingerprintdb[fp]
    to_ret || { os: "Not in FP-DB", os_version: "Not in FP-DB", detail: "Not in FP-DB" }
  end

  # Loads a new fingerprint database if a new file version is available or the database is not yet initialized
  # This allows hotswaping the fingerprint database without the need to restart the capture process
  # @return nil
  def self.check_new_file
    thisupdate = File.mtime(File.join('resources', "./fingerprint.#{VERSION}.txt"))

    if @@fingerprintdb_lastupdate.nil? || thisupdate > @@fingerprintdb_lastupdate
      temp_db = {}
      begin
        File.read(File.join('resources', "./fingerprint.#{VERSION}.txt")).each_line do |l|
          next unless l.match /^[0-9a-f]{64}|[^|]*|[^|]*|[^|]*$/
          d = l.split('|').collect(&:strip)
          next if d[0] == 'Fingerprint'
          temp_db[d[0]] = {os: d[1], os_version: d[2], detail: d[3]}
        end
      rescue => e
        $stderr.puts 'Error reading fingerprintdb'
      end
      @@fingerprintdb = temp_db
      @@fingerprintdb_lastupdate = thisupdate
      nil
    end
  end
end
