#!/usr/bin/env ruby

class Fingerprint
  VERSION="v2"
  @@fingerprintdb = {}
  @@fingerprintdb_lastupdate = nil

  def self.to_h(fb)
    self.check_new_file
    to_ret = @@fingerprintdb[fb]
    to_ret ||= { os: "Not in FP-DB", os_version: "Not in FP-DB", detail: "Not in FP-DB" }
  end

  def self.check_new_file
    thisupdate = File.mtime("./fingerprint.#{VERSION}.txt")

    if @@fingerprintdb_lastupdate.nil? || thisupdate > @@fingerprintdb_lastupdate then
      temp_db = {}
      begin
        File.read("./fingerprint.#{VERSION}.txt").each_line do |l|
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
    end
  end
end
