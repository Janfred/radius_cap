ElasticHelper.initialize_elasticdata @config[:debug]

Thread.start do
  Thread.current.name = "Elastic Writer"
  loop do
    begin
      toins = nil
      ElasticHelper.elasticdata.synchronize do
        ElasticHelper.waitcond.wait_while { ElasticHelper.elasticdata.empty? }
        toins = ElasticHelper.elasticdata.shift
      end

      next if toins.nil?

      BlackBoard.logger.trace 'To insert: ' + toins.to_s

      username = nil
      mac = nil
      if toins[:radsec] && toins[:radsec][:attributes] && toins[:radsec][:attributes][:username]
        username = toins[:radsec][:attributes][:username]
        BlackBoard.logger.trace 'Username from RADSEC ' + username
      end
      if toins[:radsec] && toins[:radsec][:attributes] && toins[:radsec][:attributes][:mac]
        mac = toins[:radsec][:attributes][:mac]
        BlackBoard.logger.trace 'MAC from RADSEC ' + mac
      end

      filters = @config[:elastic_filter].select { |x|
        (x[:username].nil? || username.nil? || x[:username] == username) &&
            (x[:mac].nil? || mac.nil? || x[:mac] == mac)
      }

      if filters.length == 0
        StatHandler.increase(:elastic_writes)
        StatHandler.increase(:packet_elastic_written, toins[:radsec][:information][:roundtrips])
        ElasticHelper.insert_into_elastic(toins, @config[:debug], @config[:noelastic], @config[:filewrite])
      else
        logger.debug 'Filtered out Elasticdata'
        StatHandler.increase(:elastic_filters)
        StatHandler.increase(:packet_elastic_filtered, toins[:radsec][:information][:roundtrips])
      end

    rescue => e
      BlackBoard.logger.error("Error in Elastic Write", exception: e)
    end
  end
end
