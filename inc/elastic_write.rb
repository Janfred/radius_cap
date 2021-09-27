# frozen_string_literal: true

ElasticHelper.initialize_elasticdata @config[:debug]

Thread.start do
  Thread.current.name = 'Elastic Writer'
  loop do
    toins = nil
    thres_ok = false
    ElasticHelper.elasticdata.synchronize do
      ElasticHelper.waitcond.wait_while { ElasticHelper.elasticdata.empty? }
      toins = ElasticHelper.elasticdata.shift
      thres_ok = ElasticHelper.elasticdata.length < 1000
    end

    next if toins.nil?

    BlackBoard.logger.trace "To insert: #{toins}"

    username = nil
    mac = nil
    if toins[:radsec] && toins[:radsec][:attributes] && toins[:radsec][:attributes][:username]
      username = toins[:radsec][:attributes][:username]
      BlackBoard.logger.trace "Username from RADSEC #{username}"
    end
    if toins[:radsec] && toins[:radsec][:attributes] && toins[:radsec][:attributes][:mac]
      mac = toins[:radsec][:attributes][:mac]
      BlackBoard.logger.trace "MAC from RADSEC #{mac}"
    end
    if toins[:radius] && toins[:radius][:attributes] && toins[:radius][:attributes][:username]
      username = toins[:radius][:attributes][:username]
      BlackBoard.logger.trace "Username from RADIUS #{username}"
    end
    if toins[:radius] && toins[:radius][:attributes] && toins[:radius][:attributes][:mac]
      mac = toins[:radius][:attributes][:mac]
      BlackBoard.logger.trace "MAC from RADIUS #{mac}"
    end

    filters = @config[:elastic_filter].select do |x|
      (x[:username].nil? || username.nil? || x[:username] == username) &&
        (x[:mac].nil? || mac.nil? || x[:mac] == mac)
    end

    roundtrips = 0
    if toins[:radsec] && toins[:radsec][:information] && toins[:radsec][:information][:roundtrips]
      roundtrips = toins[:radsec][:information][:roundtrips]
    end
    if toins[:radius] && toins[:radius][:information] && toins[:radius][:information][:roundtrips]
      roundtrips = toins[:radius][:information][:roundtrips]
    end
    if filters.empty?
      StatHandler.increase(:elastic_writes)
      StatHandler.increase(:packet_elastic_written, roundtrips)
      ElasticHelper.insert_into_elastic(toins, @config[:debug], @config[:noelastic], @config[:filewrite], thres_ok)
    else
      BlackBoard.logger.debug 'Filtered out Elasticdata'
      StatHandler.increase(:elastic_filters)
      StatHandler.increase(:packet_elastic_filtered, roundtrips)
    end

  rescue StandardError => e
    BlackBoard.logger.error('Error in Elastic Write', exception: e)
  end
end
