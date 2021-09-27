# frozen_string_literal: true

# Statistic thread
Thread.start do
  Thread.current.name = 'Statistic writer'
  scheduler = Rufus::Scheduler.new
  scheduler.cron '* * * * *' do
    StatHandler.log_stat

    stat = {}
    ElasticHelper.elasticdata.synchronize do
      stat[:elastic_length] = ElasticHelper.elasticdata.length
    end
    BlackBoard.pktbuf.synchronize do
      stat[:pktbuf_length] = BlackBoard.pktbuf.length
    end
    RadsecStreamHelper.instance.known_streams.length

    logmsg = ''
    logmsg += "Elastic queue length #{stat[:elastic_length]}"
    logmsg += " Stream queue length #{StackParser.instance.priv_stack_data.length}"
    logmsg += " Pktbuf queue length #{stat[:pktbuf_length]}"
    logmsg += " Known streams length #{RadsecStreamHelper.instance.known_streams.length}"

    StatHandler.log_additional logmsg
  end
end
