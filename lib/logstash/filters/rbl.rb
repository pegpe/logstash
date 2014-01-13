# Call this file 'rbl.rb' (in logstash/filters, as above)
require "logstash/filters/base"
require "logstash/namespace"

class LogStash::Filters::Rbl < LogStash::Filters::Base

  # Setting the config_name here is required. This is how you
  # configure this filter from your logstash config.
  #
  # filter {
  #   rbl { ... }
  # }
  config_name "rbl"

  # New plugins should start life at milestone 1.
  milestone 1

  # Default blacklists, append or remove as you like.
  config :blacklists, :validate => :array, :default => [ 'zen.spamhaus.org', 'b.barracudacentral.org', 'spam.dnsbl.sorbs.net']

  # the ipaddress to look up. If this field is an array, only the first value will be used.
  config :source, :validate => :string

  # Use custom nameserver.
  config :nameserver, :validate => :string

  # resolv calls will be wrapped in a timeout instance, currently not working
  config :timeout, :validate => :number, :default => 8

  # The field that eventuelly contains the result
  config :target, :validate => :string, :default => 'blacklist'

  public
  def register
    require "resolv"
    require "timeout"
    if @nameserver.nil?
      @resolv = Resolv.new
    else
      @resolv = Resolv.new(resolvers=[::Resolv::Hosts.new, ::Resolv::DNS.new(:nameserver => [@nameserver], :search => [], :ndots => 1)])
    end
    @ip_validator = Resolv::AddressRegex
  end # def register

  public
  def filter(event)
    @logger.debug("RBL:", :type => @type, :config => @config, :event => @event)
    # return nothing unless there's an actual filter event
    return unless filter?(event)
    if @blacklists
      @logger.debug("RBL:", :type => @type, :config => @config, :event => @event)
      #raise error if @source cannot be converted to a reverse ipv4 address
      begin
        $check = event[@source]
        $check = $check.first if $check.is_a? Array
        $check = $check.split('.').reverse.join('.')
      rescue  Exception => e
        @logger.error("Could not convert address to  reverse ipv4 address", :field => @field, :event => event)
      end  
      blacklists.each do |list|
          $host = $check+'.'+list
          begin
#             begin
#               status = Timeout::timeout(@timeout) { 
                  address = @resolv.getaddress($host)
                  @logger.debug(address)
                  event[@target] = {} if event[@target].nil?
                  event[@target][list] = address
                  @logger.debug("RBL:", :list => list, :address => address) 
#               }
#             rescue Timeout::Error
#               @logger.debug("RBL: resolve action timed out")
          rescue
            @logger.debug("RBL: resolve error")
          end
       end

    end
    # filter_matched should go in the last line of our successful code 
    filter_matched(event)
  end # def filter
end # class LogStash::Filters::Rbl
