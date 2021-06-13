require 'fluent/plugin/filter'
require 'digest'

module Fluent::Plugin
  class TwistlockSyslogFilter < Filter
    # Register this filter as "twistlock-syslog"
    Fluent::Plugin.register_filter('twistlock_syslog', self)
    config_param :key_path, :string, default: '/fluentd/etc/private.pem'
    config_param :key_name, :string, default: 'message'

    def configure(conf)
      super
      unless File.file?(@key_path)
        raise Fluent::ConfigError, "Private key file must be present. #{@key_path} Please check."
      end
    end
    def start
      super
      @private_key = OpenSSL::PKey::RSA.new(File.read(@key_path))
    end
    def filter(tag, time, record)
      message = record[@key_name][0..-2]
      begin
        message.split(/(?<!\\|=)"\s/).each { |in_msg|
          keymap = in_msg.split('="')
          record[keymap[0]] = keymap[1]
        }
        record.delete("ident")
        record.delete("pid")
        record.delete("time")
        if record.key?("host_name")
          record["host"] = record["host_name"]
          record.delete("host_name")
        end
        signature = @private_key.sign(OpenSSL::Digest::SHA256.new, record[@key_name])
        record["signature"] = Base64.encode64(signature)
      rescue Exception => e
        log.warn "Unable to map record with message=#{record[@key_name]}"
        log.warn e.backtrace.inspect
      end
      record
    end
  end
end