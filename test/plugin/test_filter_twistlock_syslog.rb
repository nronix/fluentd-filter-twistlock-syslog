require 'helper'
require 'fluent/test/driver/filter'
require 'base64'

class TwistlockSyslogFilterTest < Test::Unit::TestCase

  def setup
    Fluent::Test.setup
    rsa_key = OpenSSL::PKey::RSA.new(2048)
    @public_key = rsa_key.public_key.to_pem
    File.write("private.key",rsa_key.to_pem)
    File.write("public.key",@public_key)
  end

  CONFIG = %[
    key_path private.key
  ]

  def create_driver(conf=CONFIG)
    Fluent::Test::Driver::Filter.new(Fluent::Plugin::TwistlockSyslogFilter).configure(conf)
  end

  def test_filter()
    inputs = [
      {'message' => 'time="2021-06-12T18:47:19.93975234Z" type="host_runtime_audit" id="twistlock-dev" host_name="ip-10-2-101-51.us-west-2.compute.internal" app="sshd" effect="alert" msg="High rate of custom rule events, reporting aggregation started; last event: Lateral SSH detected by user root using process /usr/sbin/sshd -D -R" log_type="processes" audit_id="61c501371f8484f006b37123" account_id="123456789012"'},
      {'message' => 'time="2021-06-12T18:47:06.217304072Z" type="file_integrity_event_host" id="twistlock-dev" event_type="write" path="/etc/nginx/test" file_type="2" description="Process vi wrote to path (user: ec2-user)" host="ip-10-2-101-51.us-west-2.compute.internal" process="vi" user="ec2-user" rule="Default - alert on suspicious runtime behavior" account_id="123456789012"'},
      {'message' => 'time="2021-06-12T18:46:01.118660606Z" type="management_audit" id="twistlock-dev" log_type="rule" username="example@example.com" source_ip="10.1.1.1" api="/api/v1/policies/runtime/host" changes=" {   \"_id\": \"hostRuntime\",   \"owner\": \"system\",   \"rules\": [     {        \"antiMalware\": {\"allowedProcesses\":[],\"cryptoMiner\":\"alert\",\"customFeed\":\"alert\",\"deniedProcesses\":{\"effect\":\"alert\",\"paths\":[]},\"encryptedBinaries\": \"****\",\"executionFlowHijack\":\"alert\",\"intelligenceFeed\":\"alert\",\"reverseShell\":\"alert\",\"serviceUnknownOriginBinary\":\"alert\",\"suspiciousELFHeaders\":\"alert\",\"tempFSProc\":\"alert\",\"userUnknownOriginBinary\":\"alert\",\"webShell\":\"alert\",\"wildFireAnalysis\":\"alert\"},       \"collections\": [         {           \"accountIDs\": [\"*\"],           \"appIDs\": [\"*\"],           \"clusters\": [\"*\"],           \"codeRepos\": [\"*\"],           \"color\": \"#3FA2F7\",           \"containers\": [\"*\"],           \"description\": \"System - all resources collection\",           \"functions\": [\"*\"],           \"hosts\": [\"*\"],           \"images\": [\"*\"],           \"labels\": [\"*\"],-          \"modified\": \"2021-06-09T21:56:29.272Z\",+          \"modified\": \"2021-06-09T21:56:29.721Z\",           \"name\": \"All\",           \"namespaces\": [\"*\"],           \"owner\": \"system\",           \"prisma\": false,           \"system\": true         }       ],+      \"customRules\": [{\"_id\":32,\"action\":\"audit\",\"effect\":\"alert\"}],        \"dns\": {\"allow\":[],\"deny\":[],\"denyListEffect\":\"disable\",\"intelligenceFeed\":\"disable\"},       \"fileIntegrityRules\": [+        {\"path\":\"/etc/nginx/\",\"write\":true}       ],        \"forensic\": {\"activitiesDisabled\":false,\"dockerEnabled\":false,\"readonlyDockerEnabled\":false,\"serviceActivitiesEnabled\":false,\"sshdEnabled\":false,\"sudoEnabled\":false},       \"logInspectionRules\": [],-      \"modified\": \"0001-01-01T00:00:00Z\",+      \"modified\": \"2021-06-12T18:46:01.116Z\",       \"name\": \"Default - alert on suspicious runtime behavior\",        \"network\": {\"allowedOutboundIPs\":[],\"customFeed\":\"alert\",\"deniedListeningPorts\":[],\"deniedOutboundIPs\":[],\"deniedOutboundPorts\":[],\"denyListEffect\":\"alert\",\"intelligenceFeed\":\"alert\"},-      \"owner\": \"\",+      \"owner\": \"test@example.com\",       \"previousName\": \"\"     }   ] }"'}

    ]
    d = create_driver(CONFIG)
    d.run(default_tag: 'test.input') do
      inputs.each do |dat|
        d.feed dat
        plain = Base64.decode64(dat["signature"])
        public_key_obj = OpenSSL::PKey::RSA.new(@public_key)
        assert_equal(true, public_key_obj.verify(OpenSSL::Digest::SHA256.new, plain, dat['message']) )
      end
    end
  end

end
