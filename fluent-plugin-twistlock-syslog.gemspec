# encoding: utf-8
$:.push File.expand_path('../lib', __FILE__)

Gem::Specification.new do |gem|
  gem.name        = "fluent-plugin-twistlock-syslog"
  gem.description = "Filter plugin for Fluent to convert twistlock syslog message to hashmap for better SIEM data"
  gem.homepage    = "https://github.com/nronix/fluentd-filter-twistlock-syslog"
  gem.summary     = gem.description
  gem.version     = "1.0.1"
  gem.authors     = ["nronix"]
  gem.email       = "nikhilrao37@gmail.com"
  gem.license     = 'MIT'
  gem.files       = Dir['Rakefile', '{lib}/**/*', 'README*', 'LICENSE*']
  gem.require_paths = ['lib']

  gem.add_dependency "fluentd", [">= 0.10.58", "< 2"]
  gem.add_development_dependency "rake", ">= 0.9.2"
  gem.add_development_dependency "test-unit", ">= 3.0.8"
end