# -*- encoding: utf-8 -*-

Gem::Specification.new do |s|
  s.name = %q{pcap}
  s.version = "0.7.13"

  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=
  s.authors = [%q{Masaki Fukushima}, %q{Andrew Hobson}, %q{Matthew Wise}]
  s.date = %q{2014-08-10}
  s.description = %q{Ruby interface to LBL Packet Capture library. This library also includes classes to access packet header fields.}
  s.email = %q{fukusima@goto.info.waseda.ac.jp}
  s.extensions = [%q{ext/extconf.rb}]
  s.extra_rdoc_files = [
    "ChangeLog",
     "README"
  ]
  s.files = `git ls-files`.split($/)
  s.homepage = %q{http://www.github.com/mawise/ruby-pcap}
  s.rdoc_options = [%q{--charset=UTF-8}]
  s.require_paths = [%q{lib}]
  s.rubygems_version = %q{1.8.4}
  s.summary = %q{Interface to LBL Packet Capture library (libpcap)}

end
