Ruby Pcap
=========

ruby-pcap is a ruby interface for libpcap (Packet Capture library).
This library also includes classes to access packet headers.

##Installation

###Requirements:

  - ruby-1.8.x or ruby-1.9.2 (or greater)
  - libpcap-devel (http://www.tcpdump.org/)

###Compile:

If ruby supports dynamic link of extension module on your OS,
following commands will install ruby-pcap.

```bash
  gem build pcap.gemspec
  sudo gem install pcap*.gem
```  

### Tests:

```bash
  ruby test/test_pcap.rb
```

## Usage

See the documentation under the directory 'doc'.
Directory 'examples' contains some simple scripts.

### Author

* Masaki Fukushima <fukusima@goto.info.waseda.ac.jp>

* Modifications by Andrew Hobson <ahobson@gmail.com>

* OS X and Ruby 1.9.2 support by Tim Jarratt <tjarratt@gmail.com>

* Performance Improvements and other great contributes by Ilya Maykov

* IPv6 Support by Matthew Wise <matthew.rs.wise@gmail.com>

ruby-pcap is copyrighted free software by Masaki Fukushima.

You can redistribute it and/or modify it under the terms of
the GPL (GNU GENERAL PUBLIC LICENSE).  See COPYING file about GPL.

THIS SOFTWARE IS PROVIDED "AS IS" AND WITHOUT ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.  See the GPL for
more details.
