begin
  require 'rubygems'
  require 'rake/testtask'

  Rake::TestTask.new do |t|
    t.libs<<'test'
  end

  desc "Run tests"
  task :default => :test

rescue LoadError
  puts "Jeweler not available. Install it with: sudo gem install technicalpickles-jeweler -s http://gems.github.com"
end
