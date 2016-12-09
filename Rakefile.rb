require 'rake'
require 'erb'
require 'rake/clean'
require 'albacore'
require 'open-uri'
require 'fileutils'
require 'os'
require 'nokogiri'
require 'openssl'
import 'nuget.rake'

CLEAN.include(['src/**/obj', 'src/**/bin', 'tool', 'packages/**','src/**/*.nuspec', 'src/**/*.nupkg', 'tools', 'packages', '*.nupkg'])
Configuration = ENV['CONFIGURATION'] || 'Release'
PACKAGES = File.expand_path("packages")
TOOLS = File.expand_path("tools")
NUGET = File.expand_path("#{TOOLS}/nuget")
NUGET_EXE = File.expand_path("#{TOOLS}/nuget/nuget.exe")
@version = "2.12.0"
PROJECTS = Dir.glob('src/*').select{|dir| File.directory? dir }

desc 'Retrieve things'
task :retrieve => ["nuget:fetch"]

desc 'Does the build'
task :build => [:retrieve, :compile]

desc 'clean, retrieve, build, generate nuspecs'
task :preflight => [:clean, :build, :nuspec_gen]


desc 'publish'
task :publish => [:preflight,:nuspec_gen, :nuspec_pack,  :nuspec_publish]

build :compile do |t|
  t.prop 'Configuration', Configuration
  t.sln = 'OwinOAuthProviders.sln'
end


desc "Generate nuspec files"
task :nuspec_gen do
  template = ERB.new(File.read('nuspectemplate.nuspec.erb'))

  @nugets = []
  PROJECTS.each{|directory|
    @id = File.basename(directory)
    @nugets.push(@id)
    output = template.result()
    File.write(File.join(directory, "#{@id}.nuspec"), output)
  }
  File.write('Owin.Security.Providers.nuspec', ERB.new(File.read('global.nuspec.erb')).result())
end

desc 'pack nuspec files'
task :nuspec_pack do
  PROJECTS.each{|dir|
    Dir.chdir(dir) do
      sh "#{NUGET_EXE} pack #{FileList["*.csproj"].first} -Prop Configuration=#{Configuration}"
    end
  }
  sh "#{NUGET_EXE} pack Owin.Security.Providers.nuspec -Exclude \"**\""
end

desc 'publish nugets'
task :nuspec_publish do
  PROJECTS.each{|dir|
    Dir.chdir(dir) do
      sh "#{NUGET_EXE} push #{FileList["*.nupkg"].first}"
    end
  }
  sh "#{NUGET_EXE} push #{FileList["*.nupkg"].first}"
end
