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

CLEAN.include(['src/**/obj', 'src/**/bin', 'tool', 'packages/**','src/**/*.nuspec', 'src/**/*.nupkg', 'tools', 'packages'])
Configuration = ENV['CONFIGURATION'] || 'Release'
PACKAGES = File.expand_path("packages")
TOOLS = File.expand_path("tools")
NUGET = File.expand_path("#{TOOLS}/nuget")
NUGET_EXE = File.expand_path("#{TOOLS}/nuget/nuget.exe")
@version = "2.0.0-beta1"
PROJECTS = Dir.glob('src/*').select{|dir| File.directory? dir }

desc 'Retrieve things'
task :retrieve => ["nuget:fetch"]

desc 'Does the build'
task :build => [:retrieve, :compile]

desc 'clean, retrieve, build, generate nuspecs'
task :preflight => [:clean, :build, :nuspec_gen]

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
task :nuspec_pack => :nuspec_gen do
  PROJECTS.each{|dir|
    Dir.chdir(dir) do
      sh "#{NUGET_EXE} pack #{FileList["*.csproj"].first} -Prop Configuration=#{Configuration} -IncludeReferencedProjects"
    end
  }
  sh "#{NUGET_EXE} pack Owin.Security.Providers.nuspec -Exclude \"**\""
end

desc 'publish nugets'
task :nuget_
